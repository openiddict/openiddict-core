/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using OpenIddict.Client.SystemNetHttp;
using static OpenIddict.Client.SystemNetHttp.OpenIddictClientSystemNetHttpHandlerFilters;
using static OpenIddict.Client.SystemNetHttp.OpenIddictClientSystemNetHttpHandlers;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;

namespace OpenIddict.Client.WebIntegration;

public static partial class OpenIddictClientWebIntegrationHandlers
{
    public static class Revocation
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } =
        [
            /*
             * Revocation request preparation:
             */
            MapNonStandardRequestParameters.Descriptor,
            OverrideHttpMethod.Descriptor,
            AttachBearerAccessToken.Descriptor,
            AttachNonStandardRequestPayload.Descriptor,

            /*
             * Revocation response extraction:
             */
            NormalizeContentType.Descriptor
        ];
        
        /// <summary>
        /// Contains the logic responsible for attaching a non-standard payload for the providers that require it.
        /// </summary>
        public sealed class AttachNonStandardRequestPayload : IOpenIddictClientHandler<PrepareRevocationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<PrepareRevocationRequestContext>()
                    .AddFilter<RequireHttpUri>()
                    .UseSingletonHandler<AttachNonStandardRequestPayload>()
                    .SetOrder(AttachHttpParameters<PrepareRevocationRequestContext>.Descriptor.Order + 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(PrepareRevocationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(context.Transaction.Request is not null, SR.GetResourceString(SR.ID4008));

                // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another client stack.
                var request = context.Transaction.GetHttpRequestMessage() ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

                request.Content = context.Registration.ProviderType switch
                {
                    // The token revocation endpoints exposed by these providers
                    // requires sending the request parameters as a JSON payload:
                    ProviderTypes.Miro => JsonContent.Create(
                        context.Transaction.Request,
                        OpenIddictSerializer.Default.Request,
                        new MediaTypeHeaderValue(OpenIddictClientSystemNetHttpConstants.MediaTypes.Json)
                        {
                            CharSet = OpenIddictClientSystemNetHttpConstants.Charsets.Utf8
                        }),

                    _ => request.Content
                };

                return default;
            }
        }


        /// <summary>
        /// Contains the logic responsible for mapping non-standard request parameters
        /// to their standard equivalent for the providers that require it.
        /// </summary>
        public sealed class MapNonStandardRequestParameters : IOpenIddictClientHandler<PrepareRevocationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<PrepareRevocationRequestContext>()
                    .UseSingletonHandler<MapNonStandardRequestParameters>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(PrepareRevocationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // These providers don't support the standard "token" parameter and
                // require using the non-standard "access_token" parameter instead.
                if (context.Registration.ProviderType is
                    ProviderTypes.VkId  or ProviderTypes.Webflow or
                    ProviderTypes.Weibo or ProviderTypes.Yandex)
                {
                    context.Request.AccessToken = context.Token;
                    context.Request.Token = null;
                    context.Request.TokenTypeHint = null;
                }

                // Linear requires only the access_token and no other parameters.
                else if (context.Registration.ProviderType is ProviderTypes.Linear)
                {
                    context.Request.AccessToken = context.Token;
                    context.Request.Token = null;
                    context.Request.TokenTypeHint = null;
                    context.Request.ClientId = null;
                }

                // Miro uses a JSON payload that expects the non-standard
                // "accessToken", "clientId" and "clientSecret" properties.
                else if (context.Registration.ProviderType is ProviderTypes.Miro)
                {
                    context.Request["accessToken"] = context.Token;
                    context.Request["clientId"] = context.Request.ClientId;
                    context.Request["clientSecret"] = context.Request.ClientSecret;
                    context.Request.Token = null;
                    context.Request.TokenTypeHint = null;
                    context.Request.ClientId = null;
                    context.Request.ClientSecret = null;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for overriding the HTTP method for the providers that require it.
        /// </summary>
        public sealed class OverrideHttpMethod : IOpenIddictClientHandler<PrepareRevocationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<PrepareRevocationRequestContext>()
                    .AddFilter<RequireHttpUri>()
                    .UseSingletonHandler<OverrideHttpMethod>()
                    .SetOrder(PreparePostHttpRequest<PrepareRevocationRequestContext>.Descriptor.Order + 250)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(PrepareRevocationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another client stack.
                var request = context.Transaction.GetHttpRequestMessage() ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

                request.Method = context.Registration.ProviderType switch
                {
                    ProviderTypes.Zendesk => HttpMethod.Delete,

                    _ => request.Method
                };

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the token to revoke
        /// to the HTTP Authorization header for the providers that require it.
        /// </summary>
        public sealed class AttachBearerAccessToken : IOpenIddictClientHandler<PrepareRevocationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<PrepareRevocationRequestContext>()
                    .AddFilter<RequireHttpUri>()
                    .UseSingletonHandler<AttachBearerAccessToken>()
                    .SetOrder(AttachHttpParameters<PrepareRevocationRequestContext>.Descriptor.Order - 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(PrepareRevocationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another client stack.
                var request = context.Transaction.GetHttpRequestMessage() ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

                // Zendesk requires using bearer authentication with the token that is going to be revoked.
                if (context.Registration.ProviderType is ProviderTypes.Zendesk)
                {
                    request.Headers.Authorization = new AuthenticationHeaderValue(Schemes.Bearer, context.Token);

                    // Remove the token from the request payload to ensure it's not sent twice.
                    context.Request.Token = null;
                }

                // Miro requires using bearer authentication with the token that is going to be revoked.
                //
                // Note: the token property CANNOT be used here as the token parameter is mapped to "accessToken".
                else if (context.Registration.ProviderType is ProviderTypes.Miro &&
                    (string?) context.Request["accessToken"] is { Length: > 0 } token)
                {
                    request.Headers.Authorization = new AuthenticationHeaderValue(Schemes.Bearer, token);
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for normalizing the returned content
        /// type of revocation responses for the providers that require it.
        /// </summary>
        public sealed class NormalizeContentType : IOpenIddictClientHandler<ExtractRevocationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ExtractRevocationResponseContext>()
                    .AddFilter<RequireHttpUri>()
                    .UseSingletonHandler<NormalizeContentType>()
                    .SetOrder(ExtractJsonHttpResponse<ExtractRevocationResponseContext>.Descriptor.Order - 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ExtractRevocationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to System.Net.Http requests. If the HTTP response cannot be resolved,
                // this may indicate that the request was incorrectly processed by another client stack.
                var response = context.Transaction.GetHttpResponseMessage() ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

                if (response.Content is null)
                {
                    return default;
                }

                // Some providers are known to return invalid or incorrect media types, which prevents
                // OpenIddict from extracting revocation responses. To work around that, the declared
                // content type is replaced by the correct value for the providers that require it.

                response.Content.Headers.ContentType = context.Registration.ProviderType switch
                {
                    // MusicBrainz returns empty revocation responses declared as "text/html" responses.
                    //
                    // Since empty HTML payloads are not valid JSON nodes, the Content-Type is manually set
                    // to null to prevent OpenIddict from trying to extract a JSON payload from such responses.
                    ProviderTypes.MusicBrainz when response.Content.Headers.ContentLength is 0 => null,

                    // Reddit returns empty revocation responses declared as "application/json" responses.
                    //
                    // Since empty JSON payloads are not valid JSON nodes, the Content-Type is manually set
                    // to null to prevent OpenIddict from trying to extract a JSON payload from such responses.
                    ProviderTypes.Reddit when response.Content.Headers.ContentLength is 0 => null,

                    _ => response.Content.Headers.ContentType
                };

                return default;
            }
        }
    }
}
