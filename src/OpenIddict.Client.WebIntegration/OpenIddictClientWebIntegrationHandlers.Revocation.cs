/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using static OpenIddict.Client.SystemNetHttp.OpenIddictClientSystemNetHttpHandlerFilters;
using static OpenIddict.Client.SystemNetHttp.OpenIddictClientSystemNetHttpHandlers;
using static OpenIddict.Client.SystemNetHttp.OpenIddictClientSystemNetHttpHandlers.Exchange;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;

namespace OpenIddict.Client.WebIntegration;

public static partial class OpenIddictClientWebIntegrationHandlers
{
    public static class Revocation
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create([
            /*
             * Revocation request preparation:
             */
            AttachNonStandardBasicAuthenticationCredentials.Descriptor,

            /*
             * Revocation response extraction:
             */
            NormalizeContentType.Descriptor
        ]);

        /// <summary>
        /// Contains the logic responsible for attaching the client credentials to the HTTP Authorization
        /// header using a non-standard construction logic for the providers that require it.
        /// </summary>
        public sealed class AttachNonStandardBasicAuthenticationCredentials : IOpenIddictClientHandler<PrepareRevocationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<PrepareRevocationRequestContext>()
                    .AddFilter<RequireHttpUri>()
                    .UseSingletonHandler<AttachNonStandardBasicAuthenticationCredentials>()
                    .SetOrder(AttachBasicAuthenticationCredentials.Descriptor.Order - 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(PrepareRevocationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Some providers are known to incorrectly implement basic authentication support, either because
                // an incorrect encoding scheme is used (e.g the credentials are not formURL-encoded as required
                // by the OAuth 2.0 specification) or because basic authentication is required even for public
                // clients, even though these clients don't have a secret (which requires using an empty password).

                Debug.Assert(context.Request is not null, SR.GetResourceString(SR.ID4008));

                // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another client stack.
                var request = context.Transaction.GetHttpRequestMessage() ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

                // These providers require using basic authentication to flow the client_id
                // for all types of client applications, even when there's no client_secret.
                if (context.Registration.ProviderType is ProviderTypes.Reddit &&
                    !string.IsNullOrEmpty(context.Request.ClientId))
                {
                    // Important: the credentials MUST be formURL-encoded before being base64-encoded.
                    var credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(new StringBuilder()
                        .Append(EscapeDataString(context.Request.ClientId))
                        .Append(':')
                        .Append(EscapeDataString(context.Request.ClientSecret))
                        .ToString()));

                    // Attach the authorization header containing the client identifier to the HTTP request.
                    request.Headers.Authorization = new AuthenticationHeaderValue(Schemes.Basic, credentials);

                    // Remove the client credentials from the request payload to ensure they are not sent twice.
                    context.Request.ClientId = context.Request.ClientSecret = null;
                }

                return default;

                static string? EscapeDataString(string? value)
                    => value is not null ? Uri.EscapeDataString(value).Replace("%20", "+") : null;
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
                    // Since empty HTML payloads are not valid JSON nodes, the Content-Length is manually set
                    // to 0 to prevent OpenIddict from trying to extract a JSON payload from such responses.
                    ProviderTypes.MusicBrainz when response.Content.Headers.ContentLength is 0 => null,

                    // Reddit returns empty revocation responses declared as "application/json" responses.
                    //
                    // Since empty JSON payloads are not valid JSON nodes, the Content-Length is manually set
                    // to 0 to prevent OpenIddict from trying to extract a JSON payload from such responses.
                    ProviderTypes.Reddit when response.Content.Headers.ContentLength is 0 => null,

                    _ => response.Content.Headers.ContentType
                };

                return default;
            }
        }
    }
}
