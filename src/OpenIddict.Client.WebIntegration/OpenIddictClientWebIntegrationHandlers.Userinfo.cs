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
using static OpenIddict.Client.SystemNetHttp.OpenIddictClientSystemNetHttpConstants;
using static OpenIddict.Client.SystemNetHttp.OpenIddictClientSystemNetHttpHandlerFilters;
using static OpenIddict.Client.SystemNetHttp.OpenIddictClientSystemNetHttpHandlers;
using static OpenIddict.Client.SystemNetHttp.OpenIddictClientSystemNetHttpHandlers.Userinfo;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;

namespace OpenIddict.Client.WebIntegration;

public static partial class OpenIddictClientWebIntegrationHandlers
{
    public static class Userinfo
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Userinfo request preparation:
             */
            OverrideHttpMethod.Descriptor,
            AttachRequestHeaders.Descriptor,
            AttachAccessTokenParameter.Descriptor,
            AttachNonStandardParameters.Descriptor,
            AttachNonStandardRequestPayload.Descriptor,

            /*
             * Userinfo response extraction:
             */
            NormalizeContentType.Descriptor,
            UnwrapUserinfoResponse.Descriptor);

        /// <summary>
        /// Contains the logic responsible for overriding the HTTP method for the providers that require it.
        /// </summary>
        public sealed class OverrideHttpMethod : IOpenIddictClientHandler<PrepareUserinfoRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<PrepareUserinfoRequestContext>()
                    .AddFilter<RequireHttpMetadataUri>()
                    .UseSingletonHandler<OverrideHttpMethod>()
                    .SetOrder(PreparePostHttpRequest<PrepareUserinfoRequestContext>.Descriptor.Order + 250)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(PrepareUserinfoRequestContext context)
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
                    // SubscribeStar's userinfo implementation is based on GraphQL, which requires using POST.
                    ProviderTypes.SubscribeStar => HttpMethod.Post,

                    _ => request.Method
                };

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching additional
        /// headers to the request for the providers that require it.
        /// </summary>
        public sealed class AttachRequestHeaders : IOpenIddictClientHandler<PrepareUserinfoRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<PrepareUserinfoRequestContext>()
                    .AddFilter<RequireHttpMetadataUri>()
                    .UseSingletonHandler<AttachRequestHeaders>()
                    .SetOrder(AttachUserAgentHeader<PrepareUserinfoRequestContext>.Descriptor.Order + 250)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(PrepareUserinfoRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another client stack.
                var request = context.Transaction.GetHttpRequestMessage() ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

                // Notion requires sending an explicit API version (which is statically set
                // to the last version known to be supported by the OpenIddict integration).
                if (context.Registration.ProviderType is ProviderTypes.Notion)
                {
                    request.Headers.Add("Notion-Version", "2022-06-28");
                }

                // Trakt requires sending both an API key (which is always the client identifier) and an API version
                // (which is statically set to the last version known to be supported by the OpenIddict integration).
                else if (context.Registration.ProviderType is ProviderTypes.Trakt)
                {
                    request.Headers.Add("trakt-api-key", context.Registration.ClientId);
                    request.Headers.Add("trakt-api-version", "2");
                }

                // Trovo requires sending the client identifier as a separate, non-standard header.
                else if (context.Registration.ProviderType is ProviderTypes.Trovo)
                {
                    request.Headers.Add("Client-ID", context.Registration.ClientId);
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the access token
        /// parameter to the request for the providers that require it.
        /// </summary>
        public sealed class AttachAccessTokenParameter : IOpenIddictClientHandler<PrepareUserinfoRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<PrepareUserinfoRequestContext>()
                    .AddFilter<RequireHttpMetadataUri>()
                    .UseSingletonHandler<AttachAccessTokenParameter>()
                    .SetOrder(AttachBearerAccessToken.Descriptor.Order + 250)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(PrepareUserinfoRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another client stack.
                var request = context.Transaction.GetHttpRequestMessage() ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

                // By default, OpenIddict sends the access token as part of the Authorization header
                // using the Bearer authentication scheme. Some providers don't support this method
                // and require sending the access token as part of the userinfo request payload
                // or using a non-standard authentication scheme (e.g OAuth instead of Bearer).

                // These providers require sending the access token as part of the request payload.
                if (context.Registration.ProviderType is ProviderTypes.Deezer or ProviderTypes.Mixcloud or ProviderTypes.StackExchange)
                {
                    context.Request.AccessToken = request.Headers.Authorization?.Parameter;

                    // Remove the access token from the request headers to ensure it's not sent twice.
                    request.Headers.Authorization = null;
                }

                // Shopify requires using the non-standard "X-Shopify-Access-Token" header.
                else if (context.Registration.ProviderType is ProviderTypes.Shopify)
                {
                    request.Headers.Add("X-Shopify-Access-Token", request.Headers.Authorization?.Parameter);

                    // Remove the access token from the request headers to ensure it's not sent twice.
                    request.Headers.Authorization = null;
                }

                // Trovo requires using the "OAuth" scheme instead of the standard "Bearer" value.
                else if (context.Registration.ProviderType is ProviderTypes.Trovo)
                {
                    request.Headers.Authorization = new AuthenticationHeaderValue("OAuth",
                        request.Headers.Authorization?.Parameter);
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching non-standard
        /// parameters to the request for the providers that require it.
        /// </summary>
        public sealed class AttachNonStandardParameters : IOpenIddictClientHandler<PrepareUserinfoRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<PrepareUserinfoRequestContext>()
                    .UseSingletonHandler<AttachNonStandardParameters>()
                    .SetOrder(AttachHttpParameters<PrepareUserinfoRequestContext>.Descriptor.Order - 250)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(PrepareUserinfoRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // ArcGIS Online doesn't support header-based content negotiation and requires using
                // the non-standard "f" parameter to get back JSON responses instead of HTML pages.
                if (context.Registration.ProviderType is ProviderTypes.ArcGisOnline)
                {
                    context.Request["f"] = "json";
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching a non-standard payload for the providers that require it.
        /// </summary>
        public sealed class AttachNonStandardRequestPayload : IOpenIddictClientHandler<PrepareUserinfoRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<PrepareUserinfoRequestContext>()
                    .AddFilter<RequireHttpMetadataUri>()
                    .UseSingletonHandler<AttachNonStandardRequestPayload>()
                    .SetOrder(AttachHttpParameters<PrepareUserinfoRequestContext>.Descriptor.Order + 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(PrepareUserinfoRequestContext context)
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
                    // SubscribeStar's userinfo implementation is based on GraphQL,
                    // which requires sending the request parameters as a JSON payload.
                    ProviderTypes.SubscribeStar => JsonContent.Create(context.Transaction.Request,
                        new MediaTypeHeaderValue(MediaTypes.Json)
                        {
                            CharSet = Charsets.Utf8
                        }),

                    _ => request.Content
                };

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for normalizing the returned content
        /// type of userinfo responses for the providers that require it.
        /// </summary>
        public sealed class NormalizeContentType : IOpenIddictClientHandler<ExtractUserinfoResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ExtractUserinfoResponseContext>()
                    .UseSingletonHandler<NormalizeContentType>()
                    .SetOrder(ExtractUserinfoTokenHttpResponse.Descriptor.Order - 250)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ExtractUserinfoResponseContext context)
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
                // OpenIddict from extracting userinfo responses. To work around that, the declared
                // content type is replaced by the correct value for the providers that require it.

                response.Content.Headers.ContentType = context.Registration.ProviderType switch
                {
                    // Mixcloud returns JSON-formatted contents declared as "text/javascript".
                    ProviderTypes.Mixcloud => new MediaTypeHeaderValue(MediaTypes.Json)
                    {
                        CharSet = Charsets.Utf8
                    },

                    _ => response.Content.Headers.ContentType
                };

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the userinfo response
        /// from nested JSON nodes (e.g "data") for the providers that require it.
        /// </summary>
        public sealed class UnwrapUserinfoResponse : IOpenIddictClientHandler<ExtractUserinfoResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ExtractUserinfoResponseContext>()
                    .UseSingletonHandler<UnwrapUserinfoResponse>()
                    .SetOrder(int.MaxValue - 50_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ExtractUserinfoResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(context.Response is not null, SR.GetResourceString(SR.ID4007));

                // Some providers are known to wrap their userinfo payloads in top-level JSON nodes
                // (generally named "d", "data" or "response"), which prevents the default extraction
                // logic from mapping the parameters to CLR claims. To work around that, this handler
                // is responsible for extracting the nested payload and replacing the userinfo response.

                context.Response = context.Registration.ProviderType switch
                {
                    // Basecamp returns a nested "identity" object and a collection of "accounts".
                    ProviderTypes.Basecamp => new(context.Response["identity"]?.GetNamedParameters() ??
                        throw new InvalidOperationException(SR.FormatID0334("identity")))
                    {
                        ["accounts"] = context.Response["accounts"]
                    },

                    // Fitbit returns a nested "user" object.
                    ProviderTypes.Fitbit => new(context.Response["user"]?.GetNamedParameters() ??
                        throw new InvalidOperationException(SR.FormatID0334("user"))),

                    // Harvest returns a nested "user" object and a collection of "accounts".
                    ProviderTypes.Harvest => new(context.Response["user"]?.GetNamedParameters() ??
                        throw new InvalidOperationException(SR.FormatID0334("user")))
                    {
                        ["accounts"] = context.Response["accounts"]
                    },

                    // Kroger, Twitter and Patreon return a nested "data" object.
                    ProviderTypes.Kroger or ProviderTypes.Patreon or ProviderTypes.Twitter
                        => new(context.Response["data"]?.GetNamedParameters() ??
                        throw new InvalidOperationException(SR.FormatID0334("data"))),

                    // ServiceChannel returns a nested "UserProfile" object.
                    ProviderTypes.ServiceChannel => new(context.Response["UserProfile"]?.GetNamedParameters() ??
                        throw new InvalidOperationException(SR.FormatID0334("UserProfile"))),

                    // StackExchange returns an "items" array containing a single element.
                    ProviderTypes.StackExchange => new(context.Response["items"]?[0]?.GetNamedParameters() ??
                        throw new InvalidOperationException(SR.FormatID0334("items/0"))),

                    // SubscribeStar returns a nested "user" object that is itself nested in a GraphQL "data" node.
                    ProviderTypes.SubscribeStar => new(context.Response["data"]?["user"]?.GetNamedParameters() ??
                        throw new InvalidOperationException(SR.FormatID0334("data/user"))),

                    // Tumblr returns a nested "user" object that is itself nested in a "response" node.
                    ProviderTypes.Tumblr => new(context.Response["response"]?["user"]?.GetNamedParameters() ??
                        throw new InvalidOperationException(SR.FormatID0334("response/user"))),

                    _ => context.Response
                };

                return default;
            }
        }
    }
}
