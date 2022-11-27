/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics;
using System.Net.Http.Headers;
using System.Text.Json;
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
            AttachRequestHeaders.Descriptor,
            AttachAccessTokenParameter.Descriptor,

            /*
             * Userinfo response extraction:
             */
            NormalizeContentType.Descriptor,
            UnwrapUserinfoResponse.Descriptor);

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
                    .AddFilter<RequireHttpMetadataAddress>()
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

                // Trakt requires sending both an API key (which is always the client identifier) and an API version
                // (which is statically set to the last version known to be supported by the OpenIddict integration).
                if (context.Registration.ProviderName is Providers.Trakt)
                {
                    var options = context.Registration.GetTraktOptions();

                    request.Headers.Add("trakt-api-key", options.ClientId);
                    request.Headers.Add("trakt-api-version", "2");
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
                    .AddFilter<RequireHttpMetadataAddress>()
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
                // and require sending the access token as part of the userinfo request payload.

                (context.Request.AccessToken, request.Headers.Authorization) = context.Registration.ProviderName switch
                {
                    Providers.Deezer   or
                    Providers.Mixcloud or
                    Providers.StackExchange
                        => (request.Headers.Authorization?.Parameter, null),

                    _ => (context.Request.AccessToken, request.Headers.Authorization)
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

                response.Content.Headers.ContentType = context.Registration.ProviderName switch
                {
                    // Mixcloud returns JSON-formatted contents declared as "text/javascript".
                    Providers.Mixcloud => new MediaTypeHeaderValue(MediaTypes.Json)
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

                context.Response = context.Registration.ProviderName switch
                {
                    // StackExchange returns an "items" array containing a single element.
                    Providers.StackExchange => (JsonElement) context.Response["items"]
                        is { ValueKind: JsonValueKind.Array } element && element.GetArrayLength() is 1 ?
                        new(element[0]) : throw new InvalidOperationException(SR.FormatID0334("items")),

                    // Twitter returns a nested "data" object.
                    Providers.Twitter => (JsonElement) context.Response["data"]
                        is { ValueKind: JsonValueKind.Object } element ?
                        new(element) : throw new InvalidOperationException(SR.FormatID0334("data")),

                    _ => context.Response
                };

                return default;
            }
        }
    }
}
