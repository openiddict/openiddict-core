/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics;
using System.Text.Json;
using static OpenIddict.Client.SystemNetHttp.OpenIddictClientSystemNetHttpHandlerFilters;
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
            AttachAccessTokenParameter.Descriptor,

            /*
             * Userinfo response extraction:
             */
            UnwrapUserinfoResponse.Descriptor);

        /// <summary>
        /// Contains the logic responsible for attaching the access token
        /// parameter to the request for the providers that require it.
        /// </summary>
        public class AttachAccessTokenParameter : IOpenIddictClientHandler<PrepareUserinfoRequestContext>
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

                if (context.Registration.ProviderName is Providers.Deezer or Providers.StackExchange)
                {
                    context.Request.AccessToken = request.Headers.Authorization?.Parameter;
                    request.Headers.Authorization = null;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the userinfo response
        /// from nested JSON nodes (e.g "data") for the providers that require it.
        /// </summary>
        public class UnwrapUserinfoResponse : IOpenIddictClientHandler<ExtractUserinfoResponseContext>
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
