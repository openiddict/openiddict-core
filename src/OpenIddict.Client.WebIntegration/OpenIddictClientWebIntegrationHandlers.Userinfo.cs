/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics;
using System.Text.Json;
using static OpenIddict.Client.OpenIddictClientHandlers.Userinfo;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;

namespace OpenIddict.Client.WebIntegration;

public static partial class OpenIddictClientWebIntegrationHandlers
{
    public static class Userinfo
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Userinfo response extraction:
             */
            UnwrapUserinfoResponse.Descriptor);

        /// <summary>
        /// Contains the logic responsible for extracting the userinfo response
        /// from nested JSON nodes (e.g "data") for the providers that require it.
        /// </summary>
        public class UnwrapUserinfoResponse : IOpenIddictClientHandler<HandleUserinfoResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleUserinfoResponseContext>()
                    .UseSingletonHandler<UnwrapUserinfoResponse>()
                    .SetOrder(PopulateClaims.Descriptor.Order - 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleUserinfoResponseContext context)
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
