/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;

namespace OpenIddict.Client.WebIntegration;

public static partial class OpenIddictClientWebIntegrationHandlers
{
    public static class Authentication
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Authorization request preparation:
             */
            MapNonStandardRequestParameters.Descriptor);

        /// <summary>
        /// Contains the logic responsible for mapping non-standard request parameters
        /// to their standard equivalent for the providers that require it.
        /// </summary>
        public sealed class MapNonStandardRequestParameters : IOpenIddictClientHandler<PrepareAuthorizationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<PrepareAuthorizationRequestContext>()
                    .UseSingletonHandler<MapNonStandardRequestParameters>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(PrepareAuthorizationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Some providers implement old drafts of the OAuth 2.0 specification that didn't support
                // the "response_type" parameter but relied on a "type" parameter to determine the type
                // of flow (web server or user agent-based). Since the "user_agent" value more or less
                // corresponds to the legacy OAuth 2.0-only implicit flow, it is deliberately not
                // supported, so the only supported value is "web_server" (aka authorization code flow).

                if (context.Registration.ProviderName is Providers.Basecamp)
                {
                    context.Request["type"] = "web_server";
                    context.Request.ResponseType = null;
                }

                return default;
            }
        }
    }
}
