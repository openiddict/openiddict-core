/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Text.Json;
using System.Text.Json.Nodes;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;

namespace OpenIddict.Client.WebIntegration;

public static partial class OpenIddictClientWebIntegrationHandlers
{
    public static class Introspection
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } =
        [
            /*
             * Introspection response extraction:
             */
            MapNonStandardResponseParameters.Descriptor
        ];

        /// <summary>
        /// Contains the logic responsible for mapping non-standard response parameters
        /// to their standard equivalent for the providers that require it.
        /// </summary>
        public sealed class MapNonStandardResponseParameters : IOpenIddictClientHandler<ExtractIntrospectionResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ExtractIntrospectionResponseContext>()
                    .UseSingletonHandler<MapNonStandardResponseParameters>()
                    .SetOrder(int.MaxValue - 50_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ExtractIntrospectionResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (context.Response is null)
                {
                    return default;
                }

                // Note: NetSuite returns the "scope" parameter as a non-standard string array,
                // so this is converted to a space-separated string.
                if (context.Registration.ProviderType is ProviderTypes.NetSuite &&
                    (JsonElement?)context.Response[Parameters.Scope] is { ValueKind: JsonValueKind.Array } scopeArray)
                {
                    context.Response.Scope = string.Join(
                        " ",
                        scopeArray.EnumerateArray()
                            .Select(val => val.GetString()?.ToLowerInvariant())
                            .Where(val => val is not null)
                    );
                }

                return default;
            }
        }
    }
}
