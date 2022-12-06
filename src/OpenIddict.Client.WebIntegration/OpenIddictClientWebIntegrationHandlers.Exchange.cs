/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using OpenIddict.Extensions;
using static OpenIddict.Client.SystemNetHttp.OpenIddictClientSystemNetHttpHandlerFilters;
using static OpenIddict.Client.SystemNetHttp.OpenIddictClientSystemNetHttpHandlers;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;

namespace OpenIddict.Client.WebIntegration;

public static partial class OpenIddictClientWebIntegrationHandlers
{
    public static class Exchange
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Token request preparation:
             */
            AttachNonStandardQueryStringParameters.Descriptor,

            /*
             * Token response extraction:
             */
            MapNonStandardResponseParameters.Descriptor);

        /// <summary>
        /// Contains the logic responsible for attaching non-standard query string
        /// parameters to the token request for the providers that require it.
        /// </summary>
        public sealed class AttachNonStandardQueryStringParameters : IOpenIddictClientHandler<PrepareTokenRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<PrepareTokenRequestContext>()
                    .AddFilter<RequireHttpMetadataUri>()
                    .UseSingletonHandler<AttachNonStandardQueryStringParameters>()
                    .SetOrder(AttachQueryStringParameters<PrepareTokenRequestContext>.Descriptor.Order + 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(PrepareTokenRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another client stack.
                var request = context.Transaction.GetHttpRequestMessage() ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

                if (request.RequestUri is null)
                {
                    return default;
                }

                // By default, Deezer returns non-standard token responses formatted as formurl-encoded
                // payloads and declared as "text/html" content but allows sending an "output" query string
                // parameter containing "json" to get a response conforming to the OAuth 2.0 specification.
                if (context.Registration.ProviderName is Providers.Deezer)
                {
                    request.RequestUri = OpenIddictHelpers.AddQueryStringParameter(
                        request.RequestUri, name: "output", value: "json");
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching non-standard query string
        /// parameters to the token request for the providers that require it.
        /// </summary>
        public sealed class MapNonStandardResponseParameters : IOpenIddictClientHandler<ExtractTokenResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ExtractTokenResponseContext>()
                    .UseSingletonHandler<MapNonStandardResponseParameters>()
                    .SetOrder(int.MaxValue - 50_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ExtractTokenResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (context.Response is null)
                {
                    return default;
                }

                // Note: Deezer doesn't return a standard "expires_in" parameter
                // but returns an equivalent "expires" integer parameter instead.
                if (context.Registration.ProviderName is Providers.Deezer)
                {
                    context.Response[Parameters.ExpiresIn] = context.Response["expires"];
                    context.Response["expires"] = null;
                }

                return default;
            }
        }
    }
}
