/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics;
using System.Net.Http.Headers;
using System.Text;
using OpenIddict.Extensions;
using static OpenIddict.Client.SystemNetHttp.OpenIddictClientSystemNetHttpHandlerFilters;
using static OpenIddict.Client.SystemNetHttp.OpenIddictClientSystemNetHttpHandlers;
using static OpenIddict.Client.SystemNetHttp.OpenIddictClientSystemNetHttpHandlers.Exchange;
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
            AttachNonStandardBasicAuthenticationCredentials.Descriptor,
            AttachNonStandardQueryStringParameters.Descriptor,

            /*
             * Token response extraction:
             */
            MapNonStandardResponseParameters.Descriptor);

        /// <summary>
        /// Contains the logic responsible for attaching the client credentials to the HTTP Authorization
        /// header using a non-standard construction logic for the providers that require it.
        /// </summary>
        public sealed class AttachNonStandardBasicAuthenticationCredentials : IOpenIddictClientHandler<PrepareTokenRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<PrepareTokenRequestContext>()
                    .AddFilter<RequireHttpMetadataUri>()
                    .UseSingletonHandler<AttachNonStandardBasicAuthenticationCredentials>()
                    .SetOrder(AttachBasicAuthenticationCredentials.Descriptor.Order + 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(PrepareTokenRequestContext context)
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
                if (context.Registration.ProviderName is Providers.Reddit)
                {
                    // Important: the credentials MUST be formURL-encoded before being base64-encoded.
                    var credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(new StringBuilder()
                        .Append(EscapeDataString(context.Request.ClientId))
                        .Append(':')
                        .Append(EscapeDataString(context.Request.ClientSecret))
                        .ToString()));

                    // Attach the authorization header containing the client credentials to the HTTP request.
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
