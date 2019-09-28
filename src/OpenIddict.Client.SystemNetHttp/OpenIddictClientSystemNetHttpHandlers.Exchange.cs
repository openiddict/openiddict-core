/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics;
using System.Net.Http.Headers;
using System.Text;

namespace OpenIddict.Client.SystemNetHttp;

public static partial class OpenIddictClientSystemNetHttpHandlers
{
    public static class Exchange
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Token request processing:
             */
            PreparePostHttpRequest<PrepareTokenRequestContext>.Descriptor,
            AttachBasicAuthenticationCredentials.Descriptor,
            AttachFormParameters<PrepareTokenRequestContext>.Descriptor,
            SendHttpRequest<ApplyTokenRequestContext>.Descriptor,
            DisposeHttpRequest<ApplyTokenRequestContext>.Descriptor,

            /*
             * Token response processing:
             */
            ExtractJsonHttpResponse<ExtractTokenResponseContext>.Descriptor,
            DisposeHttpResponse<ExtractTokenResponseContext>.Descriptor);

        /// <summary>
        /// Contains the logic responsible of attaching the client credentials to the HTTP Authorization header.
        /// </summary>
        public class AttachBasicAuthenticationCredentials : IOpenIddictClientHandler<PrepareTokenRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<PrepareTokenRequestContext>()
                    .AddFilter<RequireHttpMetadataAddress>()
                    .UseSingletonHandler<AttachBasicAuthenticationCredentials>()
                    .SetOrder(AttachFormParameters<PrepareTokenRequestContext>.Descriptor.Order - 1000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(PrepareTokenRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(context.Request is not null, SR.GetResourceString(SR.ID4008));

                // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another client stack.
                var request = context.Transaction.GetHttpRequestMessage();
                if (request is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));
                }

                // If no client identifier was attached to the request, skip the following logic.
                if (string.IsNullOrEmpty(context.Request.ClientId))
                {
                    return;
                }

                var configuration = await context.Registration.ConfigurationManager.GetConfigurationAsync(default) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0140));

                // Ensure the issuer resolved from the configuration matches the expected value.
                if (configuration.Issuer != context.Issuer)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0307));
                }

                // The OAuth 2.0 specification recommends sending the client credentials using basic authentication.
                // However, this authentication method is known to have compatibility issues with the way the
                // client credentials are encoded (they MUST be formURL-encoded before being base64-encoded).
                // To guarantee that the OpenIddict client handler can be used with servers implementing
                // non-standard encoding, the client_secret_post is always preferred when it's explicitly
                // listed as a supported client authentication method for the token endpoint.
                // If client_secret_post is not listed or if the server returned an empty methods list,
                // client_secret_basic is always used, as it MUST be implemented by all OAuth 2.0 servers.
                //
                // See https://tools.ietf.org/html/rfc8414#section-2
                // and https://tools.ietf.org/html/rfc6749#section-2.3.1 for more information.
                if (!configuration.TokenEndpointAuthMethodsSupported.Contains(ClientAuthenticationMethods.ClientSecretPost))
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

                static string? EscapeDataString(string? value)
                    => value is not null ? Uri.EscapeDataString(value).Replace("%20", "+") : null;
            }
        }
    }
}
