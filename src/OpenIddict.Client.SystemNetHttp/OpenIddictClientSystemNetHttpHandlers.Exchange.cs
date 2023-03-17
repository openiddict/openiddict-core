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
            CreateHttpClient<PrepareTokenRequestContext>.Descriptor,
            PreparePostHttpRequest<PrepareTokenRequestContext>.Descriptor,
            AttachHttpVersion<PrepareTokenRequestContext>.Descriptor,
            AttachJsonAcceptHeaders<PrepareTokenRequestContext>.Descriptor,
            AttachUserAgentHeader<PrepareTokenRequestContext>.Descriptor,
            AttachFromHeader<PrepareTokenRequestContext>.Descriptor,
            AttachBasicAuthenticationCredentials.Descriptor,
            AttachFormParameters<PrepareTokenRequestContext>.Descriptor,
            SendHttpRequest<ApplyTokenRequestContext>.Descriptor,
            DisposeHttpRequest<ApplyTokenRequestContext>.Descriptor,

            /*
             * Token response processing:
             */
            DecompressResponseContent<ExtractTokenResponseContext>.Descriptor,
            ExtractJsonHttpResponse<ExtractTokenResponseContext>.Descriptor,
            ExtractWwwAuthenticateHeader<ExtractTokenResponseContext>.Descriptor,
            ValidateHttpResponse<ExtractTokenResponseContext>.Descriptor,
            DisposeHttpResponse<ExtractTokenResponseContext>.Descriptor);

        /// <summary>
        /// Contains the logic responsible for attaching the client credentials to the HTTP Authorization header.
        /// </summary>
        public sealed class AttachBasicAuthenticationCredentials : IOpenIddictClientHandler<PrepareTokenRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<PrepareTokenRequestContext>()
                    .AddFilter<RequireHttpMetadataUri>()
                    .UseSingletonHandler<AttachBasicAuthenticationCredentials>()
                    .SetOrder(AttachFormParameters<PrepareTokenRequestContext>.Descriptor.Order - 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(PrepareTokenRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(context.Request is not null, SR.GetResourceString(SR.ID4008));

                // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another client stack.
                var request = context.Transaction.GetHttpRequestMessage() ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

                // The OAuth 2.0 specification recommends sending the client credentials using basic authentication.
                // However, this authentication method is known to have severe compatibility/interoperability issues:
                //
                //   - While restricted to clients that have been given a secret (i.e confidential clients) by the
                //     specification, basic authentication is also sometimes required by server implementations for
                //     public clients that don't have a client secret: in this case, an empty password is used and
                //     the client identifier is sent alone in the Authorization header (instead of being sent using
                //     the standard "client_id" parameter present in the request body).
                //
                //   - While the OAuth 2.0 specification requires that the client credentials be formURL-encoded
                //     before being base64-encoded, many implementations are known to implement a non-standard
                //     encoding scheme, where neither the client_id nor the client_secret are formURL-encoded.
                //
                // To guarantee that the OpenIddict implementation can be used with most servers implementions,
                // basic authentication is only used when a client secret is present and client_secret_post is
                // always preferred when it's explicitly listed as a supported client authentication method.
                // If client_secret_post is not listed or if the server returned an empty methods list,
                // client_secret_basic is always used, as it MUST be implemented by all OAuth 2.0 servers.
                //
                // See https://tools.ietf.org/html/rfc8414#section-2
                // and https://tools.ietf.org/html/rfc6749#section-2.3.1 for more information.
                if (request.Headers.Authorization is null &&
                    !string.IsNullOrEmpty(context.Request.ClientId) &&
                    !string.IsNullOrEmpty(context.Request.ClientSecret) &&
                    UseBasicAuthentication(context.Configuration))
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

                static bool UseBasicAuthentication(OpenIddictConfiguration configuration)
                    => configuration.TokenEndpointAuthMethodsSupported switch
                    {
                        // If at least one authentication method was explicit added, only use basic authentication
                        // if it's supported AND if client_secret_post is not supported or enabled by the server.
                        { Count: > 0 } methods => methods.Contains(ClientAuthenticationMethods.ClientSecretBasic) &&
                                                 !methods.Contains(ClientAuthenticationMethods.ClientSecretPost),

                        // Otherwise, if no authentication method was explicit added, assume only basic is supported.
                        { Count: _ } => true
                    };

                static string EscapeDataString(string value) => Uri.EscapeDataString(value).Replace("%20", "+");
            }
        }
    }
}
