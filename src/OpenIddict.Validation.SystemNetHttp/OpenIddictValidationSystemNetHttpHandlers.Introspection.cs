/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using JetBrains.Annotations;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Validation.OpenIddictValidationEvents;
using static OpenIddict.Validation.SystemNetHttp.OpenIddictValidationSystemNetHttpHandlerFilters;
using SR = OpenIddict.Abstractions.Resources.OpenIddictResources;

namespace OpenIddict.Validation.SystemNetHttp
{
    public static partial class OpenIddictValidationSystemNetHttpHandlers
    {
        public static class Introspection
        {
            public static ImmutableArray<OpenIddictValidationHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
                /*
                 * Introspection request processing:
                 */
                PreparePostHttpRequest<PrepareIntrospectionRequestContext>.Descriptor,
                AttachBasicAuthenticationCredentials.Descriptor,
                AttachFormParameters<PrepareIntrospectionRequestContext>.Descriptor,
                SendHttpRequest<ApplyIntrospectionRequestContext>.Descriptor,

                /*
                 * Introspection response processing:
                 */
                ExtractJsonHttpResponse<ExtractIntrospectionResponseContext>.Descriptor);

            /// <summary>
            /// Contains the logic responsible of attaching the client credentials to the HTTP Authorization header.
            /// </summary>
            public class AttachBasicAuthenticationCredentials : IOpenIddictValidationHandler<PrepareIntrospectionRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                    = OpenIddictValidationHandlerDescriptor.CreateBuilder<PrepareIntrospectionRequestContext>()
                        .AddFilter<RequireHttpMetadataAddress>()
                        .UseSingletonHandler<AttachBasicAuthenticationCredentials>()
                        .SetOrder(AttachFormParameters<PrepareIntrospectionRequestContext>.Descriptor.Order - 1000)
                        .SetType(OpenIddictValidationHandlerType.BuiltIn)
                        .Build();

                public async ValueTask HandleAsync([NotNull] PrepareIntrospectionRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
                    // this may indicate that the request was incorrectly processed by another client stack.
                    var request = context.Transaction.GetHttpRequestMessage();
                    if (request == null)
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID1172));
                    }

                    var configuration = await context.Options.ConfigurationManager.GetConfigurationAsync(default) ??
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID1139));

                    // The OAuth 2.0 specification recommends sending the client credentials using basic authentication.
                    // However, this authentication method is known to have compatibility issues with how the
                    // client credentials are encoded, that MUST be formURL-encoded before being base64-encoded.
                    // To guarantee that the OpenIddict validation handler can be used with servers implementing
                    // non-standard encoding, the client_secret_post is always preferred when it's explicitly
                    // listed as a supported client authentication method for the introspection endpoint.
                    // If client_secret_post is not listed or if the server returned an empty methods list,
                    // client_secret_basic is always used, as it MUST be supported by all OAuth 2.0 servers.
                    //
                    // See https://tools.ietf.org/html/rfc8414#section-2
                    // and https://tools.ietf.org/html/rfc6749#section-2.3.1 for more information.
                    if (!configuration.IntrospectionEndpointAuthMethodsSupported.Contains(ClientAuthenticationMethods.ClientSecretPost))
                    {
                        var builder = new StringBuilder()
                            .Append(EscapeDataString(context.Request.ClientId))
                            .Append(':')
                            .Append(EscapeDataString(context.Request.ClientSecret));

                        var credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(builder.ToString()));

                        // Attach the authorization header containing the client credentials to the HTTP request.
                        request.Headers.Authorization = new AuthenticationHeaderValue(Schemes.Basic, credentials);

                        // Remove the client credentials from the request.
                        context.Request.ClientId = context.Request.ClientSecret = null;
                    }

                    static string EscapeDataString(string value)
                    {
                        if (string.IsNullOrEmpty(value))
                        {
                            return null;
                        }

                        return Uri.EscapeDataString(value).Replace("%20", "+");
                    }
                }
            }
        }
    }
}
