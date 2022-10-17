/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using static OpenIddict.Client.OpenIddictClientHandlers.Discovery;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;

namespace OpenIddict.Client.WebIntegration;

public static partial class OpenIddictClientWebIntegrationHandlers
{
    public static class Discovery
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Configuration response handling:
             */
            AmendIssuer.Descriptor,
            AmendClientAuthenticationMethods.Descriptor,
            AmendCodeChallengeMethods.Descriptor,
            AmendEndpoints.Descriptor);

        /// <summary>
        /// Contains the logic responsible for amending the issuer for the providers that require it.
        /// </summary>
        public class AmendIssuer : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<AmendIssuer>()
                    .SetOrder(ValidateIssuer.Descriptor.Order - 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Note: the server configuration metadata returned by the Microsoft Account "common" tenant
                // uses "https://login.microsoftonline.com/{tenantid}/v2.0" as the issuer to indicate that
                // the issued identity tokens will have a dynamic issuer claim whose value will be resolved
                // based on the client identity. As required by RFC8414, OpenIddict would automatically reject
                // such responses as the issuer wouldn't match the expected value. To work around that, the issuer
                // is replaced by this handler to always use "https://login.microsoftonline.com/common/v2.0".
                if (context.Registration.ProviderName is Providers.Microsoft &&
                    context.Registration.GetMicrosoftOptions() is { Tenant: string tenant } &&
                    string.Equals(tenant, "common", StringComparison.OrdinalIgnoreCase))
                {
                    context.Response[Metadata.Issuer] = "https://login.microsoftonline.com/common/v2.0";
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for amending the supported
        /// client authentication methods for the providers that require it.
        /// </summary>
        public class AmendClientAuthenticationMethods : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<AmendClientAuthenticationMethods>()
                    .SetOrder(ExtractTokenEndpointClientAuthenticationMethods.Descriptor.Order + 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Apple implements a non-standard client authentication method for the token endpoint
                // that is inspired by the standard private_key_jwt method but doesn't use the standard
                // client_assertion/client_assertion_type parameters. Instead, the client assertion
                // must be sent as a "dynamic" client secret using client_secret_post. Since the logic
                // is the same as private_key_jwt, the configuration is amended to assume Apple supports
                // private_key_jwt and an event handler is responsible for populating the client_secret
                // parameter using the client assertion token once it has been generated by OpenIddict.
                if (context.Registration.ProviderName is Providers.Apple)
                {
                    context.Configuration.TokenEndpointAuthMethodsSupported.Add(
                        ClientAuthenticationMethods.PrivateKeyJwt);
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for amending the supported
        /// code challenge methods for the providers that require it.
        /// </summary>
        public class AmendCodeChallengeMethods : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<AmendCodeChallengeMethods>()
                    .SetOrder(ExtractCodeChallengeMethods.Descriptor.Order + 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Microsoft Account supports both the "plain" and "S256" code challenge methods but
                // doesn't list them in the server configuration metadata. To ensure the OpenIddict
                // client uses Proof Key for Code Exchange for the Microsoft provider, the 2 methods
                // are manually added to the list of supported code challenge methods by this handler.
                if (context.Registration.ProviderName is Providers.Microsoft)
                {
                    context.Configuration.CodeChallengeMethodsSupported.Add(CodeChallengeMethods.Plain);
                    context.Configuration.CodeChallengeMethodsSupported.Add(CodeChallengeMethods.Sha256);
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for amending the endpoint URIs for the providers that require it.
        /// </summary>
        public class AmendEndpoints : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<AmendEndpoints>()
                    .SetOrder(int.MaxValue - 100_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // While PayPal supports OpenID Connect discovery, the configuration document returned
                // by the sandbox environment always contains the production endpoints, which would
                // prevent the OpenIddict integration from working properly when using the sandbox mode.
                // To work around that, the endpoints are manually overriden when this environment is used.
                if (context.Registration.ProviderName is Providers.PayPal &&
                    context.Registration.GetPayPalOptions() is { Environment: PayPal.Environments.Sandbox })
                {
                    context.Configuration.AuthorizationEndpoint =
                        new Uri("https://www.sandbox.paypal.com/signin/authorize", UriKind.Absolute);
                    context.Configuration.JwksUri =
                        new Uri("https://api-m.sandbox.paypal.com/v1/oauth2/certs", UriKind.Absolute);
                    context.Configuration.TokenEndpoint =
                        new Uri("https://api-m.sandbox.paypal.com/v1/oauth2/token", UriKind.Absolute);
                    context.Configuration.UserinfoEndpoint =
                        new Uri("https://api-m.sandbox.paypal.com/v1/oauth2/token/userinfo", UriKind.Absolute);
                }

                return default;
            }
        }
    }
}
