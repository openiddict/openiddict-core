/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using static OpenIddict.Client.OpenIddictClientHandlers.Protection;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;

namespace OpenIddict.Client.WebIntegration;

public static partial class OpenIddictClientWebIntegrationHandlers
{
    public static class Protection
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create([
            /*
             * Token validation:
             */
            AmendTokenValidationParameters.Descriptor
        ]);

        /// <summary>
        /// Contains the logic responsible for amending the token validation parameters for the providers that require it.
        /// </summary>
        public sealed class AmendTokenValidationParameters : IOpenIddictClientHandler<ValidateTokenContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .UseSingletonHandler<AmendTokenValidationParameters>()
                    .SetOrder(ResolveTokenValidationParameters.Descriptor.Order + 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateTokenContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Note: the client registration may be null (e.g when validating a state token).
                // In this case, don't amend the default token validation parameters.
                if (context.Registration is null)
                {
                    return default;
                }

                context.TokenValidationParameters.ValidateIssuer = context.Registration.ProviderType switch
                {
                    // When the Microsoft Account provider is configured to use one of the special tenants,
                    // the returned tokens include a dynamic issuer claim corresponding to the tenant
                    // that is associated with the client application. Since the tenant cannot be
                    // inferred when targeting these special tenants, issuer validation is disabled.
                    //
                    // For more information about the special tenants supported by Microsoft Account/Entra ID, see
                    // https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc#find-your-apps-openid-configuration-document-uri.
                    ProviderTypes.Microsoft when
                        context.Registration.GetMicrosoftSettings() is { Tenant: string tenant } &&
                        (string.Equals(tenant, "common", StringComparison.OrdinalIgnoreCase) ||
                         string.Equals(tenant, "consumers", StringComparison.OrdinalIgnoreCase) ||
                         string.Equals(tenant, "organizations", StringComparison.OrdinalIgnoreCase))
                        => false,

                    // Note: the issuer returned in the Webex server configuration metadata is region-specific and
                    // varies dynamically depending on the location of the client making the discovery request.
                    // Since the returned issuer is not stable, issuer validation is always disabled for Webex.
                    ProviderTypes.Webex => false,

                    _ => context.TokenValidationParameters.ValidateIssuer
                };

                return default;
            }
        }
    }
}
