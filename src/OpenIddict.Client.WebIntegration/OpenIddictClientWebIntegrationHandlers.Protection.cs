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
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Token validation:
             */
            AmendTokenValidationParameters.Descriptor);

        /// <summary>
        /// Contains the logic responsible for amending the token validation parameters for the providers that require it.
        /// </summary>
        public class AmendTokenValidationParameters : IOpenIddictClientHandler<ValidateTokenContext>
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

                context.TokenValidationParameters.ValidateIssuer = context.Registration.GetProviderName() switch
                {
                    // When the Microsoft Account provider is configured to use the "common" tenant,
                    // the returned tokens include a dynamic issuer claim corresponding to the tenant
                    // that is associated with the client application. Since the tenant cannot be
                    // inferred when targeting the common tenant instance, issuer validation is disabled.
                    Providers.Microsoft when string.Equals(
                        context.Registration.GetMicrosoftOptions().Tenant,
                        "common", StringComparison.OrdinalIgnoreCase)
                        => false,

                    _ => context.TokenValidationParameters.ValidateIssuer
                };

                return default;
            }
        }
    }
}
