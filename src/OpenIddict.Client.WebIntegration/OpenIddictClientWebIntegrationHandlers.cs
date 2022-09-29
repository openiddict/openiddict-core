/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using System.Diagnostics;
using System.Security.Claims;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;

namespace OpenIddict.Client.WebIntegration;

[EditorBrowsable(EditorBrowsableState.Never)]
public static partial class OpenIddictClientWebIntegrationHandlers
{
    public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
        /*
         * Authentication processing:
         */
        AttachNonStandardClientAssertionTokenClaims.Descriptor,
        AttachTokenRequestNonStandardClientCredentials.Descriptor,

        /*
         * Challenge processing:
         */
        AttachNonDefaultResponseMode.Descriptor,
        FormatNonStandardScopeParameter.Descriptor)
        .AddRange(Discovery.DefaultHandlers)
        .AddRange(Protection.DefaultHandlers)
        .AddRange(Userinfo.DefaultHandlers);

    /// <summary>
    /// Contains the logic responsible for amending the client
    /// assertion methods for the providers that require it.
    /// </summary>
    public class AttachNonStandardClientAssertionTokenClaims : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireClientAssertionTokenGenerated>()
                .UseSingletonHandler<AttachNonStandardClientAssertionTokenClaims>()
                .SetOrder(PrepareClientAssertionTokenPrincipal.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.ClientAssertionTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // For client assertions to be considered valid by the Apple ID authentication service,
            // the team identifier associated with the developer account MUST be used as the issuer
            // and the static "https://appleid.apple.com" URL MUST be used as the token audience.
            //
            // For more information about the custom client authentication method implemented by Apple,
            // see https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens.
            if (context.Registration.GetProviderName() is Providers.Apple)
            {
                var options = context.Registration.GetAppleOptions();
                context.ClientAssertionTokenPrincipal.SetClaim(Claims.Private.Issuer, options.TeamId);
                context.ClientAssertionTokenPrincipal.SetAudiences("https://appleid.apple.com");
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching custom client credentials
    /// parameters to the token request for the providers that require it.
    /// </summary>
    public class AttachTokenRequestNonStandardClientCredentials : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireTokenRequest>()
                .UseSingletonHandler<AttachTokenRequestNonStandardClientCredentials>()
                .SetOrder(AttachTokenRequestClientCredentials.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.TokenRequest is not null, SR.GetResourceString(SR.ID4008));

            // Apple implements a non-standard client authentication method for the token endpoint
            // that is inspired by the standard private_key_jwt method but doesn't use the standard
            // client_assertion/client_assertion_type parameters. Instead, the client assertion
            // must be sent as a "dynamic" client secret using client_secret_post. Since the logic
            // is the same as private_key_jwt, the configuration is amended to assume Apple supports
            // private_key_jwt and an event handler is responsible for populating the client_secret
            // parameter using the client assertion token once it has been generated by OpenIddict.
            if (context.Registration.GetProviderName() is Providers.Apple)
            {
                context.TokenRequest.ClientSecret = context.TokenRequest.ClientAssertion;
                context.TokenRequest.ClientAssertion = null;
                context.TokenRequest.ClientAssertionType = null;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching a specific response mode for providers that require it.
    /// </summary>
    public class AttachNonDefaultResponseMode : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireInteractiveGrantType>()
                .UseSingletonHandler<AttachNonDefaultResponseMode>()
                // Note: this handler MUST be invoked after the scopes have been attached to the
                // context to support overriding the response mode based on the requested scopes.
                .SetOrder(AttachScopes.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            context.ResponseMode = context.Registration.GetProviderName() switch
            {
                // Note: Apple requires using form_post when the "email" or "name" scopes are requested.
                Providers.Apple when context.Scopes.Contains(Scopes.Email) || context.Scopes.Contains("name")
                    => ResponseModes.FormPost,

                _ => context.ResponseMode
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for overriding the standard "scope"
    /// parameter for providers that are known to use a non-standard format.
    /// </summary>
    public class FormatNonStandardScopeParameter : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireInteractiveGrantType>()
                .UseSingletonHandler<FormatNonStandardScopeParameter>()
                .SetOrder(AttachChallengeParameters.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            context.Request.Scope = context.Registration.GetProviderName() switch
            {
                // The following providers are known to use comma-separated scopes instead of
                // the standard format (that requires using a space as the scope separator):
                Providers.Reddit => string.Join(",", context.Scopes),

                _ => context.Request.Scope
            };

            return default;
        }
    }
}
