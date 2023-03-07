/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using System.Diagnostics;
using System.Security.Claims;
using System.Text.Json;
using OpenIddict.Extensions;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;

namespace OpenIddict.Client.WebIntegration;

[EditorBrowsable(EditorBrowsableState.Never)]
public static partial class OpenIddictClientWebIntegrationHandlers
{
    public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
        /*
         * Authentication processing:
         */
        HandleNonStandardFrontchannelErrorResponse.Descriptor,
        OverrideTokenEndpoint.Descriptor,
        AttachNonStandardClientAssertionTokenClaims.Descriptor,
        AttachTokenRequestNonStandardClientCredentials.Descriptor,
        AdjustRedirectUriInTokenRequest.Descriptor,
        OverrideValidatedBackchannelTokens.Descriptor,
        DisableBackchannelIdentityTokenNonceValidation.Descriptor,
        AttachAdditionalUserinfoRequestParameters.Descriptor,
        PopulateUserinfoTokenPrincipalFromTokenResponse.Descriptor,

        /*
         * Challenge processing:
         */
        OverrideAuthorizationEndpoint.Descriptor,
        OverrideResponseMode.Descriptor,
        FormatNonStandardScopeParameter.Descriptor,
        IncludeStateParameterInRedirectUri.Descriptor,
        AttachAdditionalChallengeParameters.Descriptor)
        .AddRange(Discovery.DefaultHandlers)
        .AddRange(Exchange.DefaultHandlers)
        .AddRange(Protection.DefaultHandlers)
        .AddRange(Userinfo.DefaultHandlers);

    /// <summary>
    /// Contains the logic responsible for handling non-standard
    /// authorization errors for the providers that require it.
    /// </summary>
    public sealed class HandleNonStandardFrontchannelErrorResponse : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<HandleNonStandardFrontchannelErrorResponse>()
                .SetOrder(HandleFrontchannelErrorResponse.Descriptor.Order - 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Note: some providers are known to return non-standard errors.
            // To normalize the set of errors handled by the OpenIddict client,
            // the non-standard errors are mapped to their standard equivalent.
            //
            // Errors that are not handled here will be automatically handled
            // by the standard handler present in the core OpenIddict client.

            if (context.Registration.ProviderName is Providers.Deezer)
            {
                // Note: Deezer uses a custom "error_reason" parameter instead of the
                // standard "error" parameter defined by the OAuth 2.0 specification.
                //
                // See https://developers.deezer.com/api/oauth for more information.
                var error = (string?) context.Request["error_reason"];
                if (string.Equals(error, "user_denied", StringComparison.Ordinal))
                {
                    context.Reject(
                        error: Errors.AccessDenied,
                        description: SR.GetResourceString(SR.ID2149),
                        uri: SR.FormatID8000(SR.ID2149));

                    return default;
                }
            }

            else if (context.Registration.ProviderName is Providers.LinkedIn)
            {
                var error = (string?) context.Request[Parameters.Error];
                if (string.Equals(error, "user_cancelled_authorize", StringComparison.Ordinal) ||
                    string.Equals(error, "user_cancelled_login", StringComparison.Ordinal))
                {
                    context.Reject(
                        error: Errors.AccessDenied,
                        description: SR.GetResourceString(SR.ID2149),
                        uri: SR.FormatID8000(SR.ID2149));

                    return default;
                }
            }

            else if (context.Registration.ProviderName is Providers.Mixcloud)
            {
                var error = (string?) context.Request[Parameters.Error];
                if (string.Equals(error, "user_denied", StringComparison.Ordinal))
                {
                    context.Reject(
                        error: Errors.AccessDenied,
                        description: SR.GetResourceString(SR.ID2149),
                        uri: SR.FormatID8000(SR.ID2149));

                    return default;
                }
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for overriding the address
    /// of the token endpoint for the providers that require it.
    /// </summary>
    public sealed class OverrideTokenEndpoint : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<OverrideTokenEndpoint>()
                .SetOrder(ResolveTokenEndpoint.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            context.TokenEndpoint = context.Registration.ProviderName switch
            {
                // Trovo uses a different token endpoint for the refresh token grant.
                //
                // For more information, see
                // https://developer.trovo.live/docs/APIs.html#_4-3-refresh-access-token.
                Providers.Trovo when context.GrantType is GrantTypes.RefreshToken
                    => new Uri("https://open-api.trovo.live/openplatform/refreshtoken", UriKind.Absolute),

                _ => context.TokenEndpoint
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for amending the client
    /// assertion methods for the providers that require it.
    /// </summary>
    public sealed class AttachNonStandardClientAssertionTokenClaims : IOpenIddictClientHandler<ProcessAuthenticationContext>
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
            if (context.Registration.ProviderName is Providers.Apple)
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
    public sealed class AttachTokenRequestNonStandardClientCredentials : IOpenIddictClientHandler<ProcessAuthenticationContext>
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
            if (context.Registration.ProviderName is Providers.Apple)
            {
                context.TokenRequest.ClientSecret = context.TokenRequest.ClientAssertion;
                context.TokenRequest.ClientAssertion = null;
                context.TokenRequest.ClientAssertionType = null;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching custom client credentials
    /// parameters to the token request for the providers that require it.
    /// </summary>
    public sealed class AdjustRedirectUriInTokenRequest : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireTokenRequest>()
                .UseSingletonHandler<AdjustRedirectUriInTokenRequest>()
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

            if (context.TokenRequest.RedirectUri is null)
            {
                return default;
            }

            // Note: some providers don't support the "state" parameter, don't flow
            // it correctly or don't include it in errored authorization responses.
            //
            // Since OpenIddict requires flowing the state token in every circumstance
            // (for security reasons), the state token is appended to the "redirect_uri"
            // instead of being sent as a standard OAuth 2.0 authorization request parameter.
            //
            // Note: for token requests to use the actual redirect_uri that was sent as part
            // of the authorization requests, the value persisted in the state token principal
            // MUST be replaced to include the state token received by the redirection endpoint.

            context.TokenRequest.RedirectUri = context.Registration.ProviderName switch
            {
                Providers.Deezer or
                Providers.Mixcloud => OpenIddictHelpers.AddQueryStringParameter(
                    uri: new Uri(context.TokenRequest.RedirectUri, UriKind.Absolute),
                    name: Parameters.State,
                    value: context.StateToken).AbsoluteUri,

                _ => context.TokenRequest.RedirectUri
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for overriding the set
    /// of required tokens for the providers that require it.
    /// </summary>
    public sealed class OverrideValidatedBackchannelTokens : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<OverrideValidatedBackchannelTokens>()
                .SetOrder(EvaluateValidatedBackchannelTokens.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            (context.ExtractBackchannelIdentityToken,
             context.RequireBackchannelIdentityToken,
             context.ValidateBackchannelIdentityToken) = context.Registration.ProviderName switch
            {
                // While PayPal claims the OpenID Connect flavor of the code flow is supported,
                // their implementation doesn't return an id_token from the token endpoint.
                Providers.PayPal => (false, false, false),

                _ => (context.ExtractBackchannelIdentityToken,
                      context.RequireBackchannelIdentityToken,
                      context.ValidateBackchannelIdentityToken)
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for disabling the backchannel
    /// identity token nonce validation for the providers that require it.
    /// </summary>
    public sealed class DisableBackchannelIdentityTokenNonceValidation : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<DisableBackchannelIdentityTokenNonceValidation>()
                .SetOrder(ValidateBackchannelIdentityTokenNonce.Descriptor.Order - 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Note: despite implementing OpenID Connect, some providers are known to implement the
            // specification incorrectly and either don't support the "nonce" authorization request
            // parameter, don't include it in the issued identity tokens or flow an unexpected value.
            //
            // Despite being an important security feature, nonce validation is explicitly disabled
            // for the providers that are known to cause errors when nonce validation is enforced.

            context.DisableBackchannelIdentityTokenNonceValidation = context.Registration.ProviderName switch
            {
                Providers.Dropbox => true, // Dropbox doesn't include the nonce in the identity tokens.

                _ => context.DisableBackchannelIdentityTokenNonceValidation
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching additional parameters
    /// to the userinfo request for the providers that require it.
    /// </summary>
    public sealed class AttachAdditionalUserinfoRequestParameters : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireUserinfoRequest>()
                .UseSingletonHandler<AttachAdditionalUserinfoRequestParameters>()
                .SetOrder(AttachUserinfoRequestParameters.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.UserinfoRequest is not null, SR.GetResourceString(SR.ID4008));

            // By default, LinkedIn returns all the basic fields except the profile image.
            // To retrieve the profile image, a projection parameter must be sent with
            // all the parameters that should be returned from the userinfo endpoint.
            if (context.Registration.ProviderName is Providers.LinkedIn)
            {
                var options = context.Registration.GetLinkedInOptions();

                context.UserinfoRequest["projection"] = string.Concat("(", string.Join(",", options.Fields), ")");
            }

            // Patreon limits the number of fields returned by the userinfo endpoint
            // but allows returning additional information using special parameters that
            // determine what fields will be returned as part of the userinfo response.
            else if (context.Registration.ProviderName is Providers.Patreon)
            {
                var options = context.Registration.GetPatreonOptions();

                context.UserinfoRequest["fields[user]"] = string.Join(",", options.UserFields);
            }

            // StackOverflow requires sending an application key and a site parameter
            // containing the name of the site from which the user profile is retrieved.
            else if (context.Registration.ProviderName is Providers.StackExchange)
            {
                var options = context.Registration.GetStackExchangeOptions();

                context.UserinfoRequest["key"] = options.ApplicationKey;
                context.UserinfoRequest["site"] = options.Site;
            }

            // Trakt allows retrieving additional user details via the "extended" parameter.
            else if (context.Registration.ProviderName is Providers.Trakt)
            {
                context.UserinfoRequest["extended"] = "full";
            }

            // Twitter limits the number of fields returned by the userinfo endpoint
            // but allows returning additional information using special parameters that
            // determine what fields will be returned as part of the userinfo response.
            else if (context.Registration.ProviderName is Providers.Twitter)
            {
                var options = context.Registration.GetTwitterOptions();

                context.UserinfoRequest["expansions"] = string.Join(",", options.Expansions);
                context.UserinfoRequest["tweet.fields"] = string.Join(",", options.TweetFields);
                context.UserinfoRequest["user.fields"] = string.Join(",", options.UserFields);
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for creating a userinfo token principal from the custom
    /// parameters returned in the token response for the providers that require it.
    /// </summary>
    public sealed class PopulateUserinfoTokenPrincipalFromTokenResponse : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireTokenRequest>()
                .UseSingletonHandler<PopulateUserinfoTokenPrincipalFromTokenResponse>()
                .SetOrder(ValidateUserinfoToken.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.TokenResponse is not null, SR.GetResourceString(SR.ID4007));

            // Don't overwrite the userinfo token principal if one was already set.
            if (context.UserinfoTokenPrincipal is not null)
            {
                return default;
            }

            // Some providers don't provide an OAuth 2.0/OpenID Connect userinfo endpoint but
            // return the user information using custom/non-standard token response parameters.
            // To work around that, this handler is responsible for extracting these parameters
            // from the token response and creating a userinfo token principal containing them.
            if (context.Registration.ProviderName is Providers.StripeConnect)
            {
                var identity = new ClaimsIdentity(
                    context.Registration.TokenValidationParameters.AuthenticationType,
                    context.Registration.TokenValidationParameters.NameClaimType,
                    context.Registration.TokenValidationParameters.RoleClaimType);

                var issuer = context.Configuration.Issuer!.AbsoluteUri;

                foreach (var parameter in context.TokenResponse.GetParameters())
                {
                    switch (context.Registration.ProviderName)
                    {
                        // For Stripe, only include "livemode" and the parameters that are prefixed with "stripe_":
                        case Providers.StripeConnect when
                            !string.Equals(parameter.Key, "livemode", StringComparison.OrdinalIgnoreCase) &&
                            !parameter.Key.StartsWith("stripe_", StringComparison.OrdinalIgnoreCase):
                            continue;
                    }

                    // Note: in the typical case, the response parameters should be deserialized from a
                    // JSON response and thus natively stored as System.Text.Json.JsonElement instances.
                    //
                    // In the rare cases where the underlying value wouldn't be a JsonElement instance
                    // (e.g when custom parameters are manually added to the response), the static
                    // conversion operator would take care of converting the underlying value to a
                    // JsonElement instance using the same value type as the original parameter value.
                    switch ((JsonElement) parameter.Value)
                    {
                        // Top-level claims represented as arrays are split and mapped to multiple CLR claims
                        // to match the logic implemented by IdentityModel for JWT token deserialization.
                        case { ValueKind: JsonValueKind.Array } value:
                            identity.AddClaims(parameter.Key, value, issuer);
                            break;

                        case { ValueKind: _ } value:
                            identity.AddClaim(parameter.Key, value, issuer);
                            break;
                    }
                }

                context.UserinfoTokenPrincipal = new ClaimsPrincipal(identity);
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for overriding the address of
    /// the authorization endpoint for the providers that require it.
    /// </summary>
    public sealed class OverrideAuthorizationEndpoint : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .UseSingletonHandler<OverrideAuthorizationEndpoint>()
                .SetOrder(AttachChallengeParameters.Descriptor.Order - 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            context.AuthorizationEndpoint = context.Registration.ProviderName switch
            {
                // Stripe uses a different authorization endpoint for express accounts.
                //
                // The type of account can be defined globally (via the Stripe options) or
                // per authentication demand by adding a specific authentication property.
                // If the authentication property is present, the global option is ignored.
                //
                // For more information, see
                // https://stripe.com/docs/connect/oauth-reference?locale=en-us#get-authorize.
                Providers.StripeConnect when context.Properties.TryGetValue(".stripe_account_type", out string? type) &&
                    string.Equals(type, "express", StringComparison.OrdinalIgnoreCase)
                    => new Uri("https://connect.stripe.com/express/oauth/authorize", UriKind.Absolute),

                Providers.StripeConnect when context.Registration.GetStripeConnectOptions() is { AccountType: string type } &&
                    string.Equals(type, "express", StringComparison.OrdinalIgnoreCase)
                    => new Uri("https://connect.stripe.com/express/oauth/authorize", UriKind.Absolute),

                _ => context.AuthorizationEndpoint
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for overriding the response mode for the providers that require it.
    /// </summary>
    public sealed class OverrideResponseMode : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireInteractiveGrantType>()
                .UseSingletonHandler<OverrideResponseMode>()
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

            context.ResponseMode = context.Registration.ProviderName switch
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
    public sealed class FormatNonStandardScopeParameter : IOpenIddictClientHandler<ProcessChallengeContext>
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

            context.Request.Scope = context.Registration.ProviderName switch
            {
                // The following providers are known to use comma-separated scopes instead of
                // the standard format (that requires using a space as the scope separator):
                Providers.Deezer => string.Join(",", context.Scopes),

                // The following providers are known to use plus-separated scopes instead of
                // the standard format (that requires using a space as the scope separator):
                Providers.Trovo => string.Join("+", context.Scopes),

                _ => context.Request.Scope
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for persisting the state parameter in the redirect URI for
    /// providers that don't support it but allow arbitrary dynamic parameters in redirect_uri.
    /// </summary>
    public sealed class IncludeStateParameterInRedirectUri : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireInteractiveGrantType>()
                .UseSingletonHandler<IncludeStateParameterInRedirectUri>()
                .SetOrder(FormatNonStandardScopeParameter.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.RedirectUri is null)
            {
                return default;
            }

            // Note: some providers don't support the "state" parameter, don't flow
            // it correctly or don't include it in errored authorization responses.
            //
            // Since OpenIddict requires flowing the state token in every circumstance
            // (for security reasons), the state token is appended to the "redirect_uri"
            // instead of being sent as a standard OAuth 2.0 authorization request parameter.
            //
            // Note: this workaround only works for providers that allow dynamic
            // redirection URIs and implement a relaxed validation policy logic.

            (context.Request.RedirectUri, context.Request.State) = context.Registration.ProviderName switch
            {
                Providers.Deezer or
                Providers.Mixcloud => (OpenIddictHelpers.AddQueryStringParameter(
                    uri: new Uri(context.RedirectUri, UriKind.Absolute),
                    name: Parameters.State,
                    value: context.Request.State).AbsoluteUri, null),

                _ => (context.Request.RedirectUri, context.Request.State)
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching additional parameters
    /// to the authorization request for the providers that require it.
    /// </summary>
    public sealed class AttachAdditionalChallengeParameters : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireInteractiveGrantType>()
                .UseSingletonHandler<AttachAdditionalChallengeParameters>()
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

            // Active Directory Federation Services allows sending a custom "resource"
            // parameter to define what API resources the access token will give access to.
            if (context.Registration.ProviderName is Providers.ActiveDirectoryFederationServices)
            {
                var options = context.Registration.GetActiveDirectoryFederationServicesOptions();

                context.Request["resource"] = options.Resource;
            }

            // By default, Google doesn't return a refresh token but allows sending an "access_type"
            // parameter to retrieve one (but it is only returned during the first authorization dance).
            if (context.Registration.ProviderName is Providers.Google)
            {
                var options = context.Registration.GetGoogleOptions();

                context.Request["access_type"] = options.AccessType;
            }

            // Pro Santé Connect's specification requires sending an acr_values parameter containing
            // the desired level of authentication (currently, only "eidas1" is supported). For more
            // information, see https://www.legifrance.gouv.fr/jorf/id/JORFTEXT000045551195.
            else if (context.Registration.ProviderName is Providers.ProSantéConnect)
            {
                var options = context.Registration.GetProSantéConnectOptions();

                context.Request.AcrValues = options.AuthenticationLevel;
            }

            // By default, Reddit doesn't return a refresh token but
            // allows sending a "duration" parameter to retrieve one.
            else if (context.Registration.ProviderName is Providers.Reddit)
            {
                var options = context.Registration.GetRedditOptions();

                context.Request["duration"] = options.Duration;
            }

            // Slack allows sending an optional "team" parameter to simplify the login process.
            else if (context.Registration.ProviderName is Providers.Slack)
            {
                var options = context.Registration.GetSlackOptions();

                context.Request["team"] = options.Team;
            }

            return default;
        }
    }
}
