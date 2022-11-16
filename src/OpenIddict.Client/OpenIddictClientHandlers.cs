/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Extensions;
using static OpenIddict.Abstractions.OpenIddictExceptions;

namespace OpenIddict.Client;

[EditorBrowsable(EditorBrowsableState.Never)]
public static partial class OpenIddictClientHandlers
{
    public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
        /*
         * Authentication processing:
         */
        ValidateAuthenticationDemand.Descriptor,
        ResolveClientRegistrationFromAuthenticationContext.Descriptor,
        EvaluateValidatedUpfrontTokens.Descriptor,
        ResolveValidatedStateToken.Descriptor,
        ValidateRequiredStateToken.Descriptor,
        ValidateStateToken.Descriptor,
        RedeemStateTokenEntry.Descriptor,
        ValidateStateTokenEndpointType.Descriptor,
        ValidateRequestForgeryProtection.Descriptor,
        ResolveClientRegistrationFromStateToken.Descriptor,
        ValidateIssuerParameter.Descriptor,
        HandleFrontchannelErrorResponse.Descriptor,
        ResolveGrantTypeFromStateToken.Descriptor,
        ResolveResponseTypeFromStateToken.Descriptor,

        EvaluateValidatedFrontchannelTokens.Descriptor,
        ResolveValidatedFrontchannelTokens.Descriptor,
        ValidateRequiredFrontchannelTokens.Descriptor,

        ValidateFrontchannelIdentityToken.Descriptor,
        ValidateFrontchannelIdentityTokenWellknownClaims.Descriptor,
        ValidateFrontchannelIdentityTokenAudience.Descriptor,
        ValidateFrontchannelIdentityTokenPresenter.Descriptor,
        ValidateFrontchannelIdentityTokenNonce.Descriptor,
        ValidateFrontchannelTokenDigests.Descriptor,

        ValidateFrontchannelAccessToken.Descriptor,
        ValidateAuthorizationCode.Descriptor,

        ResolveTokenEndpoint.Descriptor,
        EvaluateTokenRequest.Descriptor,
        AttachTokenRequestParameters.Descriptor,
        EvaluateGeneratedClientAssertionToken.Descriptor,
        PrepareClientAssertionTokenPrincipal.Descriptor,
        GenerateClientAssertionToken.Descriptor,
        AttachTokenRequestClientCredentials.Descriptor,
        SendTokenRequest.Descriptor,

        EvaluateValidatedBackchannelTokens.Descriptor,
        ResolveValidatedBackchannelTokens.Descriptor,
        ValidateRequiredBackchannelTokens.Descriptor,

        ValidateBackchannelIdentityToken.Descriptor,
        ValidateBackchannelIdentityTokenWellknownClaims.Descriptor,
        ValidateBackchannelIdentityTokenAudience.Descriptor,
        ValidateBackchannelIdentityTokenPresenter.Descriptor,
        ValidateBackchannelIdentityTokenNonce.Descriptor,
        ValidateBackchannelTokenDigests.Descriptor,

        ValidateBackchannelAccessToken.Descriptor,
        ValidateRefreshToken.Descriptor,

        ResolveUserinfoEndpoint.Descriptor,
        EvaluateUserinfoRequest.Descriptor,
        AttachUserinfoRequestParameters.Descriptor,
        SendUserinfoRequest.Descriptor,
        EvaluateValidatedUserinfoToken.Descriptor,
        ValidateRequiredUserinfoToken.Descriptor,
        ValidateUserinfoToken.Descriptor,
        ValidateUserinfoTokenWellknownClaims.Descriptor,
        ValidateUserinfoTokenSubject.Descriptor,

        /*
         * Challenge processing:
         */
        ValidateChallengeDemand.Descriptor,
        ResolveClientRegistrationFromChallengeContext.Descriptor,
        AttachGrantType.Descriptor,
        EvaluateGeneratedChallengeTokens.Descriptor,
        AttachChallengeHostProperties.Descriptor,
        AttachResponseType.Descriptor,
        AttachResponseMode.Descriptor,
        AttachClientId.Descriptor,
        AttachRedirectUri.Descriptor,
        AttachRequestForgeryProtection.Descriptor,
        AttachScopes.Descriptor,
        AttachNonce.Descriptor,
        AttachCodeChallengeParameters.Descriptor,
        PrepareStateTokenPrincipal.Descriptor,
        ValidateRedirectUriParameter.Descriptor,
        GenerateStateToken.Descriptor,
        AttachChallengeParameters.Descriptor,
        AttachCustomChallengeParameters.Descriptor,

        /*
         * Sign-out processing:
         */
        ValidateSignOutDemand.Descriptor,
        ResolveClientRegistrationFromSignOutContext.Descriptor,
        AttachOptionalClientId.Descriptor,
        AttachPostLogoutRedirectUri.Descriptor,
        EvaluateGeneratedLogoutTokens.Descriptor,
        AttachSignOutHostProperties.Descriptor,
        AttachLogoutNonce.Descriptor,
        AttachLogoutRequestForgeryProtection.Descriptor,
        PrepareLogoutStateTokenPrincipal.Descriptor,
        GenerateLogoutStateToken.Descriptor,
        AttachSignOutParameters.Descriptor,
        AttachCustomSignOutParameters.Descriptor,

        /*
         * Error processing:
         */
        AttachErrorParameters.Descriptor)

        .AddRange(Authentication.DefaultHandlers)
        .AddRange(Discovery.DefaultHandlers)
        .AddRange(Exchange.DefaultHandlers)
        .AddRange(Protection.DefaultHandlers)
        .AddRange(Session.DefaultHandlers)
        .AddRange(Userinfo.DefaultHandlers);

    /// <summary>
    /// Contains the logic responsible for rejecting invalid authentication demands.
    /// </summary>
    public sealed class ValidateAuthenticationDemand : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<ValidateAuthenticationDemand>()
                .SetOrder(int.MinValue + 100_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Authentication demands can be triggered from the redirection endpoints
            // to handle authorization/logout callbacks but also from unknown endpoints
            // when using the refresh token grant, to perform a token refresh dance.

            switch (context.EndpointType)
            {
                case OpenIddictClientEndpointType.Redirection:
                case OpenIddictClientEndpointType.PostLogoutRedirection:
                    break;

                case OpenIddictClientEndpointType.Unknown:
                    if (string.IsNullOrEmpty(context.GrantType))
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID0309));
                    }

                    if (context.GrantType is not (
                        GrantTypes.AuthorizationCode or GrantTypes.ClientCredentials or
                        GrantTypes.Implicit          or GrantTypes.Password          or GrantTypes.RefreshToken))
                    {
                        throw new InvalidOperationException(SR.FormatID0310(context.GrantType));
                    }

                    if (context.GrantType is GrantTypes.Password)
                    {
                        if (string.IsNullOrEmpty(context.Username))
                        {
                            throw new InvalidOperationException(SR.GetResourceString(SR.ID0337));
                        }

                        if (string.IsNullOrEmpty(context.Password))
                        {
                            throw new InvalidOperationException(SR.GetResourceString(SR.ID0338));
                        }
                    }

                    if (context.GrantType is GrantTypes.RefreshToken &&
                        string.IsNullOrEmpty(context.RefreshToken))
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID0311));
                    }

                    // If no issuer was explicitly attached and a single client is registered, use it.
                    // Otherwise, throw an exception to indicate that setting an explicit issuer
                    // is required when multiple clients are registered.
                    context.Issuer ??= context.Options.Registrations.Count switch
                    {
                        0 => throw new InvalidOperationException(SR.GetResourceString(SR.ID0304)),
                        1 => context.Options.Registrations[0].Issuer,
                        _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0355))
                    };

                    break;

                default: throw new InvalidOperationException(SR.GetResourceString(SR.ID0290));
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for resolving the client registration applicable to the authentication demand.
    /// </summary>
    public sealed class ResolveClientRegistrationFromAuthenticationContext : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<ResolveClientRegistrationFromAuthenticationContext>()
                .SetOrder(ValidateAuthenticationDemand.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Note: this handler only applies to authentication demands triggered from unknown endpoints.
            //
            // Client registrations/configurations that need to be resolved as part of authentication demands
            // triggered from the redirection or post-logout redirection requests are handled elsewhere.
            if (context.EndpointType is not OpenIddictClientEndpointType.Unknown)
            {
                return;
            }

            // Note: if the static registration cannot be found in the options, this may indicate
            // the client was removed after the authorization dance started and thus, can no longer
            // be used to authenticate users. In this case, throw an exception to abort the flow.
            context.Registration ??= context.Options.Registrations.Find(
                registration => registration.Issuer == context.Issuer) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0292));

            // Resolve and attach the server configuration to the context if none has been set already.
            context.Configuration ??= await context.Registration.ConfigurationManager.GetConfigurationAsync(default) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0140));

            // Ensure the issuer resolved from the configuration matches the expected value.
            if (context.Configuration.Issuer != context.Issuer)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0307));
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for determining the types of tokens to validate upfront.
    /// </summary>
    public sealed class EvaluateValidatedUpfrontTokens : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<EvaluateValidatedUpfrontTokens>()
                .SetOrder(ResolveClientRegistrationFromAuthenticationContext.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            (context.ExtractStateToken,
             context.RequireStateToken,
             context.ValidateStateToken) = context.EndpointType switch
            {
                // While the OAuth 2.0/2.1 and OpenID Connect specifications don't require sending a
                // state as part of authorization requests, the identity provider MUST return the state
                // if one was initially specified. Since OpenIddict always sends a state (used as a way
                // to mitigate CSRF attacks and store per-authorization values like the identity of the
                // chosen authorization server), the state is always considered required at this point.
                OpenIddictClientEndpointType.Redirection => (true, true, true),

                // While the OpenID Connect RP-initiated logout specification doesn't require sending
                // a state as part of logout requests, the identity provider MUST return the state
                // if one was initially specified. Since OpenIddict always sends a state (used as a
                // way to mitigate CSRF attacks and store per-logout values like the identity of the
                // chosen authorization server), the state is always considered required at this point.
                OpenIddictClientEndpointType.PostLogoutRedirection => (true, true, true),

                _ => (false, false, false)
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for resolving the state token to validate upfront from the incoming request.
    /// </summary>
    public sealed class ResolveValidatedStateToken : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<ResolveValidatedStateToken>()
                .SetOrder(EvaluateValidatedUpfrontTokens.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            context.StateToken = context.EndpointType switch
            {
                OpenIddictClientEndpointType.Redirection or OpenIddictClientEndpointType.PostLogoutRedirection
                    when context.ExtractStateToken => context.Request.State,

                _ => null
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for rejecting authentication demands that lack the required state token.
    /// </summary>
    public sealed class ValidateRequiredStateToken : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<ValidateRequiredStateToken>()
                // Note: this handler is registered with a high gap to allow handlers
                // that do token extraction to be executed before this handler runs.
                .SetOrder(ResolveValidatedStateToken.Descriptor.Order + 50_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.RequireStateToken && string.IsNullOrEmpty(context.StateToken))
            {
                context.Reject(
                    error: Errors.MissingToken,
                    description: SR.GetResourceString(SR.ID2000),
                    uri: SR.FormatID8000(SR.ID2000));

                return default;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the state token resolved from the context.
    /// </summary>
    public sealed class ValidateStateToken : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly IOpenIddictClientDispatcher _dispatcher;

        public ValidateStateToken(IOpenIddictClientDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireStateTokenValidated>()
                .UseScopedHandler<ValidateStateToken>()
                .SetOrder(ValidateRequiredStateToken.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.StateTokenPrincipal is not null ||
                string.IsNullOrEmpty(context.StateToken))
            {
                return;
            }

            var notification = new ValidateTokenContext(context.Transaction)
            {
                Token = context.StateToken,
                ValidTokenTypes = { TokenTypeHints.StateToken }
            };

            await _dispatcher.DispatchAsync(notification);

            if (notification.IsRequestHandled)
            {
                context.HandleRequest();
                return;
            }

            else if (notification.IsRequestSkipped)
            {
                context.SkipRequest();
                return;
            }

            else if (notification.IsRejected)
            {
                context.Reject(
                    error: notification.Error ?? Errors.InvalidRequest,
                    description: notification.ErrorDescription,
                    uri: notification.ErrorUri);
                return;
            }

            context.StateTokenPrincipal = notification.Principal;
        }
    }

    /// <summary>
    /// Contains the logic responsible for redeeming the token entry corresponding to the received state token.
    /// Note: this handler is not used when the degraded mode is enabled.
    /// </summary>
    public sealed class RedeemStateTokenEntry : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly IOpenIddictTokenManager _tokenManager;

        public RedeemStateTokenEntry() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0318));

        public RedeemStateTokenEntry(IOpenIddictTokenManager tokenManager)
            => _tokenManager = tokenManager ?? throw new ArgumentNullException(nameof(tokenManager));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireTokenStorageEnabled>()
                .AddFilter<RequireStateTokenPrincipal>()
                .UseScopedHandler<RedeemStateTokenEntry>()
                // Note: this handler is deliberately executed early in the pipeline to ensure
                // that the state token entry is always marked as redeemed even if the authentication
                // demand is rejected later in the pipeline (e.g because an error was returned).
                .SetOrder(ValidateStateToken.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.StateTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Extract the token identifier from the state token principal.
            // If no token identifier can be found, this indicates that the token has no backing database entry.
            var identifier = context.StateTokenPrincipal.GetTokenId();
            if (string.IsNullOrEmpty(identifier))
            {
                return;
            }

            // Mark the token as redeemed to prevent future reuses.
            var token = await _tokenManager.FindByIdAsync(identifier);
            if (token is not null && !await _tokenManager.TryRedeemAsync(token))
            {
                context.Reject(
                    error: Errors.InvalidToken,
                    description: SR.GetResourceString(SR.ID2139),
                    uri: SR.FormatID8000(SR.ID2139));

                return;
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for ensuring the resolved state
    /// token is suitable for the requested authentication demand.
    /// </summary>
    public sealed class ValidateStateTokenEndpointType : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireStateTokenPrincipal>()
                .UseSingletonHandler<ValidateStateTokenEndpointType>()
                .SetOrder(RedeemStateTokenEntry.Descriptor.Order + 1_000)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.StateTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Resolve the endpoint type allowed to be used with the state token.
            if (!Enum.TryParse(context.StateTokenPrincipal.GetClaim(Claims.Private.EndpointType),
                ignoreCase: true, out OpenIddictClientEndpointType type))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0340));
            }

            // Reject the authentication demand if the expected endpoint type doesn't
            // match the current endpoint type as it may indicate a mix-up attack (e.g a
            // state token created for a logout operation was used for a login operation).
            if (type != context.EndpointType)
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.GetResourceString(SR.ID2142),
                    uri: SR.FormatID8000(SR.ID2142));

                return default;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the request forgery protection claim that serves as a
    /// protection against state token injection, forged requests, denial of service and session fixation attacks.
    /// </summary>
    public sealed class ValidateRequestForgeryProtection : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireStateTokenValidated>()
                .UseSingletonHandler<ValidateRequestForgeryProtection>()
                .SetOrder(ValidateStateTokenEndpointType.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.StateTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Resolve the request forgery protection from the state token principal.
            var comparand = context.StateTokenPrincipal.GetClaim(Claims.RequestForgeryProtection);
            if (string.IsNullOrEmpty(comparand))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0339));
            }

            // The request forgery protection serves as a binding mechanism ensuring that a
            // state token stolen from an authorization response with the other parameters
            // cannot be validly used without also sending the matching correlation identifier.
            //
            // If the request forgery protection couldn't be resolved at this point or doesn't
            // match the expected value, this may indicate that the authentication demand is
            // unsolicited and potentially malicious (or caused by an invalid or unadequate
            // same-site configuration, if the authentication demand was handled by a web server).
            //
            // In any case, the authentication demand MUST be rejected as it's impossible to ensure
            // it's not an injection or session fixation attack without the correct "rfp" value.
            if (string.IsNullOrEmpty(context.RequestForgeryProtection) || !OpenIddictHelpers.FixedTimeEquals(
                left:  MemoryMarshal.AsBytes(comparand.AsSpan()),
                right: MemoryMarshal.AsBytes(context.RequestForgeryProtection.AsSpan())))
            {
                context.Logger.LogWarning(SR.GetResourceString(SR.ID6209));

                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.GetResourceString(SR.ID2164),
                    uri: SR.FormatID8000(SR.ID2164));

                return default;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for resolving the client registration
    /// based on the authorization server identity stored in the state token.
    /// </summary>
    public sealed class ResolveClientRegistrationFromStateToken : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireStateTokenPrincipal>()
                .UseSingletonHandler<ResolveClientRegistrationFromStateToken>()
                .SetOrder(ValidateRequestForgeryProtection.Descriptor.Order + 1_000)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.StateTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Retrieve the client definition using the authorization server stored in the state token.
            //
            // Note: there's no guarantee that the state token was not replaced by a malicious actor
            // with a state token meant to be used with a different authorization server as part of a
            // mix-up attack where the state token and the authorization code or access/identity tokens
            // wouldn't match. To mitigate this, additional defenses are added later by other handlers.

            // Restore the identity of the authorization server from the special "as" claim.
            // See https://datatracker.ietf.org/doc/html/draft-bradley-oauth-jwt-encoded-state-09#section-2
            // for more information.
            var value = context.StateTokenPrincipal.GetClaim(Claims.AuthorizationServer);
            if (string.IsNullOrEmpty(value) || !Uri.TryCreate(value, UriKind.Absolute, out Uri? issuer) ||
                !issuer.IsWellFormedOriginalString())
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0291));
            }

            // Note: if the static registration cannot be found in the options, this may indicate
            // the client was removed after the authorization dance started and thus, can no longer
            // be used to authenticate users. In this case, throw an exception to abort the flow.
            context.Issuer = issuer;
            context.Registration = context.Options.Registrations.Find(registration => registration.Issuer == issuer) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0292));

            // Resolve and attach the server configuration to the context.
            context.Configuration = await context.Registration.ConfigurationManager.GetConfigurationAsync(default) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0140));

            // Ensure the issuer resolved from the configuration matches the expected value.
            if (context.Configuration.Issuer != context.Issuer)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0307));
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for ensuring the issuer parameter, if available, matches the expected issuer.
    /// </summary>
    public sealed class ValidateIssuerParameter : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireRedirectionRequest>()
                .UseSingletonHandler<ValidateIssuerParameter>()
                .SetOrder(ResolveClientRegistrationFromStateToken.Descriptor.Order + 1_000)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Issuer is { IsAbsoluteUri: true }, SR.GetResourceString(SR.ID4013));

            // To help mitigate mix-up attacks, the identity of the issuer can be returned by
            // authorization servers that support it as a part of the "iss" parameter, which
            // allows comparing it to the issuer in the state token. Depending on the selected
            // response_type, the same information could be retrieved from the identity token
            // that is expected to contain an "iss" claim containing the issuer identity.
            //
            // This handler eagerly validates the "iss" parameter if the authorization server
            // is known to support it (and automatically rejects the request if it doesn't).
            // Validation based on the identity token is performed later in the pipeline.
            //
            // See https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-19#section-4.4
            // for more information.
            var issuer = (string?) context.Request[Parameters.Iss];

            if (context.Configuration.AuthorizationResponseIssParameterSupported is true)
            {
                // Reject authorization responses that don't contain the "iss" parameter
                // if the server configuration indicates this parameter should be present.
                if (string.IsNullOrEmpty(issuer))
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.GetResourceString(SR.ID2029),
                        uri: SR.FormatID8000(SR.ID2029));

                    return default;
                }

                // If the two values don't match, this may indicate a mix-up attack attempt.
                if (!Uri.TryCreate(issuer, UriKind.Absolute, out Uri? uri) ||
                    !uri.IsWellFormedOriginalString() || uri != context.Configuration.Issuer)
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2119(Parameters.Iss),
                        uri: SR.FormatID8000(SR.ID2119));

                    return default;
                }
            }

            // Reject authorization responses containing an "iss" parameter if the configuration
            // doesn't indicate this parameter is supported, as recommended by the specification.
            // See https://datatracker.ietf.org/doc/html/draft-ietf-oauth-iss-auth-resp-05#section-2.4
            // for more information.
            else if (!string.IsNullOrEmpty(issuer))
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.FormatID2120(Parameters.Iss, Metadata.AuthorizationResponseIssParameterSupported),
                    uri: SR.FormatID8000(SR.ID2120));

                return default;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for rejecting errored authorization responses.
    /// </summary>
    public sealed class HandleFrontchannelErrorResponse : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireRedirectionRequest>()
                .UseSingletonHandler<HandleFrontchannelErrorResponse>()
                .SetOrder(ValidateIssuerParameter.Descriptor.Order + 1_000)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Note: for more information about the standard error codes,
            // see https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1 and
            // https://openid.net/specs/openid-connect-core-1_0.html#AuthError.
            var error = (string?) context.Request[Parameters.Error];
            if (!string.IsNullOrEmpty(error))
            {
                context.Logger.LogInformation(SR.GetResourceString(SR.ID6208), context.Request);

                context.Reject(
                    error: error switch
                    {
                        Errors.AccessDenied             => Errors.AccessDenied,
                        Errors.AccountSelectionRequired => Errors.AccountSelectionRequired,
                        Errors.ConsentRequired          => Errors.ConsentRequired,
                        Errors.InteractionRequired      => Errors.InteractionRequired,
                        Errors.InvalidRequest           => Errors.InvalidRequest,
                        Errors.InvalidScope             => Errors.InvalidScope,
                        Errors.LoginRequired            => Errors.LoginRequired,
                        Errors.ServerError              => Errors.ServerError,
                        Errors.TemporarilyUnavailable   => Errors.TemporarilyUnavailable,
                        Errors.UnauthorizedClient       => Errors.UnauthorizedClient,
                        Errors.UnsupportedResponseType  => Errors.UnsupportedResponseType,
                        _                               => Errors.InvalidRequest
                    },
                    description: error switch
                    {
                        Errors.AccessDenied             => SR.GetResourceString(SR.ID2149),
                        Errors.AccountSelectionRequired => SR.GetResourceString(SR.ID2156),
                        Errors.ConsentRequired          => SR.GetResourceString(SR.ID2157),
                        Errors.InteractionRequired      => SR.GetResourceString(SR.ID2158),
                        Errors.InvalidRequest           => SR.GetResourceString(SR.ID2150),
                        Errors.InvalidScope             => SR.GetResourceString(SR.ID2151),
                        Errors.LoginRequired            => SR.GetResourceString(SR.ID2159),
                        Errors.ServerError              => SR.GetResourceString(SR.ID2152),
                        Errors.TemporarilyUnavailable   => SR.GetResourceString(SR.ID2153),
                        Errors.UnauthorizedClient       => SR.GetResourceString(SR.ID2154),
                        Errors.UnsupportedResponseType  => SR.GetResourceString(SR.ID2155),
                        _                               => SR.GetResourceString(SR.ID2160)
                    },
                    uri: error switch
                    {
                        Errors.AccessDenied             => SR.FormatID8000(SR.ID2149),
                        Errors.AccountSelectionRequired => SR.FormatID8000(SR.ID2156),
                        Errors.ConsentRequired          => SR.FormatID8000(SR.ID2157),
                        Errors.InteractionRequired      => SR.FormatID8000(SR.ID2158),
                        Errors.InvalidRequest           => SR.FormatID8000(SR.ID2150),
                        Errors.InvalidScope             => SR.FormatID8000(SR.ID2151),
                        Errors.LoginRequired            => SR.FormatID8000(SR.ID2159),
                        Errors.ServerError              => SR.FormatID8000(SR.ID2152),
                        Errors.TemporarilyUnavailable   => SR.FormatID8000(SR.ID2153),
                        Errors.UnauthorizedClient       => SR.FormatID8000(SR.ID2154),
                        Errors.UnsupportedResponseType  => SR.FormatID8000(SR.ID2155),
                        _                               => SR.FormatID8000(SR.ID2160)
                    });

                return default;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for resolving the grant type
    /// initially negotiated and stored in the state token, if applicable.
    /// </summary>
    public sealed class ResolveGrantTypeFromStateToken : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireRedirectionRequest>()
                .AddFilter<RequireStateTokenPrincipal>()
                .UseSingletonHandler<ResolveGrantTypeFromStateToken>()
                .SetOrder(HandleFrontchannelErrorResponse.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.StateTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Resolve the negotiated grant type from the state token.
            var type = context.StateTokenPrincipal.GetClaim(Claims.Private.GrantType);

            // Note: OpenIddict currently only supports the implicit, authorization code and refresh
            // token grants but additional grants (like CIBA) may be supported in future versions.
            switch (context.EndpointType)
            {
                // Authentication demands triggered from the redirection endpoint are only valid for
                // the authorization code and implicit grants (which includes the hybrid flow, that
                // can be represented using either the authorization code or implicit grant types).
                case OpenIddictClientEndpointType.Redirection when type is not
                    (GrantTypes.AuthorizationCode or GrantTypes.Implicit):
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.GetResourceString(SR.ID2130),
                        uri: SR.FormatID8000(SR.ID2130));

                    return default;
            }

            context.GrantType = type;

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for resolving the response type
    /// initially negotiated and stored in the state token, if applicable.
    /// </summary>
    public sealed class ResolveResponseTypeFromStateToken : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireRedirectionRequest>()
                .AddFilter<RequireStateTokenPrincipal>()
                .UseSingletonHandler<ResolveResponseTypeFromStateToken>()
                .SetOrder(ResolveGrantTypeFromStateToken.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.StateTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Resolve the negotiated response type from the state token.
            context.ResponseType = context.StateTokenPrincipal.GetClaim(Claims.Private.ResponseType);

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for determining the set of frontchannel tokens to validate.
    /// </summary>
    public sealed class EvaluateValidatedFrontchannelTokens : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<EvaluateValidatedFrontchannelTokens>()
                .SetOrder(ResolveResponseTypeFromStateToken.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            (context.ExtractAuthorizationCode,
             context.RequireAuthorizationCode,
             context.ValidateAuthorizationCode) = context.GrantType switch
            {
                // An authorization code is returned for the authorization code and implicit grants when
                // the response type contains the "code" value, which includes the authorization code
                // flow and some variations of the hybrid flow. As such, an authorization code is only
                // considered required if the negotiated response_type includes "code".
                //
                // Note: since authorization codes are supposed to be opaque to the clients, they are never
                // validated by default. Clients that need to deal with non-standard implementations
                // can use custom handlers to validate access tokens that use a readable format (e.g JWT).
                GrantTypes.AuthorizationCode or GrantTypes.Implicit when HasResponseType(ResponseTypes.Code)
                    => (true, true, false),

                _ => (false, false, false)
            };

            (context.ExtractFrontchannelAccessToken,
             context.RequireFrontchannelAccessToken,
             context.ValidateFrontchannelAccessToken) = context.GrantType switch
            {
                // An access token is returned for the authorization code and implicit grants when
                // the response type contains the "token" value, which includes some variations of
                // the implicit and hybrid flows, but not the authorization code flow. As such,
                // a frontchannel access token is only considered required if a token was requested.
                //
                // Note: since access tokens are supposed to be opaque to the clients, they are never
                // validated by default. Clients that need to deal with non-standard implementations
                // can use custom handlers to validate access tokens that use a readable format (e.g JWT).
                GrantTypes.AuthorizationCode or GrantTypes.Implicit when HasResponseType(ResponseTypes.Token)
                    => (true, true, false),

                _ => (false, false, false)
            };

            (context.ExtractFrontchannelIdentityToken,
             context.RequireFrontchannelIdentityToken,
             context.ValidateFrontchannelIdentityToken) = context.GrantType switch
            {
                // An identity token is returned for the authorization code and implicit grants when
                // the response type contains the "id_token" value, which includes some variations
                // of the implicit and hybrid flows, but not the authorization code flow. As such,
                // a frontchannel identity token is only considered required if an id_token was requested.
                //
                // Note: the granted scopes list (returned as a "scope" parameter in authorization
                // responses) is not used in this case as it's not protected against tampering.
                GrantTypes.AuthorizationCode or GrantTypes.Implicit when HasResponseType(ResponseTypes.IdToken)
                    => (true, true, true),

                _ => (false, false, false)
            };

            return default;

            bool HasResponseType(string value) => context.ResponseType!.Split(Separators.Space).Contains(value);
        }
    }

    /// <summary>
    /// Contains the logic responsible for resolving the token from the incoming request.
    /// </summary>
    public sealed class ResolveValidatedFrontchannelTokens : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<ResolveValidatedFrontchannelTokens>()
                .SetOrder(EvaluateValidatedFrontchannelTokens.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            context.AuthorizationCode = context.EndpointType switch
            {
                OpenIddictClientEndpointType.Redirection when context.ExtractAuthorizationCode
                    => context.Request.Code,

                _ => null
            };

            context.FrontchannelAccessToken = context.EndpointType switch
            {
                OpenIddictClientEndpointType.Redirection when context.ExtractFrontchannelAccessToken
                    => context.Request.AccessToken,

                _ => null
            };

            context.FrontchannelIdentityToken = context.EndpointType switch
            {
                OpenIddictClientEndpointType.Redirection when context.ExtractFrontchannelIdentityToken
                    => context.Request.IdToken,

                _ => null
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for rejecting authentication demands that lack required tokens.
    /// </summary>
    public sealed class ValidateRequiredFrontchannelTokens : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<ValidateRequiredFrontchannelTokens>()
                // Note: this handler is registered with a high gap to allow handlers
                // that do token extraction to be executed before this handler runs.
                .SetOrder(ResolveValidatedFrontchannelTokens.Descriptor.Order + 50_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if ((context.RequireAuthorizationCode         && string.IsNullOrEmpty(context.AuthorizationCode))       ||
                (context.RequireFrontchannelAccessToken   && string.IsNullOrEmpty(context.FrontchannelAccessToken)) ||
                (context.RequireFrontchannelIdentityToken && string.IsNullOrEmpty(context.FrontchannelIdentityToken)))
            {
                context.Reject(
                    error: Errors.MissingToken,
                    description: SR.GetResourceString(SR.ID2000),
                    uri: SR.FormatID8000(SR.ID2000));

                return default;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the frontchannel identity token resolved from the context.
    /// </summary>
    public sealed class ValidateFrontchannelIdentityToken : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly IOpenIddictClientDispatcher _dispatcher;

        public ValidateFrontchannelIdentityToken(IOpenIddictClientDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireFrontchannelIdentityTokenValidated>()
                .UseScopedHandler<ValidateFrontchannelIdentityToken>()
                .SetOrder(ValidateRequiredFrontchannelTokens.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.FrontchannelIdentityTokenPrincipal is not null ||
                string.IsNullOrEmpty(context.FrontchannelIdentityToken))
            {
                return;
            }

            var notification = new ValidateTokenContext(context.Transaction)
            {
                Token = context.FrontchannelIdentityToken,
                ValidTokenTypes = { TokenTypeHints.IdToken }
            };

            await _dispatcher.DispatchAsync(notification);

            if (notification.IsRequestHandled)
            {
                context.HandleRequest();
                return;
            }

            else if (notification.IsRequestSkipped)
            {
                context.SkipRequest();
                return;
            }

            else if (notification.IsRejected)
            {
                context.Reject(
                    error: notification.Error ?? Errors.InvalidRequest,
                    description: notification.ErrorDescription,
                    uri: notification.ErrorUri);
                return;
            }

            context.FrontchannelIdentityTokenPrincipal = notification.Principal;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the well-known claims contained in the frontchannel identity token.
    /// </summary>
    public sealed class ValidateFrontchannelIdentityTokenWellknownClaims : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireFrontchannelIdentityTokenPrincipal>()
                .UseSingletonHandler<ValidateFrontchannelIdentityTokenWellknownClaims>()
                .SetOrder(ValidateFrontchannelIdentityToken.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.FrontchannelIdentityTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            foreach (var group in context.FrontchannelIdentityTokenPrincipal.Claims
                .GroupBy(claim => claim.Type)
                .ToDictionary(group => group.Key, group => group.ToList()))
            {
                if (ValidateClaimGroup(group))
                {
                    continue;
                }

                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.FormatID2121(group.Key),
                    uri: SR.FormatID8000(SR.ID2121));

                return default;
            }

            // Identity tokens MUST contain an "iss" claim. For more information,
            // see https://openid.net/specs/openid-connect-core-1_0.html#IDToken.
            if (!context.FrontchannelIdentityTokenPrincipal.HasClaim(Claims.Issuer))
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.FormatID2122(Claims.Issuer),
                    uri: SR.FormatID8000(SR.ID2122));

                return default;
            }

            // Identity tokens MUST contain a "sub" claim. For more information,
            // see https://openid.net/specs/openid-connect-core-1_0.html#IDToken.
            if (!context.FrontchannelIdentityTokenPrincipal.HasClaim(Claims.Subject))
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.FormatID2122(Claims.Subject),
                    uri: SR.FormatID8000(SR.ID2122));

                return default;
            }

            // Identity tokens MUST contain at least one "aud" claim. For more information,
            // see https://openid.net/specs/openid-connect-core-1_0.html#IDToken.
            if (!context.FrontchannelIdentityTokenPrincipal.HasClaim(Claims.Audience))
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.FormatID2122(Claims.Audience),
                    uri: SR.FormatID8000(SR.ID2122));

                return default;
            }

            // Identity tokens MUST contain contain a "exp" claim. For more information,
            // see https://openid.net/specs/openid-connect-core-1_0.html#IDToken.
            if (!context.FrontchannelIdentityTokenPrincipal.HasClaim(Claims.ExpiresAt))
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.FormatID2122(Claims.ExpiresAt),
                    uri: SR.FormatID8000(SR.ID2122));

                return default;
            }

            // Identity tokens MUST contain contain an "iat" claim. For more information,
            // see https://openid.net/specs/openid-connect-core-1_0.html#IDToken.
            if (!context.FrontchannelIdentityTokenPrincipal.HasClaim(Claims.IssuedAt))
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.FormatID2122(Claims.IssuedAt),
                    uri: SR.FormatID8000(SR.ID2122));

                return default;
            }

            return default;

            static bool ValidateClaimGroup(KeyValuePair<string, List<Claim>> claims) => claims switch
            {
                // The following JWT claims MUST be represented as unique strings.
                {
                    Key: Claims.AuthenticationContextReference or Claims.AuthorizedParty or Claims.Issuer or Claims.Nonce,
                    Value: List<Claim> values
                } => values.Count is 1 && values[0].ValueType is ClaimValueTypes.String,

                // The following JWT claims MUST be represented as unique strings or array of strings.
                {
                    Key: Claims.Audience or Claims.AuthenticationMethodReference,
                    Value: List<Claim> values
                } => values.Count switch
                {
                    1 => values[0].ValueType is ClaimValueTypes.String,
                    _ => values.All(value => value.ValueType is ClaimValueTypes.String)
                },

                // The following JWT claims MUST be represented as unique numeric dates.
                {
                    Key: Claims.AuthenticationTime or Claims.ExpiresAt or Claims.IssuedAt or Claims.NotBefore,
                    Value: List<Claim> values
                } => values.Count is 1 && values[0].ValueType is ClaimValueTypes.Integer    or ClaimValueTypes.Integer32 or
                                                                 ClaimValueTypes.Integer64  or ClaimValueTypes.Double    or
                                                                 ClaimValueTypes.UInteger32 or ClaimValueTypes.UInteger64,

                // Claims that are not in the well-known list can be of any type.
                _ => true
            };
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the audience returned in the frontchannel identity token, if applicable.
    /// </summary>
    public sealed class ValidateFrontchannelIdentityTokenAudience : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireFrontchannelIdentityTokenPrincipal>()
                .UseSingletonHandler<ValidateFrontchannelIdentityTokenAudience>()
                .SetOrder(ValidateFrontchannelIdentityTokenWellknownClaims.Descriptor.Order + 1_000)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.FrontchannelIdentityTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Note: while an identity token typically contains a single audience represented
            // as a JSON string, multiple values can be returned represented as a JSON array.
            //
            // In any case, the client identifier of the application MUST be included in the audiences.
            // See https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation for more information.
            var audiences = context.FrontchannelIdentityTokenPrincipal.GetClaims(Claims.Audience);
            if (!string.IsNullOrEmpty(context.Registration.ClientId) && !audiences.Contains(context.Registration.ClientId))
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.GetResourceString(SR.ID2123),
                    uri: SR.FormatID8000(SR.ID2123));

                return default;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the presenter returned in the frontchannel identity token, if applicable.
    /// </summary>
    public sealed class ValidateFrontchannelIdentityTokenPresenter : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireFrontchannelIdentityTokenPrincipal>()
                .UseSingletonHandler<ValidateFrontchannelIdentityTokenPresenter>()
                .SetOrder(ValidateFrontchannelIdentityTokenAudience.Descriptor.Order + 1_000)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.FrontchannelIdentityTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Note: the "azp" claim is optional, but if it's present, it MUST match the client identifier of the application.
            // See https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation for more information.
            var presenter = context.FrontchannelIdentityTokenPrincipal.GetClaim(Claims.AuthorizedParty);
            if (!string.IsNullOrEmpty(presenter) && !string.IsNullOrEmpty(context.Registration.ClientId) &&
                !string.Equals(presenter, context.Registration.ClientId, StringComparison.Ordinal))
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.GetResourceString(SR.ID2123),
                    uri: SR.FormatID8000(SR.ID2123));

                return default;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the nonce returned in the frontchannel identity token, if applicable.
    /// </summary>
    public sealed class ValidateFrontchannelIdentityTokenNonce : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireFrontchannelIdentityTokenPrincipal>()
                .AddFilter<RequireStateTokenPrincipal>()
                .UseSingletonHandler<ValidateFrontchannelIdentityTokenNonce>()
                .SetOrder(ValidateFrontchannelIdentityTokenPresenter.Descriptor.Order + 1_000)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Note: the OpenID Connect specification relies on nonces as a way to detect and
            // prevent replay attacks by binding the returned identity token(s) to a specific
            // random value sent by the client application as part of the authorization request.
            //
            // When Proof Key for Code Exchange is not supported or not available, nonces can
            // also be used to detect authorization code or identity token injection attacks.
            //
            // For more information, see https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes
            // and https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.5.3.2.
            //
            // While OpenIddict fully implements nonce support, its implementation slightly
            // differs from the implementation suggested by the OpenID Connect specification:
            //
            //   - Nonces are used internally as unique, per-authorization flow identifiers and
            //     are always considered required when using an interactive flow, independently
            //     of whether the authorization flow is an OAuth 2.0-only or OpenID Connect flow.
            //
            //   - Instead of being stored as separate cookies as suggested by the specification,
            //     nonces are used by the ASP.NET Core and OWIN hosts to build a unique value
            //     for the name of the correlation cookie used with state tokens to prevent CSRF,
            //     which reduces the number of cookies used by the OpenIddict client web hosts.
            //
            //   - Nonces are attached to the authorization requests AND stored in the state
            //     tokens so that the nonces and the state tokens form a 1 <-> 1 relationship,
            //     which forces sending the matching state to be able to validate identity tokens.
            //
            //   - Replay detection is implemented by invalidating state tokens the very first time
            //     they are presented at the redirection endpoint, even if the response indicates
            //     an errored authorization response (e.g if the authorization demand was denied).
            //     Since nonce validation depends on the value stored in the state token, marking
            //     state tokens as already redeemed is enough to prevent nonces from being replayed.

            Debug.Assert(context.FrontchannelIdentityTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));
            Debug.Assert(context.StateTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            switch ((
                FrontchannelIdentityTokenNonce: context.FrontchannelIdentityTokenPrincipal.GetClaim(Claims.Nonce),
                StateTokenNonce: context.StateTokenPrincipal.GetClaim(Claims.Private.Nonce)))
            {
                // If no nonce is present in the state token, bypass the validation logic.
                case { StateTokenNonce: null or { Length: not > 0 } }:
                    return default;

                // If the request was not an OpenID Connect request but an identity token
                // was returned nethertheless, don't require a nonce to be present.
                case { FrontchannelIdentityTokenNonce: null or { Length: not > 0 } }
                    when !context.StateTokenPrincipal.HasScope(Scopes.OpenId):
                    return default;

                // If the nonce is not present in the identity token, return an error.
                case { FrontchannelIdentityTokenNonce: null or { Length: not > 0 } }:
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2122(Claims.Nonce),
                        uri: SR.FormatID8000(SR.ID2122));

                    return default;

                // If the two nonces don't match, return an error.
                case { FrontchannelIdentityTokenNonce: string left, StateTokenNonce: string right } when
                    !OpenIddictHelpers.FixedTimeEquals(
                        left:  MemoryMarshal.AsBytes(left.AsSpan()), // The nonce in the identity token is already hashed.
                        right: MemoryMarshal.AsBytes(Base64UrlEncoder.Encode(
                            OpenIddictHelpers.ComputeSha256Hash(Encoding.UTF8.GetBytes(right))).AsSpan())):
                    context.Logger.LogWarning(SR.GetResourceString(SR.ID6210));

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2124(Claims.Nonce),
                        uri: SR.FormatID8000(SR.ID2124));

                    return default;

                default: return default;
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the digests of the frontchannel tokens, if applicable.
    /// </summary>
    public sealed class ValidateFrontchannelTokenDigests : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireFrontchannelIdentityTokenPrincipal>()
                .UseSingletonHandler<ValidateFrontchannelTokenDigests>()
                .SetOrder(ValidateFrontchannelIdentityTokenNonce.Descriptor.Order + 1_000)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.FrontchannelIdentityTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Resolve the signing algorithm used to sign the identity token. If the private
            // claim cannot be found, it means the "alg" header of the identity token was
            // malformed but the token was still considered valid. While highly unlikly,
            // an exception is thrown in this case to abort the authentication demand.
            var algorithm = context.FrontchannelIdentityTokenPrincipal.GetClaim(Claims.Private.SigningAlgorithm);
            if (string.IsNullOrEmpty(algorithm))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0293));
            }

            // If a frontchannel access token was returned in the authorization response,
            // ensure the at_hash claim matches the hash of the actual access token.
            if (!string.IsNullOrEmpty(context.FrontchannelAccessToken))
            {
                // Note: the at_hash MUST be present in identity tokens returned from the authorization endpoint.
                // See https://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken2 for more information.
                var hash = context.FrontchannelIdentityTokenPrincipal.GetClaim(Claims.AccessTokenHash);
                if (string.IsNullOrEmpty(hash))
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2122(Claims.AccessTokenHash),
                        uri: SR.FormatID8000(SR.ID2122));

                    return default;
                }

                if (!ValidateTokenHash(algorithm, context.FrontchannelAccessToken, hash))
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2124(Claims.AccessTokenHash),
                        uri: SR.FormatID8000(SR.ID2124));

                    return default;
                }
            }

            // If an authorization code was returned in the authorization response,
            // ensure the c_hash claim matches the hash of the actual authorization code.
            if (!string.IsNullOrEmpty(context.AuthorizationCode))
            {
                var hash = context.FrontchannelIdentityTokenPrincipal.GetClaim(Claims.CodeHash);
                if (string.IsNullOrEmpty(hash))
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2122(Claims.CodeHash),
                        uri: SR.FormatID8000(SR.ID2122));

                    return default;
                }

                if (!ValidateTokenHash(algorithm, context.AuthorizationCode, hash))
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2124(Claims.CodeHash),
                        uri: SR.FormatID8000(SR.ID2124));

                    return default;
                }
            }

            static ReadOnlySpan<char> ComputeTokenHash(string algorithm, string token)
            {
                // Resolve the hash algorithm associated with the signing algorithm and compute the token
                // hash. If an instance of the BCL hash algorithm cannot be resolved, throw an exception.
                var hash = algorithm switch
                {
                    SecurityAlgorithms.EcdsaSha256 or SecurityAlgorithms.HmacSha256 or
                    SecurityAlgorithms.RsaSha256   or SecurityAlgorithms.RsaSsaPssSha256
                        => OpenIddictHelpers.ComputeSha256Hash(Encoding.ASCII.GetBytes(token)),

                    SecurityAlgorithms.EcdsaSha384 or SecurityAlgorithms.HmacSha384 or
                    SecurityAlgorithms.RsaSha384   or SecurityAlgorithms.RsaSsaPssSha384
                        => OpenIddictHelpers.ComputeSha384Hash(Encoding.ASCII.GetBytes(token)),

                    SecurityAlgorithms.EcdsaSha512 or SecurityAlgorithms.HmacSha384 or
                    SecurityAlgorithms.RsaSha512   or SecurityAlgorithms.RsaSsaPssSha512
                        => OpenIddictHelpers.ComputeSha512Hash(Encoding.ASCII.GetBytes(token)),

                    _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0293))
                };

                // Warning: only the left-most half of the access token and authorization code digest is used.
                // See http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken for more information.
                return Base64UrlEncoder.Encode(hash, 0, hash.Length / 2).AsSpan();
            }

            static bool ValidateTokenHash(string algorithm, string token, string hash) =>
                OpenIddictHelpers.FixedTimeEquals(
                    left:  MemoryMarshal.AsBytes(hash.AsSpan()),
                    right: MemoryMarshal.AsBytes(ComputeTokenHash(algorithm, token)));

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the frontchannel access token resolved from the context.
    /// Note: this handler is typically not used for standard-compliant implementations as access tokens
    /// are supposed to be opaque to clients.
    /// </summary>
    public sealed class ValidateFrontchannelAccessToken : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly IOpenIddictClientDispatcher _dispatcher;

        public ValidateFrontchannelAccessToken(IOpenIddictClientDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireFrontchannelAccessTokenValidated>()
                .UseScopedHandler<ValidateFrontchannelAccessToken>()
                .SetOrder(ValidateFrontchannelTokenDigests.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.FrontchannelAccessTokenPrincipal is not null ||
                string.IsNullOrEmpty(context.FrontchannelAccessToken))
            {
                return;
            }

            var notification = new ValidateTokenContext(context.Transaction)
            {
                Token = context.FrontchannelAccessToken,
                ValidTokenTypes = { TokenTypeHints.AccessToken }
            };

            await _dispatcher.DispatchAsync(notification);

            if (notification.IsRequestHandled)
            {
                context.HandleRequest();
                return;
            }

            else if (notification.IsRequestSkipped)
            {
                context.SkipRequest();
                return;
            }

            else if (notification.IsRejected)
            {
                context.Reject(
                    error: notification.Error ?? Errors.InvalidRequest,
                    description: notification.ErrorDescription,
                    uri: notification.ErrorUri);
                return;
            }

            context.FrontchannelAccessTokenPrincipal = notification.Principal;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the authorization code resolved from the context.
    /// Note: this handler is typically not used for standard-compliant implementations as authorization codes
    /// are supposed to be opaque to clients.
    /// </summary>
    public sealed class ValidateAuthorizationCode : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly IOpenIddictClientDispatcher _dispatcher;

        public ValidateAuthorizationCode(IOpenIddictClientDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthorizationCodeValidated>()
                .UseScopedHandler<ValidateAuthorizationCode>()
                .SetOrder(ValidateFrontchannelAccessToken.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.AuthorizationCodePrincipal is not null ||
                string.IsNullOrEmpty(context.AuthorizationCode))
            {
                return;
            }

            var notification = new ValidateTokenContext(context.Transaction)
            {
                Token = context.AuthorizationCode,
                ValidTokenTypes = { TokenTypeHints.AuthorizationCode }
            };

            await _dispatcher.DispatchAsync(notification);

            if (notification.IsRequestHandled)
            {
                context.HandleRequest();
                return;
            }

            else if (notification.IsRequestSkipped)
            {
                context.SkipRequest();
                return;
            }

            else if (notification.IsRejected)
            {
                context.Reject(
                    error: notification.Error ?? Errors.InvalidRequest,
                    description: notification.ErrorDescription,
                    uri: notification.ErrorUri);
                return;
            }

            context.AuthorizationCodePrincipal = notification.Principal;
        }
    }

    /// <summary>
    /// Contains the logic responsible for resolving the address of the token endpoint.
    /// </summary>
    public sealed class ResolveTokenEndpoint : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<ResolveTokenEndpoint>()
                .SetOrder(ValidateAuthorizationCode.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // If the address of the token endpoint wasn't explicitly set
            // at this stage, try to extract it from the server configuration.
            context.TokenEndpoint ??= context.Configuration.TokenEndpoint switch
            {
                { IsAbsoluteUri: true } address when address.IsWellFormedOriginalString() => address,

                _ => null
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for determining whether a token request should be sent.
    /// </summary>
    public sealed class EvaluateTokenRequest : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<EvaluateTokenRequest>()
                .SetOrder(ResolveTokenEndpoint.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            context.SendTokenRequest = context.GrantType switch
            {
                // For the authorization code and implicit grants, always send a token request
                // if an authorization code was requested in the initial authorization request.
                GrantTypes.AuthorizationCode or GrantTypes.Implicit when HasResponseType(ResponseTypes.Code)
                    => true,

                // For client credentials, resource owner password credentials
                // and refresh token requests, always send a token request.
                GrantTypes.ClientCredentials or GrantTypes.Password or GrantTypes.RefreshToken => true,

                _ => false
            };

            return default;

            bool HasResponseType(string value) => context.ResponseType!.Split(Separators.Space).Contains(value);
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the parameters to the token request, if applicable.
    /// </summary>
    public sealed class AttachTokenRequestParameters : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireTokenRequest>()
                .UseSingletonHandler<AttachTokenRequestParameters>()
                .SetOrder(EvaluateTokenRequest.Descriptor.Order + 1_000)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Attach a new request instance if necessary.
            context.TokenRequest ??= new OpenIddictRequest();

            // Attach the selected grant type.
            context.TokenRequest.GrantType = context.GrantType switch
            {
                null => throw new InvalidOperationException(SR.GetResourceString(SR.ID0294)),

                // Note: in OpenID Connect, the hybrid flow doesn't have a dedicated grant_type and is
                // typically treated as a combination of both the implicit and authorization code grants.
                // If the implicit flow was selected during the challenge phase and an authorization code
                // was returned, this very likely means that the hybrid flow was used. In this case,
                // use grant_type=authorization_code when communicating with the remote token endpoint.
                GrantTypes.Implicit => GrantTypes.AuthorizationCode,

                // For other values, don't do any mapping.
                string type => type
            };

            if (context.Scopes.Count > 0)
            {
                // Note: the final OAuth 2.0 specification requires using a space as the scope separator.
                // Clients that need to deal with older or non-compliant implementations can register
                // a custom handler to use a different separator (typically, a comma).
                context.TokenRequest.Scope = string.Join(" ", context.Scopes);
            }

            // If the token request uses an authorization code grant, retrieve the code_verifier and
            // the redirect_uri from the state token principal and attach them to the request, if available.
            if (context.TokenRequest.GrantType is GrantTypes.AuthorizationCode)
            {
                Debug.Assert(!string.IsNullOrEmpty(context.AuthorizationCode), SR.GetResourceString(SR.ID4010));
                Debug.Assert(context.StateTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

                context.TokenRequest.Code = context.AuthorizationCode;
                context.TokenRequest.CodeVerifier = context.StateTokenPrincipal.GetClaim(Claims.Private.CodeVerifier);
                context.TokenRequest.RedirectUri = context.StateTokenPrincipal.GetClaim(Claims.Private.RedirectUri);
            }

            // If the token request uses a resource owner password credentials grant, attach the credentials to the request.
            else if (context.TokenRequest.GrantType is GrantTypes.Password)
            {
                Debug.Assert(!string.IsNullOrEmpty(context.Username), SR.GetResourceString(SR.ID4014));
                Debug.Assert(!string.IsNullOrEmpty(context.Password), SR.GetResourceString(SR.ID4015));

                context.TokenRequest.Username = context.Username;
                context.TokenRequest.Password = context.Password;
            }

            // If the token request uses a refresh token grant, attach the refresh token to the request.
            else if (context.TokenRequest.GrantType is GrantTypes.RefreshToken)
            {
                Debug.Assert(!string.IsNullOrEmpty(context.RefreshToken), SR.GetResourceString(SR.ID4010));

                context.TokenRequest.RefreshToken = context.RefreshToken;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for selecting the token types that should
    /// be generated and optionally sent as part of the authentication demand.
    /// </summary>
    public sealed class EvaluateGeneratedClientAssertionToken : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireTokenRequest>()
                .UseSingletonHandler<EvaluateGeneratedClientAssertionToken>()
                .SetOrder(AttachTokenRequestParameters.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            (context.GenerateClientAssertionToken,
             context.IncludeClientAssertionToken) = context.Registration.SigningCredentials.Count switch
            {
                // If a token request is going to be sent and if at least one signing key was
                // attached to the client registration, generate and include a client assertion
                // token if the configuration indicates the server supports private_key_jwt.
                > 0 when context.Configuration.TokenEndpointAuthMethodsSupported.Contains(
                    ClientAuthenticationMethods.PrivateKeyJwt) => (true, true),

                _ => (false, false)
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for preparing and attaching the claims principal
    /// used to generate the client assertion token, if one is going to be sent.
    /// </summary>
    public sealed class PrepareClientAssertionTokenPrincipal : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireClientAssertionTokenGenerated>()
                .UseSingletonHandler<PrepareClientAssertionTokenPrincipal>()
                .SetOrder(EvaluateGeneratedClientAssertionToken.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Issuer is { IsAbsoluteUri: true }, SR.GetResourceString(SR.ID4013));

            // Create a new principal that will be used to store the client assertion claims.
            var principal = new ClaimsPrincipal(new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType));
            principal.SetCreationDate(DateTimeOffset.UtcNow);

            var lifetime = context.Options.ClientAssertionTokenLifetime;
            if (lifetime.HasValue)
            {
                principal.SetExpirationDate(principal.GetCreationDate() + lifetime.Value);
            }

            // Use the address of the token endpoint as the audience, as recommended by the specifications.
            // Applications that need to use a different value can register a custom event handler.
            //
            // See https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
            // and https://datatracker.ietf.org/doc/html/rfc7523#section-3 for more information.
            if (!string.IsNullOrEmpty(context.TokenEndpoint?.OriginalString))
            {
                principal.SetAudiences(context.TokenEndpoint.OriginalString);
            }

            // If the token endpoint address is not available, use the issuer address as the audience.
            else
            {
                principal.SetAudiences(context.Issuer.OriginalString);
            }

            // Use the client_id as both the subject and the issuer, as required by the specifications.
            //
            // See https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
            // and https://datatracker.ietf.org/doc/html/rfc7523#section-3 for more information.
            principal.SetClaim(Claims.Private.Issuer, context.Registration.ClientId)
                     .SetClaim(Claims.Subject, context.Registration.ClientId);

            // Use a random GUID as the JWT unique identifier.
            principal.SetClaim(Claims.JwtId, Guid.NewGuid().ToString());

            context.ClientAssertionTokenPrincipal = principal;

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for generating a client
    /// assertion token for the current authentication operation.
    /// </summary>
    public sealed class GenerateClientAssertionToken : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly IOpenIddictClientDispatcher _dispatcher;

        public GenerateClientAssertionToken(IOpenIddictClientDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireClientAssertionTokenGenerated>()
                .UseScopedHandler<GenerateClientAssertionToken>()
                .SetOrder(PrepareClientAssertionTokenPrincipal.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var notification = new GenerateTokenContext(context.Transaction)
            {
                CreateTokenEntry = false,
                PersistTokenPayload = false,
                Principal = context.ClientAssertionTokenPrincipal!,
                TokenFormat = TokenFormats.Jwt,
                TokenType = TokenTypeHints.ClientAssertionToken
            };

            await _dispatcher.DispatchAsync(notification);

            if (notification.IsRequestHandled)
            {
                context.HandleRequest();
                return;
            }

            else if (notification.IsRequestSkipped)
            {
                context.SkipRequest();
                return;
            }

            else if (notification.IsRejected)
            {
                context.Reject(
                    error: notification.Error ?? Errors.InvalidRequest,
                    description: notification.ErrorDescription,
                    uri: notification.ErrorUri);
                return;
            }

            context.ClientAssertionToken = notification.Token;
            context.ClientAssertionTokenType = notification.TokenFormat switch
            {
                TokenFormats.Jwt   => ClientAssertionTypes.JwtBearer,
                TokenFormats.Saml2 => ClientAssertionTypes.Saml2Bearer,

                _ => null
            };
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the client credentials to the token request, if applicable.
    /// </summary>
    public sealed class AttachTokenRequestClientCredentials : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireTokenRequest>()
                .UseSingletonHandler<AttachTokenRequestClientCredentials>()
                .SetOrder(GenerateClientAssertionToken.Descriptor.Order + 1_000)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.TokenRequest is not null, SR.GetResourceString(SR.ID4008));

            // Always attach the client_id to the request, even if an assertion is sent.
            context.TokenRequest.ClientId = context.Registration.ClientId;

            // Note: client authentication methods are mutually exclusive so the client_assertion
            // and client_secret parameters MUST never be sent at the same time. For more information,
            // see https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.
            if (context.IncludeClientAssertionToken)
            {
                context.TokenRequest.ClientAssertion = context.ClientAssertionToken;
                context.TokenRequest.ClientAssertionType = context.ClientAssertionTokenType;
            }

            // Note: the client_secret may be null at this point (e.g for a public
            // client or if a custom authentication method is used by the application).
            else
            {
                context.TokenRequest.ClientSecret = context.Registration.ClientSecret;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for sending the token request, if applicable.
    /// </summary>
    public sealed class SendTokenRequest : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientService _service;

        public SendTokenRequest(OpenIddictClientService service)
            => _service = service ?? throw new ArgumentNullException(nameof(service));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireTokenRequest>()
                .UseSingletonHandler<SendTokenRequest>()
                .SetOrder(AttachTokenRequestClientCredentials.Descriptor.Order + 1_000)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.TokenRequest is not null, SR.GetResourceString(SR.ID4008));

            // Ensure the token endpoint is present and is a valid absolute URL.
            if (context.TokenEndpoint is not { IsAbsoluteUri: true } ||
               !context.TokenEndpoint.IsWellFormedOriginalString())
            {
                throw new InvalidOperationException(SR.FormatID0301(Metadata.TokenEndpoint));
            }

            try
            {
                context.TokenResponse = await _service.SendTokenRequestAsync(
                    context.Registration, context.TokenRequest, context.TokenEndpoint);
            }

            catch (ProtocolException exception)
            {
                context.Reject(
                    error: exception.Error,
                    description: exception.ErrorDescription,
                    uri: exception.ErrorUri);

                return;
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for determining the set of backchannel tokens to validate.
    /// </summary>
    public sealed class EvaluateValidatedBackchannelTokens : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireTokenRequest>()
                .UseSingletonHandler<EvaluateValidatedBackchannelTokens>()
                .SetOrder(SendTokenRequest.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            (context.ExtractBackchannelAccessToken,
             context.RequireBackchannelAccessToken,
             context.ValidateBackchannelAccessToken) = context.GrantType switch
             {
                 // An access token is always returned as part of token responses, independently of
                 // the negotiated response types or whether the server supports OpenID Connect or not.
                 // As such, a backchannel access token is always considered required if a code was received.
                 //
                 // Note: since access tokens are supposed to be opaque to the clients, they are never
                 // validated by default. Clients that need to deal with non-standard implementations
                 // can use custom handlers to validate access tokens that use a readable format (e.g JWT).
                 GrantTypes.AuthorizationCode or GrantTypes.Implicit when HasResponseType(ResponseTypes.Code)
                     => (true, true, false),

                 // An access token is always returned as part of client credentials,
                 // resource owner password credentials and refresh token responses.
                 GrantTypes.ClientCredentials or GrantTypes.Password or GrantTypes.RefreshToken
                    => (true, true, false),

                 _ => (false, false, false)
             };

            (context.ExtractBackchannelIdentityToken,
             context.RequireBackchannelIdentityToken,
             context.ValidateBackchannelIdentityToken) = context.GrantType switch
             {
                 // An identity token is always returned as part of token responses for the code and
                 // hybrid flows when the authorization server supports OpenID Connect. As such,
                 // a backchannel identity token is only considered required if the negotiated scopes
                 // include "openid", which indicates the initial request was an OpenID Connect request.
                 GrantTypes.AuthorizationCode or GrantTypes.Implicit when HasResponseType(ResponseTypes.Code) &&
                     context.StateTokenPrincipal!.HasScope(Scopes.OpenId) => (true, true, true),

                 // The client credentials and resource owner password credentials grants don't have
                 // an equivalent in OpenID Connect so an identity token is typically never returned
                 // when using them. However, certain server implementations (like OpenIddict)
                 // allow returning it as a non-standard artifact. As such, the identity token
                 // is not considered required but will always be validated using the same routine
                 // (except nonce validation) if it is present in the token response.
                 GrantTypes.ClientCredentials or GrantTypes.Password => (true, false, true),

                 // An identity token may or may not be returned as part of refresh token responses
                 // depending on the policy adopted by the remote authorization server. As such,
                 // the identity token is not considered required but will always be validated using
                 // the same routine (except nonce validation) if it is present in the token response.
                 GrantTypes.RefreshToken => (true, false, true),

                 _ => (false, false, false)
             };

            (context.ExtractRefreshToken,
             context.RequireRefreshToken,
             context.ValidateRefreshToken) = context.GrantType switch
             {
                 // A refresh token may be returned as part of token responses, depending on the
                 // policy enforced by the remote authorization server (e.g the "offline_access"
                 // scope may be used). Since the requirements will differ between authorization
                 // servers, a refresh token is never considered required by default.
                 //
                 // Note: since refresh tokens are supposed to be opaque to the clients, they are never
                 // validated by default. Clients that need to deal with non-standard implementations
                 // can use custom handlers to validate access tokens that use a readable format (e.g JWT).
                 GrantTypes.AuthorizationCode or GrantTypes.Implicit when HasResponseType(ResponseTypes.Code)
                    => (true, false, false),

                 // A refresh token may or may not be returned as part of client credentials,
                 // resource owner password credentials and refresh token responses depending
                 // on the policy adopted by the remote authorization server. As such, a
                 // refresh token is never considered required for such token responses.
                 GrantTypes.ClientCredentials or GrantTypes.Password or GrantTypes.RefreshToken
                    => (true, false, false),

                 _ => (false, false, false)
             };

            return default;

            bool HasResponseType(string value) => context.ResponseType!.Split(Separators.Space).Contains(value);
        }
    }

    /// <summary>
    /// Contains the logic responsible for resolving the backchannel tokens by sending a token request, if applicable.
    /// </summary>
    public sealed class ResolveValidatedBackchannelTokens : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireTokenRequest>()
                .UseSingletonHandler<ResolveValidatedBackchannelTokens>()
                .SetOrder(EvaluateValidatedBackchannelTokens.Descriptor.Order + 1_000)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.TokenResponse is not null, SR.GetResourceString(SR.ID4007));

            context.BackchannelAccessToken = context.ExtractBackchannelAccessToken switch
            {
                true  => context.TokenResponse.AccessToken,
                false => null
            };

            context.BackchannelIdentityToken = context.ExtractBackchannelIdentityToken switch
            {
                true  => context.TokenResponse.IdToken,
                false => null
            };

            context.RefreshToken = context.ExtractRefreshToken switch
            {
                true  => context.TokenResponse.RefreshToken,
                false => null
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for rejecting authentication demands that lack required tokens.
    /// </summary>
    public sealed class ValidateRequiredBackchannelTokens : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireTokenRequest>()
                .UseSingletonHandler<ValidateRequiredBackchannelTokens>()
                // Note: this handler is registered with a high gap to allow handlers
                // that do token extraction to be executed before this handler runs.
                .SetOrder(ResolveValidatedBackchannelTokens.Descriptor.Order + 50_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if ((context.RequireBackchannelAccessToken   && string.IsNullOrEmpty(context.BackchannelAccessToken))   ||
                (context.RequireBackchannelIdentityToken && string.IsNullOrEmpty(context.BackchannelIdentityToken)) ||
                (context.RequireRefreshToken             && string.IsNullOrEmpty(context.RefreshToken)))
            {
                context.Reject(
                    error: Errors.MissingToken,
                    description: SR.GetResourceString(SR.ID2000),
                    uri: SR.FormatID8000(SR.ID2000));

                return default;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the backchannel identity token resolved from the context.
    /// </summary>
    public sealed class ValidateBackchannelIdentityToken : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly IOpenIddictClientDispatcher _dispatcher;

        public ValidateBackchannelIdentityToken(IOpenIddictClientDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireBackchannelIdentityTokenValidated>()
                .UseScopedHandler<ValidateBackchannelIdentityToken>()
                .SetOrder(ValidateRequiredBackchannelTokens.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.BackchannelIdentityTokenPrincipal is not null ||
                string.IsNullOrEmpty(context.BackchannelIdentityToken))
            {
                return;
            }

            var notification = new ValidateTokenContext(context.Transaction)
            {
                Token = context.BackchannelIdentityToken,
                ValidTokenTypes = { TokenTypeHints.IdToken }
            };

            await _dispatcher.DispatchAsync(notification);

            if (notification.IsRequestHandled)
            {
                context.HandleRequest();
                return;
            }

            else if (notification.IsRequestSkipped)
            {
                context.SkipRequest();
                return;
            }

            else if (notification.IsRejected)
            {
                context.Reject(
                    error: notification.Error ?? Errors.InvalidRequest,
                    description: notification.ErrorDescription,
                    uri: notification.ErrorUri);
                return;
            }

            context.BackchannelIdentityTokenPrincipal = notification.Principal;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the well-known claims contained in the backchannel identity token.
    /// </summary>
    public sealed class ValidateBackchannelIdentityTokenWellknownClaims : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireBackchannelIdentityTokenPrincipal>()
                .UseSingletonHandler<ValidateBackchannelIdentityTokenWellknownClaims>()
                .SetOrder(ValidateBackchannelIdentityToken.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.BackchannelIdentityTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            foreach (var group in context.BackchannelIdentityTokenPrincipal.Claims
                .GroupBy(claim => claim.Type)
                .ToDictionary(group => group.Key, group => group.ToList()))
            {
                if (ValidateClaimGroup(group))
                {
                    continue;
                }

                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.FormatID2125(group.Key),
                    uri: SR.FormatID8000(SR.ID2125));

                return default;
            }

            // Identity tokens MUST contain an "iss" claim. For more information,
            // see https://openid.net/specs/openid-connect-core-1_0.html#IDToken.
            if (!context.BackchannelIdentityTokenPrincipal.HasClaim(Claims.Issuer))
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.FormatID2126(Claims.Issuer),
                    uri: SR.FormatID8000(SR.ID2126));

                return default;
            }

            // Identity tokens MUST contain a "sub" claim. For more information,
            // see https://openid.net/specs/openid-connect-core-1_0.html#IDToken.
            if (!context.BackchannelIdentityTokenPrincipal.HasClaim(Claims.Subject))
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.FormatID2126(Claims.Subject),
                    uri: SR.FormatID8000(SR.ID2126));

                return default;
            }

            // Identity tokens MUST contain at least one "aud" claim. For more information,
            // see https://openid.net/specs/openid-connect-core-1_0.html#IDToken.
            if (!context.BackchannelIdentityTokenPrincipal.HasClaim(Claims.Audience))
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.FormatID2126(Claims.Audience),
                    uri: SR.FormatID8000(SR.ID2126));

                return default;
            }

            // Identity tokens MUST contain contain a "exp" claim. For more information,
            // see https://openid.net/specs/openid-connect-core-1_0.html#IDToken.
            if (!context.BackchannelIdentityTokenPrincipal.HasClaim(Claims.ExpiresAt))
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.FormatID2126(Claims.ExpiresAt),
                    uri: SR.FormatID8000(SR.ID2126));

                return default;
            }

            // Identity tokens MUST contain contain an "iat" claim. For more information,
            // see https://openid.net/specs/openid-connect-core-1_0.html#IDToken.
            if (!context.BackchannelIdentityTokenPrincipal.HasClaim(Claims.IssuedAt))
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.FormatID2126(Claims.IssuedAt),
                    uri: SR.FormatID8000(SR.ID2126));

                return default;
            }

            return default;

            static bool ValidateClaimGroup(KeyValuePair<string, List<Claim>> claims) => claims switch
            {
                // The following JWT claims MUST be represented as unique strings.
                {
                    Key: Claims.AuthenticationContextReference or Claims.AuthorizedParty or Claims.Issuer or Claims.Nonce,
                    Value: List<Claim> values
                } => values.Count is 1 && values[0].ValueType is ClaimValueTypes.String,

                // The following JWT claims MUST be represented as unique strings or array of strings.
                {
                    Key: Claims.Audience or Claims.AuthenticationMethodReference,
                    Value: List<Claim> values
                } => values.Count switch
                {
                    1 => values[0].ValueType is ClaimValueTypes.String,
                    _ => values.All(value => value.ValueType is ClaimValueTypes.String)
                },

                // The following JWT claims MUST be represented as unique numeric dates.
                {
                    Key: Claims.AuthenticationTime or Claims.ExpiresAt or Claims.IssuedAt or Claims.NotBefore,
                    Value: List<Claim> values
                } => values.Count is 1 && values[0].ValueType is ClaimValueTypes.Integer    or ClaimValueTypes.Integer32 or
                                                                 ClaimValueTypes.Integer64  or ClaimValueTypes.Double    or
                                                                 ClaimValueTypes.UInteger32 or ClaimValueTypes.UInteger64,

                // Claims that are not in the well-known list can be of any type.
                _ => true
            };
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the audience returned in the backchannel identity token, if applicable.
    /// </summary>
    public sealed class ValidateBackchannelIdentityTokenAudience : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireBackchannelIdentityTokenPrincipal>()
                .UseSingletonHandler<ValidateBackchannelIdentityTokenAudience>()
                .SetOrder(ValidateBackchannelIdentityTokenWellknownClaims.Descriptor.Order + 1_000)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.BackchannelIdentityTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Note: while an identity token typically contains a single audience represented
            // as a JSON string, multiple values can be returned represented as a JSON array.
            //
            // In any case, the client identifier of the application MUST be included in the audiences.
            // See https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation for more information.
            var audiences = context.BackchannelIdentityTokenPrincipal.GetClaims(Claims.Audience);
            if (!string.IsNullOrEmpty(context.Registration.ClientId) && !audiences.Contains(context.Registration.ClientId))
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.GetResourceString(SR.ID2127),
                    uri: SR.FormatID8000(SR.ID2127));

                return default;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the presenter returned in the backchannel identity token, if applicable.
    /// </summary>
    public sealed class ValidateBackchannelIdentityTokenPresenter : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireBackchannelIdentityTokenPrincipal>()
                .UseSingletonHandler<ValidateBackchannelIdentityTokenPresenter>()
                .SetOrder(ValidateBackchannelIdentityTokenAudience.Descriptor.Order + 1_000)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.BackchannelIdentityTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Note: the "azp" claim is optional, but if it's present, it MUST match the client identifier of the application.
            // See https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation for more information.
            var presenter = context.BackchannelIdentityTokenPrincipal.GetClaim(Claims.AuthorizedParty);
            if (!string.IsNullOrEmpty(presenter) && !string.IsNullOrEmpty(context.Registration.ClientId) &&
                !string.Equals(presenter, context.Registration.ClientId, StringComparison.Ordinal))
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.GetResourceString(SR.ID2127),
                    uri: SR.FormatID8000(SR.ID2127));

                return default;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the nonce returned in the backchannel identity token, if applicable.
    /// </summary>
    public sealed class ValidateBackchannelIdentityTokenNonce : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireBackchannelIdentityTokenPrincipal>()
                .AddFilter<RequireStateTokenPrincipal>()
                .UseSingletonHandler<ValidateBackchannelIdentityTokenNonce>()
                .SetOrder(ValidateBackchannelIdentityTokenPresenter.Descriptor.Order + 1_000)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Note: the OpenID Connect specification relies on nonces as a way to detect and
            // prevent replay attacks by binding the returned identity token(s) to a specific
            // random value sent by the client application as part of the authorization request.
            //
            // When Proof Key for Code Exchange is not supported or not available, nonces can
            // also be used to detect authorization code or identity token injection attacks.
            //
            // For more information, see https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes
            // and https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.5.3.2.
            //
            // While OpenIddict fully implements nonce support, its implementation slightly
            // differs from the implementation suggested by the OpenID Connect specification:
            //
            //   - Nonces are used internally as unique, per-authorization flow identifiers and
            //     are always considered required when using an interactive flow, independently
            //     of whether the authorization flow is an OAuth 2.0-only or OpenID Connect flow.
            //
            //   - Instead of being stored as separate cookies as suggested by the specification,
            //     nonces are used by the ASP.NET Core and OWIN hosts to build a unique value
            //     for the name of the correlation cookie used with state tokens to prevent CSRF,
            //     which reduces the number of cookies used by the OpenIddict client web hosts.
            //
            //   - Nonces are attached to the authorization requests AND stored in the state
            //     tokens so that the nonces and the state tokens form a 1 <-> 1 relationship,
            //     which forces sending the matching state to be able to validate identity tokens.
            //
            //   - Replay detection is implemented by invalidating state tokens the very first time
            //     they are presented at the redirection endpoint, even if the response indicates
            //     an errored authorization response (e.g if the authorization demand was denied).
            //     Since nonce validation depends on the value stored in the state token, marking
            //     state tokens as already redeemed is enough to prevent nonces from being replayed.

            Debug.Assert(context.BackchannelIdentityTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));
            Debug.Assert(context.StateTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            switch ((
                BackchannelIdentityTokenNonce: context.BackchannelIdentityTokenPrincipal.GetClaim(Claims.Nonce),
                StateTokenNonce: context.StateTokenPrincipal.GetClaim(Claims.Private.Nonce)))
            {
                // If no nonce is present in the state token, bypass the validation logic.
                case { StateTokenNonce: null or { Length: not > 0 } }:
                    return default;

                // If the request was not an OpenID Connect request but an identity token
                // was returned nethertheless, don't require a nonce to be present.
                case { BackchannelIdentityTokenNonce: null or { Length: not > 0 } }
                    when !context.StateTokenPrincipal.HasScope(Scopes.OpenId):
                    return default;

                // If the nonce is not present in the identity token, return an error.
                case { BackchannelIdentityTokenNonce: null or { Length: not > 0 } }:
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2126(Claims.Nonce),
                        uri: SR.FormatID8000(SR.ID2126));

                    return default;

                // If the two nonces don't match, return an error.
                case { BackchannelIdentityTokenNonce: string left, StateTokenNonce: string right } when
                    !OpenIddictHelpers.FixedTimeEquals(
                        left:  MemoryMarshal.AsBytes(left.AsSpan()), // The nonce in the identity token is already hashed.
                        right: MemoryMarshal.AsBytes(Base64UrlEncoder.Encode(
                            OpenIddictHelpers.ComputeSha256Hash(Encoding.UTF8.GetBytes(right))).AsSpan())):
                    context.Logger.LogWarning(SR.GetResourceString(SR.ID6211));

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2128(Claims.Nonce),
                        uri: SR.FormatID8000(SR.ID2128));

                    return default;

                default: return default;
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the digests of the backchannel access token.
    /// </summary>
    public sealed class ValidateBackchannelTokenDigests : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireBackchannelIdentityTokenPrincipal>()
                .UseSingletonHandler<ValidateBackchannelTokenDigests>()
                .SetOrder(ValidateBackchannelIdentityTokenNonce.Descriptor.Order + 1_000)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.BackchannelIdentityTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));
            Debug.Assert(!string.IsNullOrEmpty(context.BackchannelAccessToken), SR.GetResourceString(SR.ID4010));

            // Resolve the signing algorithm used to sign the identity token. If the private
            // claim cannot be found, it means the "alg" header of the identity token was
            // malformed but the token was still considered valid. While highly unlikly,
            // an exception is thrown in this case to abort the authentication demand.
            var algorithm = context.BackchannelIdentityTokenPrincipal.GetClaim(Claims.Private.SigningAlgorithm);
            if (string.IsNullOrEmpty(algorithm))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0295));
            }

            // Note: the at_hash is optional for backchannel identity tokens returned from the token endpoint.
            // As such, the validation routine is only enforced if the at_hash claim is present in the token.
            // See https://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken2 for more information.
            var hash = context.BackchannelIdentityTokenPrincipal.GetClaim(Claims.AccessTokenHash);
            if (!string.IsNullOrEmpty(hash) && !ValidateTokenHash(algorithm, context.BackchannelAccessToken, hash))
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.FormatID2128(Claims.AccessTokenHash),
                    uri: SR.FormatID8000(SR.ID2128));

                return default;
            }

            // Note: unlike frontchannel identity tokens, backchannel identity tokens are not expected to include
            // an authorization code hash as no authorization code is normally returned from the token endpoint.

            static ReadOnlySpan<char> ComputeTokenHash(string algorithm, string token)
            {
                // Resolve the hash algorithm associated with the signing algorithm and compute the token
                // hash. If an instance of the BCL hash algorithm cannot be resolved, throw an exception.
                var hash = algorithm switch
                {
                    SecurityAlgorithms.EcdsaSha256 or SecurityAlgorithms.HmacSha256 or
                    SecurityAlgorithms.RsaSha256   or SecurityAlgorithms.RsaSsaPssSha256
                        => OpenIddictHelpers.ComputeSha256Hash(Encoding.ASCII.GetBytes(token)),

                    SecurityAlgorithms.EcdsaSha384 or SecurityAlgorithms.HmacSha384 or
                    SecurityAlgorithms.RsaSha384   or SecurityAlgorithms.RsaSsaPssSha384
                        => OpenIddictHelpers.ComputeSha384Hash(Encoding.ASCII.GetBytes(token)),

                    SecurityAlgorithms.EcdsaSha512 or SecurityAlgorithms.HmacSha384 or
                    SecurityAlgorithms.RsaSha512   or SecurityAlgorithms.RsaSsaPssSha512
                        => OpenIddictHelpers.ComputeSha512Hash(Encoding.ASCII.GetBytes(token)),

                    _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0295))
                };

                // Warning: only the left-most half of the access token and authorization code digest is used.
                // See http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken for more information.
                return Base64UrlEncoder.Encode(hash, 0, hash.Length / 2).AsSpan();
            }

            static bool ValidateTokenHash(string algorithm, string token, string hash) =>
                OpenIddictHelpers.FixedTimeEquals(
                    left:  MemoryMarshal.AsBytes(hash.AsSpan()),
                    right: MemoryMarshal.AsBytes(ComputeTokenHash(algorithm, token)));

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the backchannel access token resolved from the context.
    /// Note: this handler is typically not used for standard-compliant implementations as access tokens
    /// are supposed to be opaque to clients.
    /// </summary>
    public sealed class ValidateBackchannelAccessToken : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly IOpenIddictClientDispatcher _dispatcher;

        public ValidateBackchannelAccessToken(IOpenIddictClientDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireBackchannelAccessTokenValidated>()
                .UseScopedHandler<ValidateBackchannelAccessToken>()
                .SetOrder(ValidateBackchannelTokenDigests.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.BackchannelAccessTokenPrincipal is not null ||
                string.IsNullOrEmpty(context.BackchannelAccessToken))
            {
                return;
            }

            var notification = new ValidateTokenContext(context.Transaction)
            {
                Token = context.BackchannelAccessToken,
                ValidTokenTypes = { TokenTypeHints.AccessToken }
            };

            await _dispatcher.DispatchAsync(notification);

            if (notification.IsRequestHandled)
            {
                context.HandleRequest();
                return;
            }

            else if (notification.IsRequestSkipped)
            {
                context.SkipRequest();
                return;
            }

            else if (notification.IsRejected)
            {
                context.Reject(
                    error: notification.Error ?? Errors.InvalidRequest,
                    description: notification.ErrorDescription,
                    uri: notification.ErrorUri);
                return;
            }

            context.BackchannelAccessTokenPrincipal = notification.Principal;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the refresh token resolved from the context.
    /// Note: this handler is typically not used for standard-compliant implementations as refresh tokens
    /// are supposed to be opaque to clients.
    /// </summary>
    public sealed class ValidateRefreshToken : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly IOpenIddictClientDispatcher _dispatcher;

        public ValidateRefreshToken(IOpenIddictClientDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireRefreshTokenValidated>()
                .UseScopedHandler<ValidateRefreshToken>()
                .SetOrder(ValidateBackchannelAccessToken.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.RefreshTokenPrincipal is not null ||
                string.IsNullOrEmpty(context.RefreshToken))
            {
                return;
            }

            var notification = new ValidateTokenContext(context.Transaction)
            {
                Token = context.RefreshToken,
                ValidTokenTypes = { TokenTypeHints.RefreshToken }
            };

            await _dispatcher.DispatchAsync(notification);

            if (notification.IsRequestHandled)
            {
                context.HandleRequest();
                return;
            }

            else if (notification.IsRequestSkipped)
            {
                context.SkipRequest();
                return;
            }

            else if (notification.IsRejected)
            {
                context.Reject(
                    error: notification.Error ?? Errors.InvalidRequest,
                    description: notification.ErrorDescription,
                    uri: notification.ErrorUri);
                return;
            }

            context.RefreshTokenPrincipal = notification.Principal;
        }
    }

    /// <summary>
    /// Contains the logic responsible for resolving the address of the userinfo endpoint.
    /// </summary>
    public sealed class ResolveUserinfoEndpoint : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<ResolveUserinfoEndpoint>()
                .SetOrder(ValidateRefreshToken.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // If the address of the userinfo endpoint wasn't explicitly set
            // at this stage, try to extract it from the server configuration.
            context.UserinfoEndpoint ??= context.Configuration.UserinfoEndpoint switch
            {
                { IsAbsoluteUri: true } address when address.IsWellFormedOriginalString() => address,

                _ => null
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for determining whether a userinfo request should be sent.
    /// </summary>
    public sealed class EvaluateUserinfoRequest : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<EvaluateUserinfoRequest>()
                .SetOrder(ResolveUserinfoEndpoint.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            context.SendUserinfoRequest = context.GrantType switch
            {
                // Information about the authenticated user can be retrieved from the userinfo
                // endpoint when a frontchannel or backchannel access token is available.
                //
                // Note: the userinfo endpoint is an optional endpoint and may not be supported.
                GrantTypes.AuthorizationCode or GrantTypes.Implicit or
                GrantTypes.Password          or GrantTypes.RefreshToken
                    when context.UserinfoEndpoint is not null &&
                    (!string.IsNullOrEmpty(context.BackchannelAccessToken) ||
                     !string.IsNullOrEmpty(context.FrontchannelAccessToken)) => true,

                _ => false
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the parameters to the userinfo request, if applicable.
    /// </summary>
    public sealed class AttachUserinfoRequestParameters : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireUserinfoRequest>()
                .UseSingletonHandler<AttachUserinfoRequestParameters>()
                .SetOrder(EvaluateUserinfoRequest.Descriptor.Order + 1_000)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Attach a new request instance if necessary.
            context.UserinfoRequest ??= new OpenIddictRequest();

            // Note: the backchannel access token (retrieved from the token endpoint) is always preferred to
            // the frontchannel access token if available, as it may grant a greater access to user's resources.
            context.UserinfoRequest.AccessToken = context.BackchannelAccessToken ?? context.FrontchannelAccessToken ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0162));

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for sending the userinfo request, if applicable.
    /// </summary>
    public sealed class SendUserinfoRequest : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientService _service;

        public SendUserinfoRequest(OpenIddictClientService service)
            => _service = service ?? throw new ArgumentNullException(nameof(service));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireUserinfoRequest>()
                .UseSingletonHandler<SendUserinfoRequest>()
                .SetOrder(AttachUserinfoRequestParameters.Descriptor.Order + 1_000)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.UserinfoRequest is not null, SR.GetResourceString(SR.ID4008));

            // Ensure the userinfo endpoint is present and is a valid absolute URL.
            if (context.UserinfoEndpoint is not { IsAbsoluteUri: true } ||
               !context.UserinfoEndpoint.IsWellFormedOriginalString())
            {
                throw new InvalidOperationException(SR.FormatID0301(Metadata.UserinfoEndpoint));
            }

            // Note: userinfo responses can be of two types:
            //  - application/json responses containing a JSON object listing the user claims as-is.
            //  - application/jwt responses containing a signed/encrypted JSON Web Token containing the user claims.

            try
            {
                (context.UserinfoResponse, (context.UserinfoTokenPrincipal, context.UserinfoToken)) =
                    await _service.SendUserinfoRequestAsync(context.Registration, context.UserinfoRequest, context.UserinfoEndpoint);
            }

            catch (ProtocolException exception)
            {
                context.Reject(
                    error: exception.Error,
                    description: exception.ErrorDescription,
                    uri: exception.ErrorUri);

                return;
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for determining whether a userinfo token should be validated.
    /// </summary>
    public sealed class EvaluateValidatedUserinfoToken : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireUserinfoRequest>()
                .UseSingletonHandler<EvaluateValidatedUserinfoToken>()
                .SetOrder(SendUserinfoRequest.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // By default, OpenIddict doesn't require that userinfo be used but userinfo tokens
            // or responses will be extracted and validated when a userinfo request was sent.
            (context.ExtractUserinfoToken,
             context.RequireUserinfoToken,
             context.ValidateUserinfoToken) = (true, false, true);

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for rejecting authentication demands that lack the required userinfo token.
    /// </summary>
    public sealed class ValidateRequiredUserinfoToken : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<ValidateRequiredUserinfoToken>()
                // Note: this handler is registered with a high gap to allow handlers
                // that do token extraction to be executed before this handler runs.
                .SetOrder(EvaluateValidatedUserinfoToken.Descriptor.Order + 50_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.RequireUserinfoToken && string.IsNullOrEmpty(context.UserinfoToken))
            {
                context.Reject(
                    error: Errors.MissingToken,
                    description: SR.GetResourceString(SR.ID2000),
                    uri: SR.FormatID8000(SR.ID2000));

                return default;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the userinfo token resolved from the context.
    /// </summary>
    public sealed class ValidateUserinfoToken : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly IOpenIddictClientDispatcher _dispatcher;

        public ValidateUserinfoToken(IOpenIddictClientDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireUserinfoTokenExtracted>()
                .UseScopedHandler<ValidateUserinfoToken>()
                .SetOrder(ValidateRequiredUserinfoToken.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.UserinfoTokenPrincipal is not null ||
                string.IsNullOrEmpty(context.UserinfoToken))
            {
                return;
            }

            var notification = new ValidateTokenContext(context.Transaction)
            {
                Token = context.UserinfoToken,
                ValidTokenTypes = { TokenTypeHints.UserinfoToken }
            };

            await _dispatcher.DispatchAsync(notification);

            if (notification.IsRequestHandled)
            {
                context.HandleRequest();
                return;
            }

            else if (notification.IsRequestSkipped)
            {
                context.SkipRequest();
                return;
            }

            else if (notification.IsRejected)
            {
                context.Reject(
                    error: notification.Error ?? Errors.InvalidRequest,
                    description: notification.ErrorDescription,
                    uri: notification.ErrorUri);
                return;
            }

            context.UserinfoTokenPrincipal = notification.Principal;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the well-known claims contained in the userinfo token.
    /// </summary>
    public sealed class ValidateUserinfoTokenWellknownClaims : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireUserinfoTokenPrincipal>()
                .UseSingletonHandler<ValidateUserinfoTokenWellknownClaims>()
                .SetOrder(ValidateUserinfoToken.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.UserinfoTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // The OpenIddict client is expected to be used with standard OpenID Connect userinfo endpoints
            // but must also support non-standard implementations, that are common with OAuth 2.0-only servers.
            //
            // As such, protocol requirements are only enforced if the server supports OpenID Connect.
            if (context.Configuration.ScopesSupported.Contains(Scopes.OpenId))
            {
                foreach (var group in context.UserinfoTokenPrincipal.Claims
                    .GroupBy(claim => claim.Type)
                    .ToDictionary(group => group.Key, group => group.ToList()))
                {
                    if (ValidateClaimGroup(group))
                    {
                        continue;
                    }

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2131(group.Key),
                        uri: SR.FormatID8000(SR.ID2131));

                    return default;
                }
            }

            return default;

            static bool ValidateClaimGroup(KeyValuePair<string, List<Claim>> claims) => claims switch
            {
                // The following JWT claims MUST be represented as unique strings.
                {
                    Key: Claims.Subject,
                    Value: List<Claim> values
                } => values.Count is 1 && values[0].ValueType is ClaimValueTypes.String,

                // Claims that are not in the well-known list can be of any type.
                _ => true
            };
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the subject claim contained in the userinfo token.
    /// </summary>
    public sealed class ValidateUserinfoTokenSubject : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireUserinfoTokenPrincipal>()
                .UseSingletonHandler<ValidateUserinfoTokenSubject>()
                .SetOrder(ValidateUserinfoTokenWellknownClaims.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.UserinfoTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // The OpenIddict client is expected to be used with standard OpenID Connect userinfo endpoints
            // but must also support non-standard implementations, that are common with OAuth 2.0-only servers.
            //
            // As such, protocol requirements are only enforced if the server supports OpenID Connect.
            if (context.Configuration.ScopesSupported.Contains(Scopes.OpenId))
            {
                // Standard OpenID Connect userinfo responses/tokens MUST contain a "sub" claim. For more
                // information, see https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse.
                if (!context.UserinfoTokenPrincipal.HasClaim(Claims.Subject))
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2132(Claims.Subject),
                        uri: SR.FormatID8000(SR.ID2132));

                    return default;
                }

                // The "sub" claim returned as part of the userinfo response/token MUST exactly match the value
                // returned in the frontchannel identity token, if one was returned. For more information,
                // see https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse.
                if (context.FrontchannelIdentityTokenPrincipal is not null && !string.Equals(
                    context.FrontchannelIdentityTokenPrincipal.GetClaim(Claims.Subject),
                    context.UserinfoTokenPrincipal.GetClaim(Claims.Subject), StringComparison.Ordinal))
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2133(Claims.Subject),
                        uri: SR.FormatID8000(SR.ID2133));

                    return default;
                }

                // The "sub" claim returned as part of the userinfo response/token MUST exactly match the value
                // returned in the frontchannel identity token, if one was returned. For more information,
                // see https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse.
                if (context.BackchannelIdentityTokenPrincipal is not null && !string.Equals(
                    context.BackchannelIdentityTokenPrincipal.GetClaim(Claims.Subject),
                    context.UserinfoTokenPrincipal.GetClaim(Claims.Subject), StringComparison.Ordinal))
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2133(Claims.Subject),
                        uri: SR.FormatID8000(SR.ID2133));

                    return default;
                }
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for rejecting invalid challenge demands.
    /// </summary>
    public sealed class ValidateChallengeDemand : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .UseSingletonHandler<ValidateChallengeDemand>()
                .SetOrder(int.MinValue + 100_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.EndpointType is not OpenIddictClientEndpointType.Unknown)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0006));
            }

            // If an explicit grant type was specified, ensure it is supported by OpenIddict.
            if (!string.IsNullOrEmpty(context.GrantType) &&
                context.GrantType is not (GrantTypes.AuthorizationCode or GrantTypes.Implicit))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0296));
            }

            // If a provider name was specified, resolve the corresponding issuer.
            if (!string.IsNullOrEmpty(context.ProviderName))
            {
                var registration = context.Options.Registrations.Find(registration => string.Equals(
                    registration.ProviderName, context.ProviderName, StringComparison.Ordinal)) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0348));

                // If an explicit issuer was also attached, ensure the two values point to the same instance.
                if (context.Issuer is not null && context.Issuer != registration.Issuer)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0349));
                }

                context.Issuer = registration.Issuer;
            }

            // If no issuer was explicitly attached and a single client is registered, use it.
            // Otherwise, throw an exception to indicate that setting an explicit issuer
            // is required when multiple clients are registered.
            context.Issuer ??= context.Options.Registrations.Count switch
            {
                0 => throw new InvalidOperationException(SR.GetResourceString(SR.ID0304)),
                1 => context.Options.Registrations[0].Issuer,
                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0305))
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for resolving the client registration applicable to the challenge demand.
    /// </summary>
    public sealed class ResolveClientRegistrationFromChallengeContext : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .UseSingletonHandler<ResolveClientRegistrationFromChallengeContext>()
                .SetOrder(ValidateChallengeDemand.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Note: if the static registration cannot be found in the options, this may indicate
            // the client was removed after the authorization dance started and thus, can no longer
            // be used to authenticate users. In this case, throw an exception to abort the flow.
            context.Registration ??= context.Options.Registrations.Find(
                registration => registration.Issuer == context.Issuer) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0292));

            // Resolve and attach the server configuration to the context if none has been set already.
            context.Configuration ??= await context.Registration.ConfigurationManager.GetConfigurationAsync(default) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0140));

            // Ensure the issuer resolved from the configuration matches the expected value.
            if (context.Configuration.Issuer != context.Issuer)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0307));
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for resolving the best grant type
    /// supported by both the client and the authorization server.
    /// </summary>
    public sealed class AttachGrantType : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .UseSingletonHandler<AttachGrantType>()
                .SetOrder(ResolveClientRegistrationFromChallengeContext.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // If an explicit grant type was specified, don't overwrite it.
            if (!string.IsNullOrEmpty(context.GrantType))
            {
                return default;
            }

            // Note: if no grant type was explicitly returned as part of the server configuration,
            // the identity provider is assumed to at least support both the authorization code
            // and the implicit grants, as defined by the discovery specifications. In this case,
            // the authorization code grant is generally preferred as it offers the broadest
            // support and the best level of security thanks to additional features like
            // client authentication, code binding and access token injections mitigations.
            // See https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
            // and https://datatracker.ietf.org/doc/html/rfc8414#section-2 for more information.

            context.GrantType = (context.Registration.GrantTypes, context.Configuration.GrantTypesSupported) switch
            {
                // If neither the client nor the server specify a list of grant types,
                // use the authorization code grant, as it's always supported by default.
                ({ Count: 0 }, { Count: 0 }) => GrantTypes.AuthorizationCode,

                // If the client supports the code grant and the server doesn't specify a list of
                // grant types, use the authorization code grant, as it's always supported by default.
                ({ Count: > 0 } client, { Count: 0 }) when client.Contains(GrantTypes.AuthorizationCode)
                    => GrantTypes.AuthorizationCode,

                // If the client supports the code grant and the server doesn't specify a list of
                // grant types, use the authorization code grant, as it's always supported by default.
                ({ Count: 0 }, { Count: > 0 } server) when server.Contains(GrantTypes.AuthorizationCode)
                    => GrantTypes.AuthorizationCode,

                // If both the client and the server support the code grant, prefer it over the implicit grant.
                ({ Count: > 0 } client, { Count: > 0 } server) when
                    server.Contains(GrantTypes.AuthorizationCode) && client.Contains(GrantTypes.AuthorizationCode)
                    => GrantTypes.AuthorizationCode,

                // If the client supports the implicit grant and the server doesn't specify a list
                // of grant types, use the implicit code grant, as it's always supported by default.
                ({ Count: > 0 } client, { Count: 0 }) when client.Contains(GrantTypes.Implicit)
                    => GrantTypes.Implicit,

                // If the client supports the implicit grant and the server doesn't specify a list
                // of grant types, use the implicit code grant, as it's always supported by default.
                ({ Count: 0 }, { Count: > 0 } server) when server.Contains(GrantTypes.Implicit)
                    => GrantTypes.Implicit,

                // If both the client and the server support the implicit grant, use it as a last chance option.
                ({ Count: > 0 } client, { Count: > 0 } server) when
                    server.Contains(GrantTypes.Implicit) && client.Contains(GrantTypes.Implicit)
                    => GrantTypes.Implicit,

                // If no common grant type can be negotiated, abort the challenge operation.
                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0297))
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for selecting the token types that
    /// should be generated and optionally returned in the response.
    /// </summary>
    public sealed class EvaluateGeneratedChallengeTokens : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .UseSingletonHandler<EvaluateGeneratedChallengeTokens>()
                .SetOrder(AttachGrantType.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // In OpenIddict, per-authorization demand values are stored in an encrypted and signed token
            // called "state token", that allows flowing per-authorization demand data like the issuer
            // targeted by the authorization demand or secret values like the code verifier used to
            // derive the code challenge sent to the remote authorization server. While not strictly
            // required by the OAuth 2.0/2.1 and OpenID Connect specifications, the state parameter is
            // considered essential in OpenIddict and as such, is always included in challenge demands
            // that use the authorization code or implicit grants (which includes the hybrid flow).
            //
            // See https://datatracker.ietf.org/doc/html/draft-bradley-oauth-jwt-encoded-state-09
            // for more information.
            (context.GenerateStateToken, context.IncludeStateToken) = context.GrantType switch
            {
                GrantTypes.AuthorizationCode or GrantTypes.Implicit => (true, true),

                _ => (false, false)
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the user-defined properties to the authentication principal.
    /// </summary>
    public sealed class AttachChallengeHostProperties : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .UseSingletonHandler<AttachChallengeHostProperties>()
                .SetOrder(EvaluateGeneratedChallengeTokens.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            context.Principal.SetClaim(Claims.Private.HostProperties, context.Properties);

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the response type to the challenge request.
    /// </summary>
    public sealed class AttachResponseType : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireInteractiveGrantType>()
                .UseSingletonHandler<AttachResponseType>()
                .SetOrder(AttachChallengeHostProperties.Descriptor.Order + 1_000)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // If an explicit response type was specified, don't overwrite it.
            if (!string.IsNullOrEmpty(context.ResponseType))
            {
                return default;
            }

            context.ResponseType = (
                context.GrantType,
                context.Registration.ResponseTypes.Select(types => 
                    types.Split(Separators.Space).ToImmutableHashSet(StringComparer.Ordinal)).ToList(),
                context.Configuration.ResponseTypesSupported.Select(types =>
                    types.Split(Separators.Space).ToImmutableHashSet(StringComparer.Ordinal)).ToList()) switch
            {
                // Note: the OAuth 2.0 provider metadata and OpenID Connect discovery specifications define
                // the supported response types as a required property. Nevertheless, to ensure OpenIddict
                // is compatible with most identity providers, a missing or empty list is not treated as an
                // error. In this case, response_type=code (for the code grant) and response_type=id_token
                // (for the implicit grant) are assumed to be the most commonly supported values.
                //
                // Note: response_type=code is always tested first as it doesn't require using
                // response_mode=form_post or response_mode=fragment: fragment doesn't natively work with
                // server-side clients and form_post is impacted by the same-site cookies restrictions
                // that are now enforced by most browser vendors, which requires using SameSite=None for
                // response_mode=form_post to work correctly. While it doesn't have native protection
                // against mix-up attacks (due to the missing id_token in the authorization response),
                // the code flow remains the best compromise and thus always comes first in the list.
                //
                // Note: response types combinations containing "token" are always tested last as some
                // authorization servers - like OpenIddict - are known to block authorization requests
                // asking for an access token if Proof Key for Code Exchange is used in the same request.
                // Returning an identity token directly from the authorization endpoint also has privacy
                // concerns that code-based flows - that require a backchannel request - typically don't
                // have when the client application (confidential or public) is executed on a server.

                // If neither the client nor the server specify a list of response types,
                // use "response_type=code", as it's the most commonly supported type.
                (GrantTypes.AuthorizationCode, { Count: 0 }, { Count: 0 })
                    => ResponseTypes.Code,

                // If the client supports "response_type=code" and the server doesn't
                // specify a list of response types, use "response_type=code".
                (GrantTypes.AuthorizationCode, { Count: > 0 } client, { Count: 0 }) when
                    client.Any(static set => set.SetEquals(new[] { ResponseTypes.Code }))
                    => ResponseTypes.Code,

                // If the server supports "response_type=code" and the client doesn't
                // specify a list of response types, use "response_type=code".
                (GrantTypes.AuthorizationCode, { Count: 0 }, { Count: > 0 } server) when
                    server.Any(static set => set.SetEquals(new[] { ResponseTypes.Code }))
                    => ResponseTypes.Code,

                // If both the client and the server support "response_type=code", use it.
                (GrantTypes.AuthorizationCode, { Count: > 0 } client, { Count: > 0 } server) when
                    server.Any(static set => set.SetEquals(new[] { ResponseTypes.Code })) &&
                    client.Any(static set => set.SetEquals(new[] { ResponseTypes.Code }))
                    => ResponseTypes.Code,

                // If the client supports "response_type=code id_token" and the server doesn't
                // specify a list of response types, use "response_type=code id_token".
                (GrantTypes.AuthorizationCode or GrantTypes.Implicit, { Count: > 0 } client, { Count: 0 }) when
                    client.Any(static set => set.SetEquals(new[] { ResponseTypes.Code, ResponseTypes.IdToken }))
                    => ResponseTypes.Code + ' ' + ResponseTypes.IdToken,

                // If the server supports "response_type=code id_token" and the client doesn't
                // specify a list of response types, use "response_type=code id_token".
                (GrantTypes.AuthorizationCode or GrantTypes.Implicit, { Count: 0 }, { Count: > 0 } server) when
                    server.Any(static set => set.SetEquals(new[] { ResponseTypes.Code, ResponseTypes.IdToken }))
                    => ResponseTypes.Code + ' ' + ResponseTypes.IdToken,

                // If both the client and the server support "response_type=code id_token", use it.
                (GrantTypes.AuthorizationCode or GrantTypes.Implicit, { Count: > 0 } client, { Count: > 0 } server) when
                    server.Any(static set => set.SetEquals(new[] { ResponseTypes.Code, ResponseTypes.IdToken })) &&
                    client.Any(static set => set.SetEquals(new[] { ResponseTypes.Code, ResponseTypes.IdToken }))
                    => ResponseTypes.Code + ' ' + ResponseTypes.IdToken,

                // If neither the client nor the server specify a list of response types, use "response_type=id_token".
                (GrantTypes.Implicit, { Count: 0 }, { Count: 0 })
                    => ResponseTypes.IdToken,

                // If the client supports "response_type=id_token" and the server doesn't
                // specify a list of response types, use "response_type=id_token".
                (GrantTypes.Implicit, { Count: > 0 } client, { Count: 0 }) when
                    client.Any(static set => set.SetEquals(new[] { ResponseTypes.IdToken }))
                    => ResponseTypes.IdToken,

                // If the server supports "response_type=id_token" and the client doesn't
                // specify a list of response types, use "response_type=id_token".
                (GrantTypes.Implicit, { Count: 0 }, { Count: > 0 } server) when
                    server.Any(static set => set.SetEquals(new[] { ResponseTypes.IdToken }))
                    => ResponseTypes.IdToken,

                // If both the client and the server support "response_type=id_token", use it.
                (GrantTypes.Implicit, { Count: > 0 } client, { Count: > 0 } server) when
                    server.Any(static set => set.SetEquals(new[] { ResponseTypes.IdToken })) &&
                    client.Any(static set => set.SetEquals(new[] { ResponseTypes.IdToken }))
                    => ResponseTypes.IdToken,

                // If the client supports "response_type=code id_token token" and the server doesn't
                // specify a list of response types, use "response_type=code id_token token".
                (GrantTypes.AuthorizationCode or GrantTypes.Implicit, { Count: > 0 } client, { Count: 0 }) when
                    client.Any(static set => set.SetEquals(new[] { ResponseTypes.Code, ResponseTypes.IdToken, ResponseTypes.Token }))
                    => ResponseTypes.Code + ' ' + ResponseTypes.IdToken + ' ' + ResponseTypes.Token,

                // If the server supports "response_type=code id_token token" and the client doesn't
                // specify a list of response types, use "response_type=code id_token token".
                (GrantTypes.AuthorizationCode or GrantTypes.Implicit, { Count: 0 }, { Count: > 0 } server) when
                    server.Any(static set => set.SetEquals(new[] { ResponseTypes.Code, ResponseTypes.IdToken, ResponseTypes.Token }))
                    => ResponseTypes.Code + ' ' + ResponseTypes.IdToken + ' ' + ResponseTypes.Token,

                // If both the client and the server support "response_type=code id_token token", use it.
                (GrantTypes.AuthorizationCode or GrantTypes.Implicit, { Count: > 0 } client, { Count: > 0 } server) when
                    server.Any(static set => set.SetEquals(new[] { ResponseTypes.Code, ResponseTypes.IdToken, ResponseTypes.Token })) &&
                    client.Any(static set => set.SetEquals(new[] { ResponseTypes.Code, ResponseTypes.IdToken, ResponseTypes.Token }))
                    => ResponseTypes.Code + ' ' + ResponseTypes.IdToken + ' ' + ResponseTypes.Token,

                // If the client supports "response_type=code token" and the server doesn't
                // specify a list of response types, use "response_type=code token".
                (GrantTypes.AuthorizationCode or GrantTypes.Implicit, { Count: > 0 } client, { Count: 0 }) when
                    client.Any(static set => set.SetEquals(new[] { ResponseTypes.Code, ResponseTypes.Token }))
                    => ResponseTypes.Code + ' ' + ResponseTypes.Token,

                // If the server supports "response_type=code token" and the client doesn't
                // specify a list of response types, use "response_type=code token".
                (GrantTypes.AuthorizationCode or GrantTypes.Implicit, { Count: 0 }, { Count: > 0 } server) when
                    server.Any(static set => set.SetEquals(new[] { ResponseTypes.Code, ResponseTypes.Token }))
                    => ResponseTypes.Code + ' ' + ResponseTypes.Token,

                // If both the client and the server support "response_type=code token", use it.
                (GrantTypes.AuthorizationCode or GrantTypes.Implicit, { Count: > 0 } client, { Count: > 0 } server) when
                    server.Any(static set => set.SetEquals(new[] { ResponseTypes.Code, ResponseTypes.Token })) &&
                    client.Any(static set => set.SetEquals(new[] { ResponseTypes.Code, ResponseTypes.Token }))
                    => ResponseTypes.Code + ' ' + ResponseTypes.Token,

                // If the client supports "response_type=id_token token" and the server doesn't
                // specify a list of response types, use "response_type=id_token token".
                (GrantTypes.Implicit, { Count: > 0 } client, { Count: 0 }) when
                    client.Any(static set => set.SetEquals(new[] { ResponseTypes.IdToken, ResponseTypes.Token }))
                    => ResponseTypes.IdToken + ' ' + ResponseTypes.Token,

                // If the server supports "response_type=id_token token" and the client doesn't
                // specify a list of response types, use "response_type=id_token token".
                (GrantTypes.Implicit, { Count: 0 }, { Count: > 0 } server) when
                    server.Any(static set => set.SetEquals(new[] { ResponseTypes.IdToken, ResponseTypes.Token }))
                    => ResponseTypes.IdToken + ' ' + ResponseTypes.Token,

                // If both the client and the server support "response_type=id_token token", use it.
                (GrantTypes.Implicit, { Count: > 0 } client, { Count: > 0 } server) when
                    server.Any(static set => set.SetEquals(new[] { ResponseTypes.IdToken, ResponseTypes.Token })) &&
                    client.Any(static set => set.SetEquals(new[] { ResponseTypes.IdToken, ResponseTypes.Token }))
                    => ResponseTypes.IdToken + ' ' + ResponseTypes.Token,

                // Note: response_type=token is not considered secure enough as it allows malicious
                // actors to inject access tokens that were initially issued to a different client.
                // As such, while OpenIddict-based servers allow using response_type=token for backward
                // compatibility with legacy clients, OpenIddict-based clients are deliberately not
                // allowed to negotiate the unsafe and OAuth 2.0-only response_type=token flow.
                //
                // For more information, see https://datatracker.ietf.org/doc/html/rfc6749#section-10.16 and
                // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-19#section-2.1.2.

                // If no common response type can be negotiated, abort the challenge operation.
                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0298))
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the response mode to the challenge request.
    /// </summary>
    public sealed class AttachResponseMode : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireInteractiveGrantType>()
                .UseSingletonHandler<AttachResponseMode>()
                .SetOrder(AttachResponseType.Descriptor.Order + 1_000)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // If an explicit response type was specified, don't overwrite it.
            if (!string.IsNullOrEmpty(context.ResponseMode))
            {
                return default;
            }

            // Note: in most cases, the query response mode will be used as it offers the
            // best compatibility and, unlike the form_post response mode, is compatible
            // with SameSite=Lax cookies (as it uses GET requests for the callback stage).
            //
            // However, browser-based hosts like Blazor may typically want to use the fragment
            // response mode as it offers a better protection for SPA applications.
            // Unfortunately, server-side clients like ASP.NET Core applications cannot
            // natively use response_mode=fragment as URL fragments are never sent to servers.
            // 
            // As such, this handler will not choose response_mode=fragment by default and it is
            // expected that specialized hosts like Blazor implement custom event handlers to
            // opt for fragment by default, if it is supported by the authorization server.

            // Some specific response_type/response_mode combinations are not allowed (e.g response_mode=query
            // can never be used with a response type containing id_token or token, as required by the OAuth 2.0
            // multiple response types specification. To prevent invalid combinations from being sent to the
            // remote server, the response types are taken into account when selecting the best response mode.
            var types = context.ResponseType!.Split(Separators.Space).ToImmutableHashSet(StringComparer.Ordinal);

            context.ResponseMode = (context.Registration.ResponseModes, context.Configuration.ResponseModesSupported) switch
            {
                // If neither the client nor the server specify a list of response modes,
                // use "response_mode=form_post" if the response types contain a value
                // that prevents response_mode=query from being used (token/id_token).
                ({ Count: 0 }, { Count: 0 }) when
                    types.Contains(ResponseTypes.IdToken) || types.Contains(ResponseTypes.Token)
                    => ResponseModes.FormPost,

                // If the client support response_mode=form_post and the server doesn't
                // specify a list of response modes, use it if the response types contain
                // a value that prevents response_mode=query from being used (token/id_token).
                ({ Count: > 0 } client, { Count: 0 }) when client.Contains(ResponseModes.FormPost) &&
                    (types.Contains(ResponseTypes.IdToken) || types.Contains(ResponseTypes.Token))
                    => ResponseModes.FormPost,

                // If the server support response_mode=form_post and the server doesn't
                // specify a list of response modes, use it if the response types contain
                // a value that prevents response_mode=query from being used (token/id_token).
                ({ Count: 0 }, { Count: > 0 } server) when server.Contains(ResponseModes.FormPost) &&
                    (types.Contains(ResponseTypes.IdToken) || types.Contains(ResponseTypes.Token))
                    => ResponseModes.FormPost,

                // If both the client and the server support response_mode=form_post, use it if the response
                // types contain a value that prevents response_mode=query from being used (token/id_token).
                ({ Count: > 0 } client, { Count: > 0 } server) when
                    client.Contains(ResponseModes.FormPost) && server.Contains(ResponseModes.FormPost) &&
                    (types.Contains(ResponseTypes.IdToken) || types.Contains(ResponseTypes.Token))
                    => ResponseModes.FormPost,

                // If neither the client nor the server specify a list of response modes,
                // use "response_mode=query" as a fallback as it's universally supported:
                ({ Count: 0 }, { Count: 0 }) => ResponseModes.Query,

                // If the client support response_mode=query and the server
                // doesn't specify a list of response modes, use it:
                ({ Count: > 0 } client, { Count: 0 }) when client.Contains(ResponseModes.Query)
                    => ResponseModes.Query,

                // If the server support response_mode=query and the client
                // doesn't specify a list of response modes, use it:
                ({ Count: 0 }, { Count: > 0 } server) when server.Contains(ResponseModes.Query)
                    => ResponseModes.Query,

                // If both the client and the server support response_mode=query, use it:
                ({ Count: > 0 } client, { Count: > 0 } server) when
                    client.Contains(ResponseModes.Query) && server.Contains(ResponseModes.Query)
                    => ResponseModes.Query,

                // If no common response mode can be negotiated, abort the challenge operation.
                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0299))
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the client identifier to the challenge request.
    /// </summary>
    public sealed class AttachClientId : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireInteractiveGrantType>()
                .UseSingletonHandler<AttachClientId>()
                .SetOrder(AttachResponseMode.Descriptor.Order + 1_000)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            context.ClientId ??= context.Registration.ClientId;

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the redirect_uri to the challenge request.
    /// </summary>
    public sealed class AttachRedirectUri : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireInteractiveGrantType>()
                .UseSingletonHandler<AttachRedirectUri>()
                .SetOrder(AttachClientId.Descriptor.Order + 1_000)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Unlike OpenID Connect, OAuth 2.0 and 2.1 don't require specifying a redirect_uri.
            // To keep OpenIddict compatible with OAuth 2.0/2.1 deployments, the redirect_uri
            // is not required for OAuth 2.0 requests but an exception will be thrown later
            // if the request that is being prepared is an OpenID Connect request.
            context.RedirectUri ??= context.Registration.RedirectUri?.AbsoluteUri;

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the scopes to the challenge request.
    /// </summary>
    public sealed class AttachScopes : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireInteractiveGrantType>()
                .UseSingletonHandler<AttachScopes>()
                .SetOrder(AttachRedirectUri.Descriptor.Order + 1_000)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // If an explicit set of scopes was specified, don't overwrite it.
            if (context.Scopes.Count > 0)
            {
                return default;
            }

            // If the server configuration indicates the identity provider supports OpenID Connect,
            // always request the "openid" scope to identify the request as an OpenID Connect request.
            //
            // Developers who prefer sending OAuth 2.0/2.1 requests to an OpenID Connect server can
            // implement a custom event handler that manually replaces the set of requested scopes.
            if (context.Configuration.ScopesSupported.Contains(Scopes.OpenId))
            {
                context.Scopes.Add(Scopes.OpenId);
            }

            context.Scopes.UnionWith(context.Registration.Scopes);

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching a request forgery protection to the authorization request.
    /// </summary>
    public sealed class AttachRequestForgeryProtection : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireInteractiveGrantType>()
                .UseSingletonHandler<AttachRequestForgeryProtection>()
                .SetOrder(AttachScopes.Descriptor.Order + 1_000)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Generate a new crypto-secure random identifier that will
            // be used as the non-guessable part of the state token.
            context.RequestForgeryProtection = Base64UrlEncoder.Encode(
                OpenIddictHelpers.CreateRandomArray(size: 256));

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching a nonce to the authorization request.
    /// </summary>
    public sealed class AttachNonce : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireInteractiveGrantType>()
                .UseSingletonHandler<AttachNonce>()
                .SetOrder(AttachRequestForgeryProtection.Descriptor.Order + 1_000)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Generate a new crypto-secure random identifier that will be used as the nonce.
            //
            // Note: a nonce is always generated for interactive grants, independently of whether
            // the request is an OpenID Connect request or not, as it's used to identify each
            // authorization demand and is needed by the web hosts like ASP.NET Core and OWIN
            // to resolve the name of the correlation cookie used to prevent forged requests.
            //
            // If the request is an OpenID Connect request, the nonce will also be hashed and
            // attached to the authorization request so that the identity provider can bind
            // the issued identity tokens to the generated value, which helps detect token
            // replay (and authorization code injection attacks when PKCE is not available).
            context.Nonce = Base64UrlEncoder.Encode(OpenIddictHelpers.CreateRandomArray(size: 256));

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the code challenge parameters to the authorization request.
    /// </summary>
    public sealed class AttachCodeChallengeParameters : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireInteractiveGrantType>()
                .UseSingletonHandler<AttachCodeChallengeParameters>()
                .SetOrder(AttachNonce.Descriptor.Order + 1_000)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Don't attach a code challenge method if no authorization code is requested as some implementations
            // (like OpenIddict server) are known to eagerly block authorization requests that specify an invalid
            // code_challenge/code_challenge_method/response_type combination (e.g response_type=id_token).
            if (!context.ResponseType!.Split(Separators.Space).Contains(ResponseTypes.Code))
            {
                return default;
            }

            context.CodeChallengeMethod ??= (
                context.Registration.CodeChallengeMethods,
                context.Configuration.CodeChallengeMethodsSupported) switch
            {
                // If neither the client nor the server specify a list of code challenge methods, don't use PKCE.
                ({ Count: 0 }, { Count: 0 }) => null,

                // If the server doesn't specify a list of code challenge methods, don't use PKCE.
                ({ Count: > 0 }, { Count: 0 }) => null,

                // If the client doesn't specify a list of code challenge methods but the server support S256, use it.
                ({ Count: 0 }, { Count: > 0 } server) when server.Contains(CodeChallengeMethods.Sha256)
                    => CodeChallengeMethods.Sha256,

                // If both the client and the server support S256, use it.
                ({ Count: > 0 } client, { Count: > 0 } server) when
                    client.Contains(CodeChallengeMethods.Sha256) && server.Contains(CodeChallengeMethods.Sha256)
                    => CodeChallengeMethods.Sha256,

                // If the client doesn't specify a list of code challenge methods but the server support plain, use it.
                ({ Count: 0 }, { Count: > 0 } server) when server.Contains(CodeChallengeMethods.Plain)
                    => CodeChallengeMethods.Plain,

                // If both the client and the server support plain, use it.
                ({ Count: > 0 } client, { Count: > 0 } server) when
                    client.Contains(CodeChallengeMethods.Plain) && server.Contains(CodeChallengeMethods.Plain)
                    => CodeChallengeMethods.Plain,

                _ => null
            };

            // Note: while enforced by OAuth 2.1 under certain circumstances, PKCE is not a required feature for
            // OAuth 2.0 and OpenID Connect (where features like nonce validation can serve similar purposes).
            // As such, no error is returned at this stage is no common code challenge method could be inferred.
            if (string.IsNullOrEmpty(context.CodeChallengeMethod))
            {
                return default;
            }

            // Generate a new crypto-secure random identifier that will be used as the code challenge.
            context.CodeVerifier = Base64UrlEncoder.Encode(OpenIddictHelpers.CreateRandomArray(size: 256));

            context.CodeChallenge = context.CodeChallengeMethod switch
            {
                // For "plain", use the code verifier as the code challenge.
                CodeChallengeMethods.Plain => context.CodeVerifier,

                // For S256, compute the SHA-256 hash of the code verifier and use it as the code challenge.
                //
                // Note: ASCII is deliberately used here, as it's the encoding required by the specification.
                // For more information, see https://datatracker.ietf.org/doc/html/rfc7636#section-4.2.
                CodeChallengeMethods.Sha256 => Base64UrlEncoder.Encode(
                    OpenIddictHelpers.ComputeSha256Hash(Encoding.ASCII.GetBytes(context.CodeVerifier))),

                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0045))
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for preparing and attaching the claims principal
    /// used to generate the state token, if one is going to be returned.
    /// </summary>
    public sealed class PrepareStateTokenPrincipal : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireLoginStateTokenGenerated>()
                .UseSingletonHandler<PrepareStateTokenPrincipal>()
                .SetOrder(AttachCodeChallengeParameters.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Issuer is { IsAbsoluteUri: true }, SR.GetResourceString(SR.ID4013));
            Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Create a new principal containing only the filtered claims.
            // Actors identities are also filtered (delegation scenarios).
            var principal = context.Principal.Clone(claim =>
            {
                // Never include the public or internal token identifiers to ensure the identifiers
                // that are automatically inherited from the parent token are not reused for the new token.
                if (string.Equals(claim.Type, Claims.JwtId, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.Private.TokenId, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // Never include the creation and expiration dates that are automatically
                // inherited from the parent token are not reused for the new token.
                if (string.Equals(claim.Type, Claims.ExpiresAt, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.IssuedAt, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.NotBefore, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // Other claims are always included in the state token, even private claims.
                return true;
            });

            principal.SetCreationDate(DateTimeOffset.UtcNow);

            var lifetime = context.Principal.GetStateTokenLifetime() ?? context.Options.StateTokenLifetime;
            if (lifetime.HasValue)
            {
                principal.SetExpirationDate(principal.GetCreationDate() + lifetime.Value);
            }

            // Store the identity of the authorization server in the state token principal to allow
            // resolving it when handling the authorization callback. Note: additional security checks
            // are generally required to ensure the state token was not replaced with a state token
            // meant to be used with a different authorization server (e.g using the "iss" parameter).
            //
            // See https://datatracker.ietf.org/doc/html/draft-bradley-oauth-jwt-encoded-state-09
            // for more information about this special claim.
            principal.SetClaim(Claims.AuthorizationServer, context.Issuer.AbsoluteUri);

            // Store the request forgery protection in the state token so it can be later used to
            // ensure the authorization response sent to the redirection endpoint is not forged.
            principal.SetClaim(Claims.RequestForgeryProtection, context.RequestForgeryProtection);

            // Store the optional return URL in the state token.
            principal.SetClaim(Claims.TargetLinkUri, context.TargetLinkUri);

            // Attach the negotiated grant type to the state token.
            principal.SetClaim(Claims.Private.GrantType, context.GrantType);

            // Attach the response type to the state token to allow the redirection endpoint
            // to ensure the returned set of tokens matches the specified response type and
            // help mitigate downgrade attacks (e.g authorization code flow -> implicit flow).
            principal.SetClaim(Claims.Private.ResponseType, context.ResponseType);

            // Store the type of endpoint allowed to receive the generated state token.
            principal.SetClaim(Claims.Private.EndpointType, Enum.GetName(
                typeof(OpenIddictClientEndpointType),
                OpenIddictClientEndpointType.Redirection)!.ToLowerInvariant());

            // Store the optional redirect_uri to allow sending it as part of the token request.
            principal.SetClaim(Claims.Private.RedirectUri, context.RedirectUri);

            // Store the code verifier in the state token so it can be sent to
            // the remote authorization server when preparing the token request.
            //
            // Note: the code challenge and challenge methods are not persisted as they are
            // not needed to send a valid token request (that only requires the code verifier).
            principal.SetClaim(Claims.Private.CodeVerifier, context.CodeVerifier);

            // Store the nonce in the state token so it can be later used to check whether
            // the nonce extracted from the identity token matches the generated value.
            //
            // Note: the nonce is also used by the ASP.NET Core and OWIN hosts as a way
            // to uniquely identify the name of the correlation cookie used for antiforgery.
            principal.SetClaim(Claims.Private.Nonce, context.Nonce);

            // Store the requested scopes in the state token.
            principal.SetClaims(Claims.Private.Scope, context.Scopes.ToImmutableArray());

            context.StateTokenPrincipal = principal;

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for generating a state token for the current challenge operation.
    /// </summary>
    public sealed class GenerateStateToken : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        private readonly IOpenIddictClientDispatcher _dispatcher;

        public GenerateStateToken(IOpenIddictClientDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireLoginStateTokenGenerated>()
                .UseScopedHandler<GenerateStateToken>()
                .SetOrder(100_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var notification = new GenerateTokenContext(context.Transaction)
            {
                CreateTokenEntry = !context.Options.DisableTokenStorage,
                PersistTokenPayload = !context.Options.DisableTokenStorage,
                Principal = context.StateTokenPrincipal!,
                TokenFormat = TokenFormats.Jwt,
                TokenType = TokenTypeHints.StateToken
            };

            await _dispatcher.DispatchAsync(notification);

            if (notification.IsRequestHandled)
            {
                context.HandleRequest();
                return;
            }

            else if (notification.IsRequestSkipped)
            {
                context.SkipRequest();
                return;
            }

            else if (notification.IsRejected)
            {
                context.Reject(
                    error: notification.Error ?? Errors.InvalidRequest,
                    description: notification.ErrorDescription,
                    uri: notification.ErrorUri);
                return;
            }

            context.StateToken = notification.Token;
        }
    }

    /// <summary>
    /// Contains the logic responsible for ensuring the redirect_uri parameter is present
    /// if the "openid" scope is requested (indicating the request is an OpenID Connect request).
    /// </summary>
    public sealed class ValidateRedirectUriParameter : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireInteractiveGrantType>()
                .UseSingletonHandler<ValidateRedirectUriParameter>()
                .SetOrder(GenerateStateToken.Descriptor.Order + 1_000)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // While OAuth 2.0/2.1 allows sending an authorization request without a redirect_uri,
            // doing so is illegal in OpenID Connect and such requests will always be rejected.
            // To make that requirement explicit, an exception is proactively thrown here.
            if (string.IsNullOrEmpty(context.RedirectUri) && context.Scopes.Contains(Scopes.OpenId))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0300));
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the appropriate parameters to the challenge response.
    /// </summary>
    public sealed class AttachChallengeParameters : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .UseSingletonHandler<AttachChallengeParameters>()
                .SetOrder(ValidateRedirectUriParameter.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Note: while the exact order of the parameters has typically no effect on how requests
            // are handled by an authorization server, client_id and redirect_uri are deliberately
            // set first so that they appear early in the URL (when GET requests are used), making
            // mistyped values easier to spot when an error is returned by the identity provider.
            context.Request.ClientId = context.ClientId;
            context.Request.RedirectUri = context.RedirectUri;
            context.Request.ResponseType = context.ResponseType;
            context.Request.ResponseMode = context.ResponseMode;

            if (context.Scopes.Count > 0)
            {
                // Note: the final OAuth 2.0 specification requires using a space as the scope separator.
                // Clients that need to deal with older or non-compliant implementations can register
                // a custom handler to use a different separator (typically, a comma).
                context.Request.Scope = string.Join(" ", context.Scopes);
            }

            // If the request is an OpenID Connect request, attach the nonce as a parameter.
            //
            // Note: the nonce is always hashed before being sent, as recommended the specification.
            // See https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes for more information.
            if (context.Scopes.Contains(Scopes.OpenId) && !string.IsNullOrEmpty(context.Nonce))
            {
                context.Request.Nonce = Base64UrlEncoder.Encode(
                    OpenIddictHelpers.ComputeSha256Hash(Encoding.UTF8.GetBytes(context.Nonce)));
            }

            context.Request.CodeChallenge = context.CodeChallenge;
            context.Request.CodeChallengeMethod = context.CodeChallengeMethod;

            context.Request.IdTokenHint = context.IdentityTokenHint;
            context.Request.LoginHint = context.LoginHint;

            if (context.IncludeStateToken)
            {
                context.Request.State = context.StateToken;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the parameters
    /// populated from user-defined handlers to the challenge response.
    /// </summary>
    public sealed class AttachCustomChallengeParameters : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .UseSingletonHandler<AttachCustomChallengeParameters>()
                .SetOrder(AttachChallengeParameters.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.Parameters.Count > 0)
            {
                foreach (var parameter in context.Parameters)
                {
                    context.Request.SetParameter(parameter.Key, parameter.Value);
                }
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for ensuring that the sign-out demand
    /// is compatible with the type of the endpoint that handled the request.
    /// </summary>
    public sealed class ValidateSignOutDemand : IOpenIddictClientHandler<ProcessSignOutContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessSignOutContext>()
                .UseSingletonHandler<ValidateSignOutDemand>()
                .SetOrder(int.MinValue + 100_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignOutContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.EndpointType is not OpenIddictClientEndpointType.Unknown)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0024));
            }

            // If a provider name was specified, resolve the corresponding issuer.
            if (!string.IsNullOrEmpty(context.ProviderName))
            {
                var registration = context.Options.Registrations.Find(registration => string.Equals(
                    registration.ProviderName, context.ProviderName, StringComparison.Ordinal)) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0348));

                // If an explicit issuer was also attached, ensure the two values point to the same instance.
                if (context.Issuer is not null && context.Issuer != registration.Issuer)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0349));
                }

                context.Issuer = registration.Issuer;
            }

            // If no issuer was explicitly attached and a single client is registered, use it.
            // Otherwise, throw an exception to indicate that setting an explicit issuer
            // is required when multiple clients are registered.
            context.Issuer ??= context.Options.Registrations.Count switch
            {
                0 => throw new InvalidOperationException(SR.GetResourceString(SR.ID0304)),
                1 => context.Options.Registrations[0].Issuer,
                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0341))
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for resolving the client registration applicable to the sign-out demand.
    /// </summary>
    public sealed class ResolveClientRegistrationFromSignOutContext : IOpenIddictClientHandler<ProcessSignOutContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessSignOutContext>()
                .UseSingletonHandler<ResolveClientRegistrationFromSignOutContext>()
                .SetOrder(ValidateSignOutDemand.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessSignOutContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Note: if the static registration cannot be found in the options, this may indicate
            // the client was removed after the authorization dance started and thus, can no longer
            // be used to authenticate users. In this case, throw an exception to abort the flow.
            context.Registration ??= context.Options.Registrations.Find(
                registration => registration.Issuer == context.Issuer) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0292));

            // Resolve and attach the server configuration to the context if none has been set already.
            context.Configuration ??= await context.Registration.ConfigurationManager.GetConfigurationAsync(default) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0140));

            // Ensure the issuer resolved from the configuration matches the expected value.
            if (context.Configuration.Issuer != context.Issuer)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0307));
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the client identifier to the sign-out request.
    /// </summary>
    public sealed class AttachOptionalClientId : IOpenIddictClientHandler<ProcessSignOutContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessSignOutContext>()
                .UseSingletonHandler<AttachOptionalClientId>()
                .SetOrder(ResolveClientRegistrationFromSignOutContext.Descriptor.Order + 1_000)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignOutContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Note: the client_id parameter is optional.
            context.ClientId ??= context.Registration.ClientId;

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the post_logout_redirect_uri to the sign-out request.
    /// </summary>
    public sealed class AttachPostLogoutRedirectUri : IOpenIddictClientHandler<ProcessSignOutContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessSignOutContext>()
                .UseSingletonHandler<AttachPostLogoutRedirectUri>()
                .SetOrder(AttachOptionalClientId.Descriptor.Order + 1_000)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignOutContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Note: the post_logout_redirect_uri parameter is optional.
            context.PostLogoutRedirectUri ??= context.Registration.PostLogoutRedirectUri?.AbsoluteUri;

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for selecting the token types that
    /// should be generated and optionally returned in the response.
    /// </summary>
    public sealed class EvaluateGeneratedLogoutTokens : IOpenIddictClientHandler<ProcessSignOutContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessSignOutContext>()
                .UseSingletonHandler<EvaluateGeneratedLogoutTokens>()
                .SetOrder(AttachPostLogoutRedirectUri.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignOutContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            (context.GenerateStateToken, context.IncludeStateToken) = (true, true);

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the user-defined properties to the authentication principal.
    /// </summary>
    public sealed class AttachSignOutHostProperties : IOpenIddictClientHandler<ProcessSignOutContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessSignOutContext>()
                .UseSingletonHandler<AttachSignOutHostProperties>()
                .SetOrder(EvaluateGeneratedLogoutTokens.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignOutContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            context.Principal.SetClaim(Claims.Private.HostProperties, context.Properties);

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching a request forgery protection to the logout request.
    /// </summary>
    public sealed class AttachLogoutRequestForgeryProtection : IOpenIddictClientHandler<ProcessSignOutContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessSignOutContext>()
                .UseSingletonHandler<AttachLogoutRequestForgeryProtection>()
                .SetOrder(AttachSignOutHostProperties.Descriptor.Order + 1_000)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignOutContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Generate a new crypto-secure random identifier that will
            // be used as the non-guessable part of the state token.
            context.RequestForgeryProtection = Base64UrlEncoder.Encode(
                OpenIddictHelpers.CreateRandomArray(size: 256));

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching a nonce to the logout request.
    /// </summary>
    public sealed class AttachLogoutNonce : IOpenIddictClientHandler<ProcessSignOutContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessSignOutContext>()
                .UseSingletonHandler<AttachLogoutNonce>()
                .SetOrder(AttachLogoutRequestForgeryProtection.Descriptor.Order + 1_000)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignOutContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Generate a new crypto-secure random identifier that will be used as the nonce.
            context.Nonce = Base64UrlEncoder.Encode(OpenIddictHelpers.CreateRandomArray(size: 256));

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for preparing and attaching the claims principal
    /// used to generate the logout state token, if one is going to be returned.
    /// </summary>
    public sealed class PrepareLogoutStateTokenPrincipal : IOpenIddictClientHandler<ProcessSignOutContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessSignOutContext>()
                .AddFilter<RequireLogoutStateTokenGenerated>()
                .UseSingletonHandler<PrepareLogoutStateTokenPrincipal>()
                .SetOrder(AttachLogoutNonce.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignOutContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Issuer is { IsAbsoluteUri: true }, SR.GetResourceString(SR.ID4013));
            Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Create a new principal containing only the filtered claims.
            // Actors identities are also filtered (delegation scenarios).
            var principal = context.Principal.Clone(claim =>
            {
                // Never include the public or internal token identifiers to ensure the identifiers
                // that are automatically inherited from the parent token are not reused for the new token.
                if (string.Equals(claim.Type, Claims.JwtId, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.Private.TokenId, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // Never include the creation and expiration dates that are automatically
                // inherited from the parent token are not reused for the new token.
                if (string.Equals(claim.Type, Claims.ExpiresAt, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.IssuedAt, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.NotBefore, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // Other claims are always included in the state token, even private claims.
                return true;
            });

            principal.SetCreationDate(DateTimeOffset.UtcNow);

            var lifetime = context.Principal.GetStateTokenLifetime() ?? context.Options.StateTokenLifetime;
            if (lifetime.HasValue)
            {
                principal.SetExpirationDate(principal.GetCreationDate() + lifetime.Value);
            }

            // Store the identity of the authorization server in the state token
            // principal to allow resolving it when handling the post-logout callback.
            //
            // See https://datatracker.ietf.org/doc/html/draft-bradley-oauth-jwt-encoded-state-09
            // for more information about this special claim.
            principal.SetClaim(Claims.AuthorizationServer, context.Issuer.AbsoluteUri);

            // Store the request forgery protection in the state token so it can be later used to
            // ensure the logout response sent to the post-logout redirection endpoint is not forged.
            principal.SetClaim(Claims.RequestForgeryProtection, context.RequestForgeryProtection);

            // Store the optional return URL in the state token.
            principal.SetClaim(Claims.TargetLinkUri, context.TargetLinkUri);

            // Store the type of endpoint allowed to receive the generated state token.
            principal.SetClaim(Claims.Private.EndpointType, Enum.GetName(
                typeof(OpenIddictClientEndpointType),
                OpenIddictClientEndpointType.PostLogoutRedirection)!.ToLowerInvariant());

            // Store the post_logout_redirect_uri to allow comparing to the actual redirection URL.
            principal.SetClaim(Claims.Private.PostLogoutRedirectUri, context.PostLogoutRedirectUri);

            // Store the nonce in the state token.
            //
            // Note: the nonce is also used by the ASP.NET Core and OWIN hosts as a way
            // to uniquely identify the name of the correlation cookie used for antiforgery.
            principal.SetClaim(Claims.Private.Nonce, context.Nonce);

            context.StateTokenPrincipal = principal;

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for generating a logout state token for the current sign-out operation.
    /// </summary>
    public sealed class GenerateLogoutStateToken : IOpenIddictClientHandler<ProcessSignOutContext>
    {
        private readonly IOpenIddictClientDispatcher _dispatcher;

        public GenerateLogoutStateToken(IOpenIddictClientDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessSignOutContext>()
                .AddFilter<RequireLogoutStateTokenGenerated>()
                .UseScopedHandler<GenerateLogoutStateToken>()
                .SetOrder(100_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessSignOutContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var notification = new GenerateTokenContext(context.Transaction)
            {
                CreateTokenEntry = !context.Options.DisableTokenStorage,
                PersistTokenPayload = !context.Options.DisableTokenStorage,
                Principal = context.StateTokenPrincipal!,
                TokenFormat = TokenFormats.Jwt,
                TokenType = TokenTypeHints.StateToken
            };

            await _dispatcher.DispatchAsync(notification);

            if (notification.IsRequestHandled)
            {
                context.HandleRequest();
                return;
            }

            else if (notification.IsRequestSkipped)
            {
                context.SkipRequest();
                return;
            }

            else if (notification.IsRejected)
            {
                context.Reject(
                    error: notification.Error ?? Errors.InvalidRequest,
                    description: notification.ErrorDescription,
                    uri: notification.ErrorUri);
                return;
            }

            context.StateToken = notification.Token;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the appropriate parameters to the sign-out response.
    /// </summary>
    public sealed class AttachSignOutParameters : IOpenIddictClientHandler<ProcessSignOutContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessSignOutContext>()
                .UseSingletonHandler<AttachSignOutParameters>()
                .SetOrder(GenerateLogoutStateToken.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignOutContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Note: while the exact order of the parameters has typically no effect on how requests
            // are handled by an authorization server, client_id and post_logout_redirect_uri are
            // set first so that they appear early in the URL (when GET requests are used), making
            // mistyped values easier to spot when an error is returned by the identity provider.
            context.Request.ClientId = context.ClientId;
            context.Request.PostLogoutRedirectUri = context.PostLogoutRedirectUri;

            context.Request.IdTokenHint = context.IdentityTokenHint;
            context.Request.LoginHint = context.LoginHint;

            if (context.IncludeStateToken)
            {
                context.Request.State = context.StateToken;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the parameters
    /// populated from user-defined handlers to the sign-out response.
    /// </summary>
    public sealed class AttachCustomSignOutParameters : IOpenIddictClientHandler<ProcessSignOutContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessSignOutContext>()
                .UseSingletonHandler<AttachCustomSignOutParameters>()
                .SetOrder(100_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignOutContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.Parameters.Count > 0)
            {
                foreach (var parameter in context.Parameters)
                {
                    context.Response.SetParameter(parameter.Key, parameter.Value);
                }
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the appropriate parameters to the error response.
    /// </summary>
    public sealed class AttachErrorParameters : IOpenIddictClientHandler<ProcessErrorContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessErrorContext>()
                .UseSingletonHandler<AttachErrorParameters>()
                .SetOrder(int.MinValue + 100_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessErrorContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            context.Response.Error = context.Error;
            context.Response.ErrorDescription = context.ErrorDescription;
            context.Response.ErrorUri = context.ErrorUri;

            if (context.Parameters.Count > 0)
            {
                foreach (var parameter in context.Parameters)
                {
                    context.Response.SetParameter(parameter.Key, parameter.Value);
                }
            }

            return default;
        }
    }
}
