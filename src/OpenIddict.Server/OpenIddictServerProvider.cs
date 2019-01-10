/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;

namespace OpenIddict.Server
{
    /// <summary>
    /// Provides the logic necessary to extract, validate and handle OpenID Connect requests.
    /// </summary>
    internal sealed partial class OpenIddictServerProvider : OpenIdConnectServerProvider
    {
        private readonly ILogger _logger;
        private readonly IOpenIddictServerEventDispatcher _eventDispatcher;
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly IOpenIddictAuthorizationManager _authorizationManager;
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly IOpenIddictTokenManager _tokenManager;

        /// <summary>
        /// Creates a new instance of the <see cref="OpenIddictServerProvider"/> class.
        /// Note: this API supports the OpenIddict infrastructure and is not intended to be used
        /// directly from your code. This API may change or be removed in future minor releases.
        /// </summary>
        public OpenIddictServerProvider(
            [NotNull] ILogger<OpenIddictServerProvider> logger,
            [NotNull] IOpenIddictServerEventDispatcher eventDispatcher,
            [NotNull] IOpenIddictApplicationManager applicationManager,
            [NotNull] IOpenIddictAuthorizationManager authorizationManager,
            [NotNull] IOpenIddictScopeManager scopeManager,
            [NotNull] IOpenIddictTokenManager tokenManager)
        {
            _logger = logger;
            _eventDispatcher = eventDispatcher;
            _applicationManager = applicationManager;
            _authorizationManager = authorizationManager;
            _scopeManager = scopeManager;
            _tokenManager = tokenManager;
        }

        public override Task MatchEndpoint([NotNull] MatchEndpointContext context)
            => _eventDispatcher.DispatchAsync(new OpenIddictServerEvents.MatchEndpoint(context));

        public override Task ProcessChallengeResponse([NotNull] ProcessChallengeResponseContext context)
        {
            Debug.Assert(context.Request.IsAuthorizationRequest() ||
                         context.Request.IsTokenRequest(),
                "The request should be an authorization or token request.");

            // Add the custom properties that are marked as public
            // as authorization or token response properties.
            var parameters = GetParameters(context.Request, context.Properties);
            foreach (var (property, parameter, value) in parameters)
            {
                context.Response.AddParameter(parameter, value);
            }

            return _eventDispatcher.DispatchAsync(new OpenIddictServerEvents.ProcessChallengeResponse(context));
        }

        public override async Task ProcessSigninResponse([NotNull] ProcessSigninResponseContext context)
        {
            var options = (OpenIddictServerOptions) context.Options;

            Debug.Assert(context.Request.IsAuthorizationRequest() ||
                         context.Request.IsTokenRequest(),
                "The request should be an authorization or token request.");

            // While null/unauthenticated identities can be validly represented and are allowed by
            // the OpenID Connect server handler, this most likely indicates that the developer
            // has not correctly set the authentication type associated with the claims identity,
            // which may later cause issues when validating opaque access tokens, as the resulting
            // principal would be considered unauthenticated by the ASP.NET Core authorization stack.
            if (context.Ticket.Principal.Identity == null || !context.Ticket.Principal.Identity.IsAuthenticated)
            {
                throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("The specified principal doesn't contain a valid or authenticated identity.")
                    .Append("Make sure that both 'ClaimsPrincipal.Identity' and 'ClaimsPrincipal.Identity.AuthenticationType' ")
                    .Append("are not null and that 'ClaimsPrincipal.Identity.IsAuthenticated' returns 'true'.")
                    .ToString());
            }

            if (context.Request.IsTokenRequest() && (context.Request.IsAuthorizationCodeGrantType() ||
                                                     context.Request.IsRefreshTokenGrantType()))
            {
                // Note: when handling a grant_type=authorization_code or refresh_token request,
                // the OpenID Connect server middleware allows creating authentication tickets
                // that are completely disconnected from the original code or refresh token ticket.
                // This scenario is deliberately not supported in OpenIddict and all the tickets
                // must be linked. To ensure the properties are flowed from the authorization code
                // or the refresh token to the new ticket, they are manually restored if necessary.
                if (string.IsNullOrEmpty(context.Ticket.GetInternalTokenId()))
                {
                    // Retrieve the original authentication ticket from the request properties.
                    var ticket = context.Request.GetProperty<AuthenticationTicket>(
                        OpenIddictConstants.Properties.AuthenticationTicket);
                    Debug.Assert(ticket != null, "The authentication ticket shouldn't be null.");

                    foreach (var property in ticket.Properties.Items)
                    {
                        // Don't override the properties that have been
                        // manually set on the new authentication ticket.
                        if (context.Ticket.HasProperty(property.Key))
                        {
                            continue;
                        }

                        context.Ticket.AddProperty(property.Key, property.Value);
                    }

                    // Always include the "openid" scope when the developer doesn't explicitly call SetScopes.
                    // Note: the application is allowed to specify a different "scopes": in this case,
                    // don't replace the "scopes" property stored in the authentication ticket.
                    if (context.Request.HasScope(OpenIddictConstants.Scopes.OpenId) && !context.Ticket.HasScope())
                    {
                        context.Ticket.SetScopes(OpenIddictConstants.Scopes.OpenId);
                    }

                    context.IncludeIdentityToken = context.Ticket.HasScope(OpenIddictConstants.Scopes.OpenId);
                }

                context.IncludeRefreshToken = context.Ticket.HasScope(OpenIddictConstants.Scopes.OfflineAccess);

                // Always include a refresh token for grant_type=refresh_token requests if
                // rolling tokens are enabled and if the offline_access scope was specified.
                if (context.Request.IsRefreshTokenGrantType())
                {
                    context.IncludeRefreshToken &= options.UseRollingTokens;
                }

                // If token revocation was explicitly disabled, none of the following security routines apply.
                if (!options.DisableTokenStorage)
                {
                    var token = await _tokenManager.FindByIdAsync(context.Ticket.GetInternalTokenId());
                    if (token == null)
                    {
                        context.Reject(
                            error: OpenIddictConstants.Errors.InvalidGrant,
                            description: context.Request.IsAuthorizationCodeGrantType() ?
                                "The specified authorization code is no longer valid." :
                                "The specified refresh token is no longer valid.");

                        return;
                    }

                    // If rolling tokens are enabled or if the request is a grant_type=authorization_code request,
                    // mark the authorization code or the refresh token as redeemed to prevent future reuses.
                    // If the operation fails, return an error indicating the code/token is no longer valid.
                    // See https://tools.ietf.org/html/rfc6749#section-6 for more information.
                    if (options.UseRollingTokens || context.Request.IsAuthorizationCodeGrantType())
                    {
                        if (!await TryRedeemTokenAsync(token))
                        {
                            context.Reject(
                                error: OpenIddictConstants.Errors.InvalidGrant,
                                description: context.Request.IsAuthorizationCodeGrantType() ?
                                    "The specified authorization code is no longer valid." :
                                    "The specified refresh token is no longer valid.");

                            return;
                        }
                    }

                    if (context.Request.IsRefreshTokenGrantType())
                    {
                        // When rolling tokens are enabled, try to revoke all the previously issued tokens
                        // associated with the authorization if the request is a refresh_token request.
                        // If the operation fails, silently ignore the error and keep processing the request:
                        // this may indicate that one of the revoked tokens was modified by a concurrent request.
                        if (options.UseRollingTokens)
                        {
                            await TryRevokeTokensAsync(context.Ticket);
                        }

                        // When rolling tokens are disabled, try to extend the expiration date
                        // of the existing token instead of returning a new refresh token
                        // with a new expiration date if sliding expiration was not disabled.
                        // If the operation fails, silently ignore the error and keep processing
                        // the request: this may indicate that a concurrent refresh token request
                        // already updated the expiration date associated with the refresh token.
                        if (!options.UseRollingTokens && options.UseSlidingExpiration)
                        {
                            await TryExtendRefreshTokenAsync(token, context.Ticket, options);
                        }
                    }
                }
            }

            // If no authorization was explicitly attached to the authentication ticket,
            // create an ad hoc authorization if an authorization code or a refresh token
            // is going to be returned to the client application as part of the response.
            if (!options.DisableAuthorizationStorage &&
                string.IsNullOrEmpty(context.Ticket.GetInternalAuthorizationId()) &&
                (context.IncludeAuthorizationCode || context.IncludeRefreshToken))
            {
                await CreateAuthorizationAsync(context.Ticket, options, context.Request);
            }

            // Add the custom properties that are marked as public as authorization or
            // token response properties and remove them from the authentication ticket
            // so they are not persisted in the authorization code/access/refresh token.
            // Note: make sure the foreach statement iterates on a copy of the ticket
            // as the property collection is modified when the property is removed.
            var parameters = GetParameters(context.Request, context.Ticket.Properties);
            foreach (var (property, parameter, value) in parameters.ToList())
            {
                context.Response.AddParameter(parameter, value);
                context.Ticket.RemoveProperty(property);
            }

            await _eventDispatcher.DispatchAsync(new OpenIddictServerEvents.ProcessSigninResponse(context));
        }

        public override Task ProcessSignoutResponse([NotNull] ProcessSignoutResponseContext context)
        {
            Debug.Assert(context.Request.IsLogoutRequest(), "The request should be a logout request.");

            // Add the custom properties that are marked as public as logout response properties.
            var parameters = GetParameters(context.Request, context.Properties);
            foreach (var (property, parameter, value) in parameters)
            {
                context.Response.AddParameter(parameter, value);
            }

            return _eventDispatcher.DispatchAsync(new OpenIddictServerEvents.ProcessSignoutResponse(context));
        }
    }
}
