/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;

namespace OpenIddict.Server
{
    /// <summary>
    /// Provides the logic necessary to extract, validate and handle OpenID Connect requests.
    /// </summary>
    internal sealed partial class OpenIddictServerProvider : OpenIdConnectServerProvider
    {
        public override Task ExtractTokenRequest([NotNull] ExtractTokenRequestContext context)
            => _eventDispatcher.DispatchAsync(new OpenIddictServerEvents.ExtractTokenRequest(context));

        public override async Task ValidateTokenRequest([NotNull] ValidateTokenRequestContext context)
        {
            var options = (OpenIddictServerOptions) context.Options;

            // Reject token requests that don't specify a supported grant type.
            if (!options.GrantTypes.Contains(context.Request.GrantType))
            {
                _logger.LogError("The token request was rejected because the '{GrantType}' " +
                                 "grant type is not supported.", context.Request.GrantType);

                context.Reject(
                    error: OpenIddictConstants.Errors.UnsupportedGrantType,
                    description: "The specified 'grant_type' parameter is not supported.");

                return;
            }

            // Reject token requests that specify scope=offline_access if the refresh token flow is not enabled.
            if (context.Request.HasScope(OpenIddictConstants.Scopes.OfflineAccess) &&
               !options.GrantTypes.Contains(OpenIddictConstants.GrantTypes.RefreshToken))
            {
                context.Reject(
                    error: OpenIddictConstants.Errors.InvalidRequest,
                    description: "The 'offline_access' scope is not allowed.");

                return;
            }

            if (context.Request.IsAuthorizationCodeGrantType())
            {
                // Optimization: the OpenID Connect server middleware automatically rejects grant_type=authorization_code
                // requests missing the redirect_uri parameter if one was specified in the initial authorization request.
                // Since OpenIddict doesn't allow redirect_uri-less authorization requests, an earlier check can be made here,
                // which saves the OpenID Connect server middleware from having to deserialize the authorization code ticket.
                // See http://openid.net/specs/openid-connect-core-1_0.html#TokenRequestValidation for more information.
                if (string.IsNullOrEmpty(context.Request.RedirectUri))
                {
                    context.Reject(
                        error: OpenIddictConstants.Errors.InvalidRequest,
                        description: "The mandatory 'redirect_uri' parameter is missing.");

                    return;
                }

                // Optimization: the OpenID Connect server middleware automatically rejects grant_type=authorization_code
                // requests missing the code_verifier parameter when a challenge was specified in the authorization request.
                // That check requires decrypting the authorization code and determining whether a code challenge was set.
                // If OpenIddict was configured to require PKCE, this can be potentially avoided by making an early check here.
                if (options.RequireProofKeyForCodeExchange && string.IsNullOrEmpty(context.Request.CodeVerifier))
                {
                    _logger.LogError("The token request was rejected because the required 'code_verifier' parameter was missing.");

                    context.Reject(
                        error: OpenIddictConstants.Errors.InvalidRequest,
                        description: "The mandatory 'code_verifier' parameter is missing.");

                    return;
                }
            }

            // Note: the OpenID Connect server middleware allows returning a refresh token with grant_type=client_credentials,
            // though it's usually not recommended by the OAuth2 specification. To encourage developers to make a new
            // grant_type=client_credentials request instead of using refresh tokens, OpenIddict uses a stricter policy
            // that rejects grant_type=client_credentials requests containing the 'offline_access' scope.
            // See https://tools.ietf.org/html/rfc6749#section-4.4.3 for more information.
            if (context.Request.IsClientCredentialsGrantType() &&
                context.Request.HasScope(OpenIddictConstants.Scopes.OfflineAccess))
            {
                context.Reject(
                    error: OpenIddictConstants.Errors.InvalidRequest,
                    description: "The 'offline_access' scope is not valid for the specified 'grant_type' parameter.");

                return;
            }

            // Validates scopes, unless scope validation was explicitly disabled.
            if (!options.DisableScopeValidation)
            {
                var scopes = new HashSet<string>(context.Request.GetScopes(), StringComparer.Ordinal);
                scopes.ExceptWith(options.Scopes);

                // If all the specified scopes are registered in the options, avoid making a database lookup.
                if (scopes.Count != 0)
                {
                    foreach (var scope in await _scopeManager.FindByNamesAsync(scopes.ToImmutableArray()))
                    {
                        scopes.Remove(await _scopeManager.GetNameAsync(scope));
                    }
                }

                // If at least one scope was not recognized, return an error.
                if (scopes.Count != 0)
                {
                    _logger.LogError("The token request was rejected because invalid scopes were specified: {Scopes}.", scopes);

                    context.Reject(
                        error: OpenIddictConstants.Errors.InvalidScope,
                        description: "The specified 'scope' parameter is not valid.");

                    return;
                }
            }

            // Optimization: the OpenID Connect server middleware automatically rejects grant_type=client_credentials
            // requests when validation is skipped but an earlier check is made here to avoid making unnecessary
            // database roundtrips to retrieve the client application corresponding to the client_id.
            if (context.Request.IsClientCredentialsGrantType() && (string.IsNullOrEmpty(context.Request.ClientId) ||
                                                                   string.IsNullOrEmpty(context.Request.ClientSecret)))
            {
                context.Reject(
                    error: OpenIddictConstants.Errors.InvalidRequest,
                    description: "The 'client_id' and 'client_secret' parameters are " +
                                 "required when using the client credentials grant.");

                return;
            }

            // At this stage, skip client authentication if the client identifier is missing
            // or reject the token request if client identification is set as required.
            // Note: the OpenID Connect server middleware will automatically ensure that
            // the calling application cannot use an authorization code or a refresh token
            // if it's not the intended audience, even if client authentication was skipped.
            if (string.IsNullOrEmpty(context.ClientId))
            {
                // Reject the request if client identification is mandatory.
                if (!options.AcceptAnonymousClients)
                {
                    _logger.LogError("The token request was rejected becaused the " +
                                     "mandatory client_id parameter was missing or empty.");

                    context.Reject(
                        error: OpenIddictConstants.Errors.InvalidRequest,
                        description: "The mandatory 'client_id' parameter is missing.");

                    return;
                }

                _logger.LogDebug("The token request validation process was partially skipped " +
                                 "because the 'client_id' parameter was missing or empty.");

                context.Skip();

                return;
            }

            // Retrieve the application details corresponding to the requested client_id.
            var application = await _applicationManager.FindByClientIdAsync(context.ClientId);
            if (application == null)
            {
                _logger.LogError("The token request was rejected because the client " +
                                 "application was not found: '{ClientId}'.", context.ClientId);

                context.Reject(
                    error: OpenIddictConstants.Errors.InvalidClient,
                    description: "The specified 'client_id' parameter is invalid.");

                return;
            }

            // Reject the request if the application is not allowed to use the token endpoint.
            if (!options.IgnoreEndpointPermissions &&
                !await _applicationManager.HasPermissionAsync(application, OpenIddictConstants.Permissions.Endpoints.Token))
            {
                _logger.LogError("The token request was rejected because the application '{ClientId}' " +
                                 "was not allowed to use the token endpoint.", context.ClientId);

                context.Reject(
                    error: OpenIddictConstants.Errors.UnauthorizedClient,
                    description: "This client application is not allowed to use the token endpoint.");

                return;
            }

            if (!options.IgnoreGrantTypePermissions)
            {
                // Reject the request if the application is not allowed to use the specified grant type.
                if (!await _applicationManager.HasPermissionAsync(application,
                    OpenIddictConstants.Permissions.Prefixes.GrantType + context.Request.GrantType))
                {
                    _logger.LogError("The token request was rejected because the application '{ClientId}' was not allowed to " +
                                     "use the specified grant type: {GrantType}.", context.ClientId, context.Request.GrantType);

                    context.Reject(
                        error: OpenIddictConstants.Errors.UnauthorizedClient,
                        description: "This client application is not allowed to use the specified grant type.");

                    return;
                }

                // Reject the request if the offline_access scope was request and if
                // the application is not allowed to use the refresh token grant type.
                if (context.Request.HasScope(OpenIddictConstants.Scopes.OfflineAccess) &&
                   !await _applicationManager.HasPermissionAsync(application, OpenIddictConstants.Permissions.GrantTypes.RefreshToken))
                {
                    _logger.LogError("The token request was rejected because the application '{ClientId}' " +
                                     "was not allowed to request the 'offline_access' scope.", context.ClientId);

                    context.Reject(
                        error: OpenIddictConstants.Errors.InvalidRequest,
                        description: "The client application is not allowed to use the 'offline_access' scope.");

                    return;
                }
            }

            // Unless permission enforcement was explicitly disabled, ensure
            // the client application is allowed to use the specified scopes.
            if (!options.IgnoreScopePermissions)
            {
                foreach (var scope in context.Request.GetScopes())
                {
                    // Avoid validating the "openid" and "offline_access" scopes as they represent protocol scopes.
                    if (string.Equals(scope, OpenIddictConstants.Scopes.OfflineAccess, StringComparison.Ordinal) ||
                        string.Equals(scope, OpenIddictConstants.Scopes.OpenId, StringComparison.Ordinal))
                    {
                        continue;
                    }

                    // Reject the request if the application is not allowed to use the iterated scope.
                    if (!await _applicationManager.HasPermissionAsync(application,
                        OpenIddictConstants.Permissions.Prefixes.Scope + scope))
                    {
                        _logger.LogError("The token request was rejected because the application '{ClientId}' " +
                                         "was not allowed to use the scope {Scope}.", context.ClientId, scope);

                        context.Reject(
                            error: OpenIddictConstants.Errors.InvalidRequest,
                            description: "This client application is not allowed to use the specified scope.");

                        return;
                    }
                }
            }

            if (await _applicationManager.IsPublicAsync(application))
            {
                // Note: public applications are not allowed to use the client credentials grant.
                if (context.Request.IsClientCredentialsGrantType())
                {
                    _logger.LogError("The token request was rejected because the public client application '{ClientId}' " +
                                     "was not allowed to use the client credentials grant.", context.Request.ClientId);

                    context.Reject(
                        error: OpenIddictConstants.Errors.UnauthorizedClient,
                        description: "The specified 'grant_type' parameter is not valid for this client application.");

                    return;
                }

                // Reject token requests containing a client_secret when the client is a public application.
                if (!string.IsNullOrEmpty(context.ClientSecret))
                {
                    _logger.LogError("The token request was rejected because the public application '{ClientId}' " +
                                     "was not allowed to send a client secret.", context.ClientId);

                    context.Reject(
                        error: OpenIddictConstants.Errors.InvalidRequest,
                        description: "The 'client_secret' parameter is not valid for this client application.");

                    return;
                }

                _logger.LogDebug("The token request validation process was not fully validated because " +
                                 "the client '{ClientId}' was a public application.", context.ClientId);

                // If client authentication cannot be enforced, call context.Skip() to inform
                // the OpenID Connect server middleware that the caller cannot be fully trusted.
                context.Skip();

                return;
            }

            // Confidential and hybrid applications MUST authenticate
            // to protect them from impersonation attacks.
            if (string.IsNullOrEmpty(context.ClientSecret))
            {
                _logger.LogError("The token request was rejected because the confidential or hybrid application " +
                                 "'{ClientId}' didn't specify a client secret.", context.ClientId);

                context.Reject(
                    error: OpenIddictConstants.Errors.InvalidClient,
                    description: "The 'client_secret' parameter required for this client application is missing.");

                return;
            }

            if (!await _applicationManager.ValidateClientSecretAsync(application, context.ClientSecret))
            {
                _logger.LogError("The token request was rejected because the confidential or hybrid application " +
                                 "'{ClientId}' didn't specify valid client credentials.", context.ClientId);

                context.Reject(
                    error: OpenIddictConstants.Errors.InvalidClient,
                    description: "The specified client credentials are invalid.");

                return;
            }

            context.Validate();

            await _eventDispatcher.DispatchAsync(new OpenIddictServerEvents.ValidateTokenRequest(context));
        }

        public override async Task HandleTokenRequest([NotNull] HandleTokenRequestContext context)
        {
            var options = (OpenIddictServerOptions) context.Options;

            if (context.Ticket != null)
            {
                // Store the authentication ticket as a request property so it can be later retrieved, if necessary.
                context.Request.SetProperty(OpenIddictConstants.Properties.AuthenticationTicket, context.Ticket);
            }

            if (!context.Request.IsAuthorizationCodeGrantType() && !context.Request.IsRefreshTokenGrantType())
            {
                // Invoke the rest of the pipeline to allow
                // the user code to handle the token request.
                context.SkipHandler();

                await _eventDispatcher.DispatchAsync(new OpenIddictServerEvents.HandleTokenRequest(context));

                return;
            }

            Debug.Assert(context.Ticket != null, "The authentication ticket shouldn't be null.");

            // Unless token revocation was explicitly disabled, ensure
            // the authorization code/refresh token is still valid.
            if (!options.DisableTokenStorage)
            {
                // Extract the token identifier from the authentication ticket.
                var identifier = context.Ticket.GetInternalTokenId();
                Debug.Assert(!string.IsNullOrEmpty(identifier), "The authentication ticket should contain a token identifier.");

                // If the authorization code/refresh token is already marked as redeemed, this may indicate that
                // it was compromised. In this case, revoke the authorization and all the associated tokens. 
                // See https://tools.ietf.org/html/rfc6749#section-10.5 for more information.
                var token = await _tokenManager.FindByIdAsync(identifier);
                if (token == null || await _tokenManager.IsRedeemedAsync(token))
                {
                    if (token != null)
                    {
                        await TryRevokeTokenAsync(token);
                    }

                    // Try to revoke the authorization and the associated tokens.
                    // If the operation fails, the helpers will automatically log
                    // and swallow the exception to ensure that a valid error
                    // response will be returned to the client application.
                    if (!options.DisableAuthorizationStorage)
                    {
                        await TryRevokeAuthorizationAsync(context.Ticket);
                        await TryRevokeTokensAsync(context.Ticket);
                    }

                    _logger.LogError("The token request was rejected because the authorization code " +
                                     "or refresh token '{Identifier}' has already been redeemed.", identifier);

                    context.Reject(
                        error: OpenIddictConstants.Errors.InvalidGrant,
                        description: context.Request.IsAuthorizationCodeGrantType() ?
                            "The specified authorization code has already been redeemed." :
                            "The specified refresh token has already been redeemed.");

                    return;
                }

                else if (!await _tokenManager.IsValidAsync(token))
                {
                    _logger.LogError("The token request was rejected because the authorization code " +
                                     "or refresh token '{Identifier}' was no longer valid.", identifier);

                    context.Reject(
                        error: OpenIddictConstants.Errors.InvalidGrant,
                        description: context.Request.IsAuthorizationCodeGrantType() ?
                            "The specified authorization code is no longer valid." :
                            "The specified refresh token is no longer valid.");

                    return;
                }
            }

            // Unless authorization revocation was explicitly disabled, ensure the
            // authorization associated with the code/refresh token is still valid.
            if (!options.DisableAuthorizationStorage)
            {
                // Extract the authorization identifier from the authentication ticket.
                var identifier = context.Ticket.GetInternalAuthorizationId();
                if (!string.IsNullOrEmpty(identifier))
                {
                    var authorization = await _authorizationManager.FindByIdAsync(identifier);
                    if (authorization == null || !await _authorizationManager.IsValidAsync(authorization))
                    {
                        _logger.LogError("The token '{Identifier}' was rejected because " +
                                         "the associated authorization was no longer valid.");

                        context.Reject(
                            error: OpenIddictConstants.Errors.InvalidGrant,
                            description: context.Request.IsAuthorizationCodeGrantType() ?
                                "The authorization associated with the authorization code is no longer valid." :
                                "The authorization associated with the refresh token is no longer valid.");

                        return;
                    }
                }
            }

            // Invoke the rest of the pipeline to allow
            // the user code to handle the token request.
            context.SkipHandler();

            await _eventDispatcher.DispatchAsync(new OpenIddictServerEvents.HandleTokenRequest(context));
        }

        public override Task ApplyTokenResponse([NotNull] ApplyTokenResponseContext context)
            => _eventDispatcher.DispatchAsync(new OpenIddictServerEvents.ApplyTokenResponse(context));
    }
}
