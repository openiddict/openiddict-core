/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Diagnostics;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace OpenIddict.Infrastructure {
    public partial class OpenIddictProvider<TUser, TApplication, TAuthorization, TScope, TToken> : OpenIdConnectServerProvider
        where TUser : class where TApplication : class where TAuthorization : class where TScope : class where TToken : class {
        public override async Task ValidateTokenRequest([NotNull] ValidateTokenRequestContext context) {
            var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TUser, TApplication, TAuthorization, TScope, TToken>>();

            // Reject token requests that don't specify a supported grant type.
            if (!services.Options.GrantTypes.Contains(context.Request.GrantType)) {
                services.Logger.LogError("The token request was rejected because the '{Grant}' " +
                                         "grant is not supported.", context.Request.GrantType);

                context.Reject(
                    error: OpenIdConnectConstants.Errors.UnsupportedGrantType,
                    description: "The specified grant_type is not supported by this authorization server.");

                return;
            }

            // Reject token requests that specify scope=offline_access if the refresh token flow is not enabled.
            if (context.Request.HasScope(OpenIdConnectConstants.Scopes.OfflineAccess) && !services.Options.IsRefreshTokenFlowEnabled()) {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "The 'offline_access' scope is not allowed.");

                return;
            }

            // Note: the OpenID Connect server middleware allows returning a refresh token with grant_type=client_credentials,
            // though it's usually not recommended by the OAuth2 specification. To encourage developers to make a new
            // grant_type=client_credentials request instead of using refresh tokens, OpenIddict uses a stricter policy
            // that rejects grant_type=client_credentials requests containing the 'offline_access' scope.
            // See https://tools.ietf.org/html/rfc6749#section-4.4.3 for more information.
            if (context.Request.IsClientCredentialsGrantType() &&
                context.Request.HasScope(OpenIdConnectConstants.Scopes.OfflineAccess)) {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "The 'offline_access' scope is not allowed when using grant_type=client_credentials.");

                return;
            }

            // Note: the OpenID Connect server middleware rejects grant_type=client_credentials requests
            // when validation is skipped but an early check is made here to avoid making unnecessary
            // database roundtrips to retrieve the client application corresponding to the client_id.
            if (context.Request.IsClientCredentialsGrantType() && (string.IsNullOrEmpty(context.Request.ClientId) ||
                                                                   string.IsNullOrEmpty(context.Request.ClientSecret))) {
                services.Logger.LogError("The token request was rejected because the client credentials were missing.");

                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "Client applications must be authenticated to use the client credentials grant.");

                return;
            }

            // Note: though required by the OpenID Connect specification for the refresh token grant,
            // client authentication is not mandatory for non-confidential client applications in OAuth2.
            // To avoid breaking OAuth2 scenarios, OpenIddict uses a relaxed policy that allows
            // public applications to use the refresh token grant without having to authenticate.
            // See http://openid.net/specs/openid-connect-core-1_0.html#RefreshingAccessToken
            // and https://tools.ietf.org/html/rfc6749#section-6 for more information.

            // At this stage, skip client authentication if the client identifier is missing.
            // Note: the OpenID Connect server middleware will automatically ensure that
            // the calling application cannot use an authorization code or a refresh token
            // if it's not the intended audience, even if client authentication was skipped.
            if (string.IsNullOrEmpty(context.ClientId)) {
                services.Logger.LogInformation("The token request validation process was skipped " +
                                               "because the client_id parameter was missing or empty.");

                context.Skip();

                return;
            }

            // Retrieve the application details corresponding to the requested client_id.
            var application = await services.Applications.FindByClientIdAsync(context.ClientId);
            if (application == null) {
                services.Logger.LogError("The token request was rejected because the client " +
                                         "application was not found: '{ClientId}'.", context.ClientId);

                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Application not found in the database: ensure that your client_id is correct.");

                return;
            }

            if (await services.Applications.IsPublicAsync(application)) {
                // Note: public applications are not allowed to use the client credentials grant.
                if (context.Request.IsClientCredentialsGrantType()) {
                    services.Logger.LogError("The token request was rejected because the public client application '{ClientId}' " +
                                             "was not allowed to use the client credentials grant.", context.Request.ClientId);

                    context.Reject(
                        error: OpenIdConnectConstants.Errors.UnauthorizedClient,
                        description: "Public clients are not allowed to use the client credentials grant.");

                    return;
                }

                // Reject tokens requests containing a client_secret when the client is a public application.
                if (!string.IsNullOrEmpty(context.ClientSecret)) {
                    services.Logger.LogError("The token request was rejected because the public application '{ClientId}' " +
                                             "was not allowed to send a client secret.", context.ClientId);

                    context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidRequest,
                        description: "Public clients are not allowed to send a client_secret.");

                    return;
                }

                services.Logger.LogInformation("The token request validation process was not fully validated because " +
                                               "the client '{ClientId}' was a public application.", context.ClientId);

                // If client authentication cannot be enforced, call context.Skip() to inform
                // the OpenID Connect server middleware that the caller cannot be fully trusted.
                context.Skip();

                return;
            }

            // Confidential applications MUST authenticate
            // to protect them from impersonation attacks.
            if (string.IsNullOrEmpty(context.ClientSecret)) {
                services.Logger.LogError("The token request was rejected because the confidential application " +
                                         "'{ClientId}' didn't specify a client secret.", context.ClientId);

                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Missing credentials: ensure that you specified a client_secret.");

                return;
            }

            if (!await services.Applications.ValidateSecretAsync(application, context.ClientSecret)) {
                services.Logger.LogError("The token request was rejected because the confidential application " +
                                         "'{ClientId}' didn't specify valid client credentials.", context.ClientId);

                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Invalid credentials: ensure that you specified a correct client_secret.");

                return;
            }

            context.Validate();
        }

        public override async Task HandleTokenRequest([NotNull] HandleTokenRequestContext context) {
            var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TUser, TApplication, TAuthorization, TScope, TToken>>();

            // Note: the OpenID Connect server middleware automatically reuses the authentication ticket
            // stored in the authorization code to create a new identity. To ensure the user was not removed
            // after the authorization code was issued, a new check is made before validating the request.
            if (context.Request.IsAuthorizationCodeGrantType()) {
                Debug.Assert(context.Ticket != null, "The authentication ticket shouldn't be null.");

                var user = await services.Users.GetUserAsync(context.Ticket.Principal);
                if (user == null) {
                    services.Logger.LogError("The token request was rejected because the user profile associated " +
                                             "with the authorization code was not found in the database: '{Identifier}'.",
                                             context.Ticket.Principal.GetClaim(ClaimTypes.NameIdentifier));

                    context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidGrant,
                        description: "The authorization code is no longer valid.");

                    return;
                }

                // Extract the token identifier from the authorization code.
                var identifier = context.Ticket.GetTicketId();
                Debug.Assert(!string.IsNullOrEmpty(identifier),
                    "The authorization code should contain a ticket identifier.");

                // Retrieve the token from the database and ensure it is still valid.
                var token = await services.Tokens.FindByIdAsync(identifier);
                if (token == null) {
                    services.Logger.LogError("The token request was rejected because the authorization code was revoked.");

                    context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidGrant,
                        description: "The authorization code is no longer valid.");

                    return;
                }

                // Revoke the authorization code to prevent token reuse.
                await services.Tokens.RevokeAsync(token);

                context.Validate(context.Ticket);

                return;
            }

            // Note: the OpenID Connect server middleware automatically reuses the authentication ticket
            // stored in the refresh token to create a new identity. To ensure the user was not removed
            // after the refresh token was issued, a new check is made before validating the request.
            else if (context.Request.IsRefreshTokenGrantType()) {
                Debug.Assert(context.Ticket != null, "The authentication ticket shouldn't be null.");

                var user = await services.Users.GetUserAsync(context.Ticket.Principal);
                if (user == null) {
                    services.Logger.LogError("The token request was rejected because the user profile associated " +
                                             "with the refresh token was not found in the database: '{Identifier}'.",
                                             context.Ticket.Principal.GetClaim(ClaimTypes.NameIdentifier));

                    context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidGrant,
                        description: "The refresh token is no longer valid.");

                    return;
                }

                // Extract the token identifier from the refresh token.
                var identifier = context.Ticket.GetTicketId();
                Debug.Assert(!string.IsNullOrEmpty(identifier),
                    "The refresh token should contain a ticket identifier.");

                // Retrieve the token from the database and ensure it is still valid.
                var token = await services.Tokens.FindByIdAsync(identifier);
                if (token == null) {
                    services.Logger.LogError("The token request was rejected because the refresh token was revoked.");

                    context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidGrant,
                        description: "The refresh token is no longer valid.");

                    return;
                }

                // When sliding expiration is enabled, immediately
                // revoke the refresh token to prevent future reuse.
                // See https://tools.ietf.org/html/rfc6749#section-6.
                if (context.Options.UseSlidingExpiration) {
                    await services.Tokens.RevokeAsync(token);
                }

                // Note: the "scopes" property stored in context.AuthenticationTicket is automatically updated by the
                // OpenID Connect server middleware when the client application requests a restricted scopes collection.
                var identity = await services.Users.CreateIdentityAsync(user, context.Ticket.GetScopes());
                if (identity == null) {
                    throw new InvalidOperationException("The token request was aborted because the user manager returned a null " +
                                                       $"identity for user '{await services.Users.GetUserNameAsync(user)}'.");
                }

                // Create a new authentication ticket holding the user identity but
                // reuse the authentication properties stored in the refresh token.
                var ticket = new AuthenticationTicket(
                    new ClaimsPrincipal(identity),
                    context.Ticket.Properties,
                    context.Options.AuthenticationScheme);

                context.Validate(ticket);

                return;
            }

            else if (context.Request.IsPasswordGrantType()) {
                // Note: at this stage, the client credentials cannot be null as the OpenID Connect server middleware
                // automatically rejects grant_type=password requests that don't specify a username/password couple.
                Debug.Assert(!string.IsNullOrEmpty(context.Request.Username) &&
                             !string.IsNullOrEmpty(context.Request.Password), "The user credentials shouldn't be null.");

                var user = await services.Users.FindByNameAsync(context.Request.Username);
                if (user == null) {
                    services.Logger.LogWarning("The token request was not fully validated because the profile corresponding to the " +
                                               "given username was not found in the database: {Username}.", context.Request.Username);
                }

                // Return an error if the username corresponds to the registered
                // email address and if the "email" scope has not been requested.
                else if (services.Users.SupportsUserEmail && context.Request.HasScope(OpenIdConnectConstants.Scopes.Profile) &&
                                                            !context.Request.HasScope(OpenIdConnectConstants.Scopes.Email)) {
                    // Retrieve the username and the email address associated with the user.
                    var username = await services.Users.GetUserNameAsync(user);
                    var email = await services.Users.GetEmailAsync(user);

                    if (!string.IsNullOrEmpty(email) && string.Equals(username, email, StringComparison.OrdinalIgnoreCase)) {
                        services.Logger.LogError("The token request was rejected because the 'email' scope was not requested: " +
                                                 "to prevent data leakage, the 'email' scope must be granted when the username " +
                                                 "is identical to the email address associated with the user profile.");

                        context.Reject(
                            error: OpenIdConnectConstants.Errors.InvalidRequest,
                            description: "The 'email' scope is required.");

                        return;
                    }
                }
            }

            // Invoke the rest of the pipeline to allow
            // the user code to handle the token request.
            context.SkipToNextMiddleware();
        }
    }
}