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
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace OpenIddict.Infrastructure {
    public partial class OpenIddictProvider<TUser, TApplication, TAuthorization, TScope, TToken> : OpenIdConnectServerProvider
        where TUser : class where TApplication : class where TAuthorization : class where TScope : class where TToken : class {
        public override async Task ValidateTokenRequest([NotNull] ValidateTokenRequestContext context) {
            var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TUser, TApplication, TAuthorization, TScope, TToken>>();

            // Note: the OpenID Connect server middleware supports authorization code, refresh token, client credentials,
            // resource owner password credentials and custom grants but OpenIddict uses a stricter policy rejecting custom grants.
            if (!context.Request.IsAuthorizationCodeGrantType() && !context.Request.IsRefreshTokenGrantType() &&
                !context.Request.IsPasswordGrantType() && !context.Request.IsClientCredentialsGrantType()) {
                services.Logger.LogError("The token request was rejected because the '{Grant}' " +
                                         "grant is not supported.", context.Request.GrantType);

                context.Reject(
                    error: OpenIdConnectConstants.Errors.UnsupportedGrantType,
                    description: "Only authorization code, refresh token, client credentials " +
                                 "and password grants are accepted by this authorization server.");

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

            // Note: though required by the OpenID Connect specification for the refresh token grant,
            // client authentication is not mandatory for non-confidential client applications in OAuth2.
            // To avoid breaking OAuth2 scenarios, OpenIddict uses a relaxed policy that allows
            // public applications to use the refresh token grant without having to authenticate.
            // See http://openid.net/specs/openid-connect-core-1_0.html#RefreshingAccessToken
            // and https://tools.ietf.org/html/rfc6749#section-6 for more information.

            // Skip client authentication if the client identifier is missing.
            // Note: ASOS will automatically ensure that the calling application
            // cannot use an authorization code or a refresh token if it's not
            // the intended audience, even if client authentication was skipped.
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

            // Reject tokens requests containing a client_secret if the client application is not confidential.
            var type = await services.Applications.GetClientTypeAsync(application);
            if (!string.Equals(type, OpenIddictConstants.ClientTypes.Confidential, StringComparison.OrdinalIgnoreCase) &&
                !string.IsNullOrEmpty(context.ClientSecret)) {
                services.Logger.LogError("The token request was rejected because the public application '{ClientId}' " +
                                         "was not allowed to send a client secret.", context.ClientId);

                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "Public clients are not allowed to send a client_secret.");

                return;
            }

            // Confidential applications MUST authenticate to protect them from impersonation attacks.
            else if (!string.Equals(type, OpenIddictConstants.ClientTypes.Public)) {
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
            }

            context.Validate();
        }

        public override async Task GrantClientCredentials([NotNull] GrantClientCredentialsContext context) {
            var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TUser, TApplication, TAuthorization, TScope, TToken>>();

            // Retrieve the application details corresponding to the requested client_id.
            // Note: this call shouldn't return a null instance, but a race condition may occur
            // if the application was removed after the initial check made by ValidateTokenRequest.
            var application = await services.Applications.FindByClientIdAsync(context.ClientId);
            if (application == null) {
                throw new InvalidOperationException("The token request was aborted because the client application corresponding " +
                                                   $"to the '{context.ClientId}' identifier was not found in the database.");
            }

            var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);

            // Note: the name identifier is always included in both identity and
            // access tokens, even if an explicit destination is not specified.
            identity.AddClaim(ClaimTypes.NameIdentifier, context.ClientId);

            identity.AddClaim(ClaimTypes.Name, await services.Applications.GetDisplayNameAsync(application),
                OpenIdConnectConstants.Destinations.AccessToken,
                OpenIdConnectConstants.Destinations.IdentityToken);

            // Create a new authentication ticket
            // holding the application identity.
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                context.Options.AuthenticationScheme);

            ticket.SetResources(context.Request.GetResources());
            ticket.SetScopes(context.Request.GetScopes());

            context.Validate(ticket);
        }

        public override async Task GrantAuthorizationCode([NotNull] GrantAuthorizationCodeContext context) {
            var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TUser, TApplication, TAuthorization, TScope, TToken>>();

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

            context.Validate(context.Ticket);
        }

        public override async Task GrantRefreshToken([NotNull] GrantRefreshTokenContext context) {
            var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TUser, TApplication, TAuthorization, TScope, TToken>>();

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

            // Note: the "scopes" property stored in context.AuthenticationTicket is automatically
            // updated by ASOS when the client application requests a restricted scopes collection.
            var identity = await services.Users.CreateIdentityAsync(user, context.Ticket.GetScopes());
            if (identity == null) {
                throw new InvalidOperationException("The token request failed because the user manager returned a null " +
                                                   $"identity for user '{await services.Users.GetUserNameAsync(user)}'.");
            }

            // Create a new authentication ticket holding the user identity but
            // reuse the authentication properties stored in the refresh token.
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                context.Ticket.Properties,
                context.Options.AuthenticationScheme);

            context.Validate(ticket);
        }

        public override async Task GrantResourceOwnerCredentials([NotNull] GrantResourceOwnerCredentialsContext context) {
            var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TUser, TApplication, TAuthorization, TScope, TToken>>();

            var user = await services.Users.FindByNameAsync(context.UserName);
            if (user == null) {
                services.Logger.LogError("The token request was rejected because no user profile corresponding to " +
                                         "the specified username was found: '{Username}'.", context.UserName);

                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidGrant,
                    description: "Invalid credentials.");

                return;
            }

            // Ensure the user is allowed to sign in.
            if (!await services.SignIn.CanSignInAsync(user)) {
                services.Logger.LogError("The token request was rejected because the user '{Username}' " +
                                         "was not allowed to sign in.", context.UserName);

                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidGrant,
                    description: "The user is not allowed to sign in.");

                return;
            }

            // Ensure the user is not already locked out.
            if (services.Users.SupportsUserLockout && await services.Users.IsLockedOutAsync(user)) {
                services.Logger.LogError("The token request was rejected because the account '{Username}' " +
                                         "was locked out to prevent brute force attacks.", context.UserName);

                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidGrant,
                    description: "Account locked out.");

                return;
            }

            // Ensure the password is valid.
            if (!await services.Users.CheckPasswordAsync(user, context.Password)) {
                services.Logger.LogError("The token request was rejected because the password didn't match " +
                                         "the password associated with the account '{Username}'.", context.UserName);

                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidGrant,
                    description: "Invalid credentials.");

                if (services.Users.SupportsUserLockout) {
                    await services.Users.AccessFailedAsync(user);

                    // Ensure the user is not locked out.
                    if (await services.Users.IsLockedOutAsync(user)) {
                        services.Logger.LogError("The token request was rejected because the account '{Username}' " +
                                                 "was locked out to prevent brute force attacks.", context.UserName);

                        context.Reject(
                            error: OpenIdConnectConstants.Errors.InvalidGrant,
                            description: "Account locked out.");
                    }
                }

                return;
            }

            if (services.Users.SupportsUserLockout) { 
                await services.Users.ResetAccessFailedCountAsync(user);
            }

            // Reject the token request if two-factor authentication has been enabled by the user.
            if (services.Users.SupportsUserTwoFactor && await services.Users.GetTwoFactorEnabledAsync(user)) {
                services.Logger.LogError("The token request was rejected because two-factor authentication " +
                                         "was required for the account '{Username}.", context.UserName);

                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidGrant,
                    description: "Two-factor authentication is required for this account.");

                return;
            }

            // Return an error if the username corresponds to the registered
            // email address and if the "email" scope has not been requested.
            if (services.Users.SupportsUserEmail && context.Request.HasScope(OpenIdConnectConstants.Scopes.Profile) &&
                                                   !context.Request.HasScope(OpenIdConnectConstants.Scopes.Email)) {
                // Retrieve the username and the email address associated with the user.
                var username = await services.Users.GetUserNameAsync(user);
                var email = await services.Users.GetEmailAsync(user);

                if (!string.IsNullOrEmpty(email) && string.Equals(username, email, StringComparison.OrdinalIgnoreCase)) {
                    services.Logger.LogError("The token request was rejected because the 'email' scope was not requested: " +
                                             "to prevent data leakage, the 'email' scope must be granted when the username" +
                                             "is identical to the email address associated with the user ({Username}).", username);

                    context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidRequest,
                        description: "The 'email' scope is required.");

                    return;
                }
            }

            var identity = await services.Users.CreateIdentityAsync(user, context.Request.GetScopes());
            if (identity == null) {
                throw new InvalidOperationException("The token request failed because the user manager returned a null " +
                                                   $"identity for user '{await services.Users.GetUserNameAsync(user)}'.");
            }

            // Create a new authentication ticket holding the user identity.
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                context.Options.AuthenticationScheme);

            ticket.SetResources(context.Request.GetResources());
            ticket.SetScopes(context.Request.GetScopes());

            context.Validate(ticket);
        }
    }
}