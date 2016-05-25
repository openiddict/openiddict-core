/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;

namespace OpenIddict {
    public partial class OpenIddictProvider<TUser, TApplication> : OpenIdConnectServerProvider where TUser : class where TApplication : class {
        public override async Task ValidateTokenRequest([NotNull] ValidateTokenRequestContext context) {
            var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TUser, TApplication>>();
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<OpenIddictProvider<TUser, TApplication>>>();

            // Note: OpenIdConnectServerHandler supports authorization code, refresh token,
            // client credentials, resource owner password credentials and custom grants
            // but this authorization server uses a stricter policy rejecting custom grant types.
            if (!context.Request.IsAuthorizationCodeGrantType() && !context.Request.IsRefreshTokenGrantType() &&
                !context.Request.IsPasswordGrantType() && !context.Request.IsClientCredentialsGrantType()) {
                logger.LogWarning("The following grant '{Grant}' is not supported.", context.Request.GrantType);
                context.Reject(
                    error: OpenIdConnectConstants.Errors.UnsupportedGrantType,
                    description: "Only authorization code, refresh token, client credentials " +
                                 "and password grants are accepted by this authorization server.");

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
                logger.LogDebug("The client_id is missing, skipping client authentication");
                context.Skip();

                return;
            }

            // Retrieve the application details corresponding to the requested client_id.
            var application = await services.Applications.FindApplicationByIdAsync(context.ClientId);
            if (application == null) {
                logger.LogWarning("Application not found in the database with client_id '{ClientId}'.", context.ClientId);
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Application not found in the database: ensure that your client_id is correct.");

                return;
            }

            // Reject tokens requests containing a client_secret if the client application is not confidential.
            if (await services.Applications.IsPublicApplicationAsync(application) && !string.IsNullOrEmpty(context.ClientSecret)) {
                logger.LogWarning("Public application '{ClientId}' is not allowed to send a client secret.", context.ClientId);
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "Public clients are not allowed to send a client_secret.");

                return;
            }

            // Confidential applications MUST authenticate
            // to protect them from impersonation attacks.
            else if (await services.Applications.IsConfidentialApplicationAsync(application)) {
                if (string.IsNullOrEmpty(context.ClientSecret)) {
                    logger.LogWarning("Confidential application '{ClientId}' must specify a client secret.", context.ClientId);
                    context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidClient,
                        description: "Missing credentials: ensure that you specified a client_secret.");

                    return;
                }

                if (!await services.Applications.ValidateSecretAsync(application, context.ClientSecret)) {
                    logger.LogWarning("Confidential application '{ClientId}' must specify a valid client secret.", context.ClientId);
                    context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidClient,
                        description: "Invalid credentials: ensure that you specified a correct client_secret.");

                    return;
                }
            }

            context.Validate();
            logger.LogInformation("The token request was successfully validated.");
        }

        public override async Task GrantClientCredentials([NotNull] GrantClientCredentialsContext context) {
            var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TUser, TApplication>>();
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<OpenIddictProvider<TUser, TApplication>>>();

            // Retrieve the application details corresponding to the requested client_id.
            var application = await services.Applications.FindApplicationByIdAsync(context.ClientId);
            if (application == null) {
                logger.LogDebug("There was an error finding application for client_id '{ClientId}', the current application is null, throwing exception.", context.ClientId);
                throw new InvalidOperationException("There was an error finding application.");
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

            logger.LogDebug("An authentication ticket was successfully generated for application {ClientId}.", context.ClientId);

            ticket.SetResources(context.Request.GetResources());
            ticket.SetScopes(context.Request.GetScopes());

            context.Validate(ticket);
            logger.LogInformation("The grant client credentials request was successfully validated.");
        }

        public override async Task GrantRefreshToken([NotNull] GrantRefreshTokenContext context) {
            var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TUser, TApplication>>();
            var options = context.HttpContext.RequestServices.GetRequiredService<IOptions<IdentityOptions>>();
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<OpenIddictProvider<TUser, TApplication>>>();

            var principal = context.Ticket?.Principal;
            if (principal == null) {
                logger.LogDebug("The AuthenticationTicket's principal is null, throwing exception.");
                throw new InvalidOperationException("The current principal is null");
            }

            var user = await services.Users.GetUserAsync(principal);
            if (user == null) {
                logger.LogWarning("There was an error finding the user '{NameIdentifier}'.", principal.FindFirstValue(ClaimTypes.NameIdentifier));
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidGrant,
                    description: "The refresh token is no longer valid.");

                return;
            }

            // If the user manager supports security stamps,
            // ensure that the refresh token is still valid.
            if (services.Users.SupportsUserSecurityStamp) {
                var identifier = principal.GetClaim(options.Value.ClaimsIdentity.SecurityStampClaimType);
                if (!string.IsNullOrEmpty(identifier) &&
                    !string.Equals(identifier, await services.Users.GetSecurityStampAsync(user), StringComparison.Ordinal)) {
                    logger.LogWarning("Security stamp does not match for the user '{NameIdentifier}'.", principal.FindFirstValue(ClaimTypes.NameIdentifier));
                    context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidGrant,
                        description: "The refresh token is no longer valid.");

                    return;
                }
            }

            // Note: the "scopes" property stored in context.AuthenticationTicket is automatically
            // updated by ASOS when the client application requests a restricted scopes collection.
            var identity = await services.Applications.CreateIdentityAsync(user, context.Ticket.GetScopes());
            if (identity == null) {
                logger.LogDebug("CreateIdentityAsync returned null for user '{NameIdentifier}', throwing exception", principal.FindFirstValue(ClaimTypes.NameIdentifier));
                throw new InvalidOperationException("There was an error during identity creation.");
            }

            // Create a new authentication ticket holding the user identity but
            // reuse the authentication properties stored in the refresh token.
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                context.Ticket.Properties,
                context.Options.AuthenticationScheme);

            logger.LogDebug("An authentication ticket was successfully generated for user '{NameIdentifier}'.", principal.FindFirstValue(ClaimTypes.NameIdentifier));

            context.Validate(ticket);
            logger.LogInformation("The refresh token request was successfully validated.");
        }

        public override async Task GrantResourceOwnerCredentials([NotNull] GrantResourceOwnerCredentialsContext context) {
            var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TUser, TApplication>>();
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<OpenIddictProvider<TUser, TApplication>>>();

            var user = await services.Users.FindByNameAsync(context.UserName);
            if (user == null) {
                logger.LogWarning("No user found with name '{UserName}'.", context.UserName);
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidGrant,
                    description: "Invalid credentials.");

                return;
            }

            // Ensure the user is allowed to sign in.
            if (!await services.SignIn.CanSignInAsync(user)) {
                logger.LogWarning("The user '{UserName}' is not allowed to sign in.", context.UserName);
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidGrant,
                    description: "The user is not allowed to sign in.");

                return;
            }

            // Ensure the user is not already locked out.
            if (services.Users.SupportsUserLockout && await services.Users.IsLockedOutAsync(user)) {
                logger.LogWarning("The user '{UserName}' is locked out.", context.UserName);
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidGrant,
                    description: "Account locked out.");

                return;
            }
            
            // Ensure the password is valid.
            if (!await services.Users.CheckPasswordAsync(user, context.Password)) {
                logger.LogWarning("The user '{UserName}' provided password does not match.", context.UserName);
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidGrant,
                    description: "Invalid credentials.");

                if (services.Users.SupportsUserLockout) {
                    logger.LogDebug("Increment user '{UserName}' failed access count.", context.UserName);
                    await services.Users.AccessFailedAsync(user);

                    // Ensure the user is not locked out.
                    if (await services.Users.IsLockedOutAsync(user)) {
                        logger.LogWarning("The user '{UserName}' is locked out.", context.UserName);
                        context.Reject(
                            error: OpenIdConnectConstants.Errors.InvalidGrant,
                            description: "Account locked out.");
                    }
                }

                return;
            }

            if (services.Users.SupportsUserLockout) {
                logger.LogDebug("Reset user '{UserName}' failed access count.", context.UserName);
                await services.Users.ResetAccessFailedCountAsync(user);
            }

            // Reject the token request if two-factor authentication has been enabled by the user.
            if (services.Users.SupportsUserTwoFactor && await services.Users.GetTwoFactorEnabledAsync(user)) {
                logger.LogWarning("Two-factor authentication is required for the user '{UserName}'.", context.UserName);
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
                    logger.LogWarning("The username '{UserName}' correspond to the email address and we carefully avoid leaking the user email if the 'email' scope is not requested.", username);
                    context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidRequest,
                        description: "The 'email' scope is required.");

                    return;
                }
            }

            var identity = await services.Applications.CreateIdentityAsync(user, context.Request.GetScopes());
            if (identity == null) {
                logger.LogDebug("CreateIdentityAsync returned null for user '{UserName}', throwing exception", context.UserName);
                throw new InvalidOperationException("There was an error during identity creation.");
            }

            // Create a new authentication ticket holding the user identity.
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                context.Options.AuthenticationScheme);

            ticket.SetResources(context.Request.GetResources());
            ticket.SetScopes(context.Request.GetScopes());

            logger.LogDebug("An authentication ticket was successfully generated for user '{UserName}'.", context.UserName);

            context.Validate(ticket);
            logger.LogInformation("The resource owner password credentials request was successfully validated.");
        }
    }
}