/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Data.Entity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Internal;
using OpenIddict.Models;

namespace OpenIddict {
    public class OpenIddictProvider<TContext, TUser, TRole, TKey> : OpenIdConnectServerProvider
        where TContext : OpenIddictContext<TUser, TRole, TKey>
        where TUser : IdentityUser<TKey>
        where TRole : IdentityRole<TKey>
        where TKey : IEquatable<TKey> {
        public override Task MatchEndpoint([NotNull] MatchEndpointContext context) {
            // Note: by default, OpenIdConnectServerHandler only handles authorization requests made to AuthorizationEndpointPath.
            // This context handler uses a more relaxed policy that allows extracting authorization requests received at
            // /connect/authorize/accept and /connect/authorize/deny (see OpenIddictController.cs for more information).
            if (context.Options.AuthorizationEndpointPath.HasValue &&
                context.Request.Path.StartsWithSegments(context.Options.AuthorizationEndpointPath)) {
                context.MatchesAuthorizationEndpoint();
            }

            return Task.FromResult<object>(null);
        }

        public override async Task ValidateClientRedirectUri([NotNull] ValidateClientRedirectUriContext context) {
            // Note: redirect_uri is not required for pure OAuth2 requests but this provider uses a stricter
            // policy making it mandatory. Requests missing an explicit redirect_uri are always rejected.
            if (string.IsNullOrEmpty(context.RedirectUri)) {
                context.Rejected(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "The required redirect_uri parameter was missing");

                return;
            }

            var database = context.HttpContext.RequestServices.GetRequiredService<TContext>();

            // Retrieve the application details corresponding to the requested client_id.
            var application = await (from entity in database.Applications
                                     where entity.ApplicationID == context.ClientId
                                     select entity).SingleOrDefaultAsync(context.HttpContext.RequestAborted);

            if (application == null) {
                context.Rejected(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Application not found in the database: ensure that your client_id is correct");

                return;
            }

            if (!string.Equals(context.RedirectUri, application.RedirectUri, StringComparison.Ordinal)) {
                context.Rejected(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Invalid redirect_uri");

                return;
            }

            context.Validated();
        }

        public override async Task ValidateClientLogoutRedirectUri([NotNull] ValidateClientLogoutRedirectUriContext context) {
            var database = context.HttpContext.RequestServices.GetRequiredService<TContext>();

            if (!await database.Applications.AnyAsync(application => application.LogoutRedirectUri == context.PostLogoutRedirectUri)) {
                context.Rejected(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Invalid post_logout_redirect_uri");

                return;
            }

            context.Validated();
        }

        public override async Task ValidateClientAuthentication([NotNull] ValidateClientAuthenticationContext context) {
            // Note: client authentication is not mandatory for non-confidential client applications like mobile apps
            // (except when using the client credentials grant type) but OpenIddict uses a safer policy that makes
            // client authentication mandatory when using the authorization code grant type of the refresh token grant type
            // and returns an error if the client_id and/or the client_secret is/are missing.
            if (context.Request.IsAuthorizationCodeGrantType() || context.Request.IsRefreshTokenGrantType()) {
                if (string.IsNullOrEmpty(context.ClientId) || string.IsNullOrEmpty(context.ClientSecret)) {
                    context.Rejected(
                        error: OpenIdConnectConstants.Errors.InvalidGrant,
                        description: "Missing credentials: ensure that your credentials were correctly " +
                                     "flowed in the request body or in the authorization header");

                    return;
                }
            }

            // Skip client authentication if the client_id is missing.
            if (string.IsNullOrEmpty(context.ClientId)) {
                context.Skipped();

                return;
            }

            var database = context.HttpContext.RequestServices.GetRequiredService<TContext>();

            // Retrieve the application details corresponding to the requested client_id.
            var application = await (from entity in database.Applications
                                     where entity.ApplicationID == context.ClientId
                                     select entity).SingleOrDefaultAsync(context.HttpContext.RequestAborted);

            if (application == null) {
                context.Rejected(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Application not found in the database: ensure that your client_id is correct");

                return;
            }

            // Reject tokens requests containing a client_secret if the client application is not confidential.
            if (application.Type == ApplicationType.Public && !string.IsNullOrEmpty(context.ClientSecret)) {
                context.Rejected(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "Public clients are not allowed to send a client_secret");

                return;
            }

            // Confidential applications MUST authenticate.
            else if (application.Type == ApplicationType.Confidential &&
                !string.Equals(context.ClientSecret, application.Secret, StringComparison.Ordinal)) {
                context.Rejected(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Invalid credentials: ensure that you specified a correct client_secret");

                return;
            }

            context.Validated();
        }

        public override async Task ValidateAuthorizationRequest([NotNull] ValidateAuthorizationRequestContext context) {
            // Only validate prompt=none requests at this stage.
            if (!string.Equals(context.Request.Prompt, "none", StringComparison.Ordinal)) {
                return;
            }

            // Extract the principal contained in the id_token_hint parameter.
            // If no principal can be extracted, an error is returned to the client application.
            var principal = await context.HttpContext.Authentication.AuthenticateAsync(context.Options.AuthenticationScheme);
            if (principal == null) {
                context.Rejected(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "The required id_token_hint parameter is missing");

                return;
            }

            if (!string.Equals(principal.FindFirstValue(JwtRegisteredClaimNames.Aud), context.Request.ClientId)) {
                context.Rejected(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "The id_token_hint parameter is invalid");

                return;
            }

            var manager = context.HttpContext.RequestServices.GetRequiredService<UserManager<TUser>>();

            // Ensure the user still exists.
            var user = await manager.FindByIdAsync(principal.GetUserId());
            if (user == null) {
                context.Rejected(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "The id_token_hint parameter is invalid");

                return;
            }
        }

        public override Task ValidateTokenRequest([NotNull] ValidateTokenRequestContext context) {
            // Note: OpenIdConnectServerHandler supports authorization code, refresh token, client credentials
            // and resource owner password credentials grant types but this authorization server uses a stricter policy
            // rejecting the last one. You may consider relaxing it to support the client credentials grant types.
            if (!context.Request.IsAuthorizationCodeGrantType() &&
                !context.Request.IsRefreshTokenGrantType() &&
                !context.Request.IsPasswordGrantType()) {
                context.Rejected(
                    error: OpenIdConnectConstants.Errors.UnsupportedGrantType,
                    description: "Only authorization code and refresh token grant types " +
                                 "are accepted by this authorization server");
            }

            return Task.FromResult<object>(null);
        }

        public override async Task AuthorizationEndpoint([NotNull] AuthorizationEndpointContext context) {
            // Only handle prompt=none requests at this stage.
            if (!string.Equals(context.Request.Prompt, "none", StringComparison.Ordinal)) {
                return;
            }

            var manager = context.HttpContext.RequestServices.GetRequiredService<UserManager<TUser>>();

            // Note: principal is guaranteed to be non-null since ValidateAuthorizationRequest
            // rejects prompt=none requests missing or having an invalid id_token_hint.
            var principal = await context.HttpContext.Authentication.AuthenticateAsync(context.Options.AuthenticationScheme);
            Debug.Assert(principal != null);

            // Note: user may be null if the user was removed after
            // the initial check made by ValidateAuthorizationRequest.
            // In this case, ignore the prompt=none request and
            // continue to the next middleware in the pipeline.
            var user = await manager.FindByIdAsync(principal.GetUserId());
            if (user == null) {
                return;
            }

            var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
            identity.AddClaim(ClaimTypes.NameIdentifier, user.Id.ToString());

            // Only add the name claim if the "profile" scope was present in the token request.
            if (context.Request.GetScopes().Contains("profile", StringComparer.OrdinalIgnoreCase)) {
                identity.AddClaim(ClaimTypes.Name, user.UserName, destination: "id_token token");
            }

            // Only add the email address if the "email" scope was present in the token request.
            if (context.Request.GetScopes().Contains("email", StringComparer.OrdinalIgnoreCase)) {
                identity.AddClaim(ClaimTypes.Email, user.Email, destination: "id_token token");
            }

            // Call SignInAsync to create and return a new OpenID Connect response containing the serialized code/tokens.
            await context.HttpContext.Authentication.SignInAsync(context.Options.AuthenticationScheme, new ClaimsPrincipal(identity));

            // Mark the response as handled
            // to skip the rest of the pipeline.
            context.HandleResponse();
        }

        public override async Task GrantResourceOwnerCredentials([NotNull] GrantResourceOwnerCredentialsContext context) {
            var manager = context.HttpContext.RequestServices.GetRequiredService<UserManager<TUser>>();

            var user = await manager.FindByNameAsync(context.UserName);
            if (user == null) {
                context.Rejected(
                    error: OpenIdConnectConstants.Errors.InvalidGrant,
                    description: "Invalid credentials");

                return;
            }

            // Ensure the user is not already locked out.
            if (manager.SupportsUserLockout && await manager.IsLockedOutAsync(user)) {
                context.Rejected(
                    error: OpenIdConnectConstants.Errors.InvalidGrant,
                    description: "Account locked out");

                return;
            }
            
            // Ensure the password is valid.
            if (!await manager.CheckPasswordAsync(user, context.Password)) {
                context.Rejected(
                    error: OpenIdConnectConstants.Errors.InvalidGrant,
                    description: "Invalid credentials");

                if (manager.SupportsUserLockout) {
                    await manager.AccessFailedAsync(user);

                    // Ensure the user is not locked out.
                    if (await manager.IsLockedOutAsync(user)) {
                        context.Rejected(
                            error: OpenIdConnectConstants.Errors.InvalidGrant,
                            description: "Account locked out");
                    }
                }

                return;
            }

            if (manager.SupportsUserLockout) { 
                await manager.ResetAccessFailedCountAsync(user);
            }

            var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
            identity.AddClaim(ClaimTypes.NameIdentifier, user.Id.ToString());

            // Only add the name claim if the "profile" scope was present in the token request.
            if (context.Request.GetScopes().Contains("profile", StringComparer.OrdinalIgnoreCase)) {
                identity.AddClaim(ClaimTypes.Name, user.UserName, destination: "id_token token");
            }

            // Only add the email address if the "email" scope was present in the token request.
            if (context.Request.GetScopes().Contains("email", StringComparer.OrdinalIgnoreCase)) {
                identity.AddClaim(ClaimTypes.Email, user.Email, destination: "id_token token");
            }
            
            context.Validated(new ClaimsPrincipal(identity));
        }
    }
}