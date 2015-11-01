/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Internal;

namespace OpenIddict {
    public class OpenIddictProvider<TUser, TApplication> : OpenIdConnectServerProvider where TUser : class where TApplication : class {
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
                    description: "The required redirect_uri parameter was missing.");

                return;
            }

            // Retrieve the application details corresponding to the requested client_id.
            var manager = context.HttpContext.RequestServices.GetRequiredService<OpenIddictManager<TUser, TApplication>>();

            var application = await manager.FindApplicationByIdAsync(context.ClientId);
            if (application == null) {
                context.Rejected(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Application not found in the database: ensure that your client_id is correct.");

                return;
            }

            if (!await manager.ValidateRedirectUriAsync(application, context.RedirectUri)) {
                context.Rejected(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Invalid redirect_uri.");

                return;
            }

            context.Validated();
        }

        public override async Task ValidateClientLogoutRedirectUri([NotNull] ValidateClientLogoutRedirectUriContext context) {
            var manager = context.HttpContext.RequestServices.GetRequiredService<OpenIddictManager<TUser, TApplication>>();

            var application = await manager.FindApplicationByLogoutRedirectUri(context.PostLogoutRedirectUri);
            if (application == null) {
                context.Rejected(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Invalid post_logout_redirect_uri.");

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
                                     "flowed in the request body or in the authorization header.");

                    return;
                }
            }

            // Skip client authentication if the client_id is missing.
            if (string.IsNullOrEmpty(context.ClientId)) {
                context.Skipped();

                return;
            }

            var manager = context.HttpContext.RequestServices.GetRequiredService<OpenIddictManager<TUser, TApplication>>();

            // Retrieve the application details corresponding to the requested client_id.
            var application = await manager.FindApplicationByIdAsync(context.ClientId);
            if (application == null) {
                context.Rejected(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Application not found in the database: ensure that your client_id is correct.");

                return;
            }

            // Reject tokens requests containing a client_secret if the client application is not confidential.
            if (await manager.IsPublicApplicationAsync(application) && !string.IsNullOrEmpty(context.ClientSecret)) {
                context.Rejected(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "Public clients are not allowed to send a client_secret.");

                return;
            }

            // Confidential applications MUST authenticate. Note: this security
            // measure also helps protecting them from impersonation attacks.
            else if (await manager.IsConfidentialApplicationAsync(application)) {
                if (string.IsNullOrEmpty(context.ClientSecret)) {
                    context.Rejected(
                        error: OpenIdConnectConstants.Errors.InvalidClient,
                        description: "Missing credentials: ensure that you specified a client_secret.");

                    return;
                }

                if (!await manager.ValidateSecretAsync(application, context.ClientSecret)) {
                    context.Rejected(
                        error: OpenIdConnectConstants.Errors.InvalidClient,
                        description: "Invalid credentials: ensure that you specified a correct client_secret.");

                    return;
                }
            }

            context.Validated();
        }

        public override async Task ValidateAuthorizationRequest([NotNull] ValidateAuthorizationRequestContext context) {
            var manager = context.HttpContext.RequestServices.GetRequiredService<OpenIddictManager<TUser, TApplication>>();

            // Retrieve the application details corresponding to the requested client_id.
            var application = await manager.FindApplicationByIdAsync(context.ClientContext.ClientId);
            Debug.Assert(application != null);

            // To prevent downgrade attacks, ensure that authorization requests using the hybrid/implicit
            // flow are rejected if the client identifier corresponds to a confidential application.
            if (await manager.IsConfidentialApplicationAsync(application) && !context.Request.IsAuthorizationCodeFlow()) {
                context.Rejected(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "Confidential clients can only use response_type=code.");

                return;
            }

            if (string.Equals(context.Request.Prompt, "none", StringComparison.Ordinal)) {
                // Extract the principal contained in the id_token_hint parameter.
                // If no principal can be extracted, an error is returned to the client application.
                var principal = await context.HttpContext.Authentication.AuthenticateAsync(context.Options.AuthenticationScheme);
                if (principal == null) {
                    context.Rejected(
                        error: OpenIdConnectConstants.Errors.InvalidRequest,
                        description: "The required id_token_hint parameter is missing.");

                    return;
                }

                if (!string.Equals(principal.FindFirstValue(JwtRegisteredClaimNames.Aud), context.Request.ClientId)) {
                    context.Rejected(
                        error: OpenIdConnectConstants.Errors.InvalidRequest,
                        description: "The id_token_hint parameter is invalid.");

                    return;
                }

                // Ensure the user still exists.
                var user = await manager.FindByIdAsync(principal.GetUserId());
                if (user == null) {
                    context.Rejected(
                        error: OpenIdConnectConstants.Errors.InvalidRequest,
                        description: "The id_token_hint parameter is invalid.");

                    return;
                }
            }
        }

        public override Task ValidateTokenRequest([NotNull] ValidateTokenRequestContext context) {
            // Note: OpenIdConnectServerHandler supports authorization code, refresh token, client credentials
            // and resource owner password credentials grant types but this authorization server uses a stricter policy
            // rejecting the last one. You may consider relaxing it to support the client credentials grant types.
            if (!context.Request.IsAuthorizationCodeGrantType() && !context.Request.IsRefreshTokenGrantType() &&
                !context.Request.IsPasswordGrantType() && !context.Request.IsClientCredentialsGrantType()) {
                context.Rejected(
                    error: OpenIdConnectConstants.Errors.UnsupportedGrantType,
                    description: "Only authorization code, refresh token, client credentials " +
                                 "and password grants are accepted by this authorization server.");
            }

            return Task.FromResult<object>(null);
        }

        public override async Task AuthorizationEndpoint([NotNull] AuthorizationEndpointContext context) {
            // Only handle prompt=none requests at this stage.
            if (!string.Equals(context.Request.Prompt, "none", StringComparison.Ordinal)) {
                return;
            }

            var manager = context.HttpContext.RequestServices.GetRequiredService<OpenIddictManager<TUser, TApplication>>();

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
            identity.AddClaim(ClaimTypes.NameIdentifier, await manager.GetUserIdAsync(user));

            // Only add the name claim if the "profile" scope was present in the authorization request.
            // Note: filtering the username is not needed at this stage as OpenIddictController.Accept
            // and OpenIddictProvider.GrantResourceOwnerCredentials are expected to reject requests that
            // don't include the "email" scope if the username corresponds to the registed email address.
            if (context.Request.ContainsScope(OpenIdConnectConstants.Scopes.Profile)) {
                identity.AddClaim(ClaimTypes.Name, await manager.GetUserNameAsync(user), destination: "id_token token");
            }

            // Only add the email address if the "email" scope was present in the authorization request.
            if (context.Request.ContainsScope(OpenIdConnectConstants.Scopes.Email)) {
                identity.AddClaim(ClaimTypes.Email, await manager.GetEmailAsync(user), destination: "id_token token");
            }

            // Call SignInAsync to create and return a new OpenID Connect response containing the serialized code/tokens.
            await context.HttpContext.Authentication.SignInAsync(context.Options.AuthenticationScheme, new ClaimsPrincipal(identity));

            // Mark the response as handled
            // to skip the rest of the pipeline.
            context.HandleResponse();
        }

        public override async Task ProfileEndpoint([NotNull] ProfileEndpointContext context) {
            var manager = context.HttpContext.RequestServices.GetRequiredService<OpenIddictManager<TUser, TApplication>>();

            var principal = context.AuthenticationTicket?.Principal;
            Debug.Assert(principal != null);

            // Note: user may be null if the user has been removed.
            // In this case, return a 400 response.
            var user = await manager.FindByIdAsync(principal.GetUserId());
            if (user == null) {
                context.Response.StatusCode = 400;
                context.HandleResponse();

                return;
            }

            // Note: "sub" is a mandatory claim.
            // See http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
            context.Subject = await manager.GetUserIdAsync(user);

            // Only add the "preferred_username" claim if the "profile" scope was present in the access token.
            // Note: filtering the username is not needed at this stage as OpenIddictController.Accept
            // and OpenIddictProvider.GrantResourceOwnerCredentials are expected to reject requests that
            // don't include the "email" scope if the username corresponds to the registed email address.
            if (principal.HasClaim(OpenIdConnectConstants.Claims.Scope, OpenIdConnectConstants.Scopes.Profile)) {
                context.PreferredUsername = await manager.GetUserNameAsync(user);
                context.FamilyName = await manager.FindClaimAsync(user, ClaimTypes.Surname);
                context.GivenName = await manager.FindClaimAsync(user, ClaimTypes.GivenName);
                context.BirthDate = await manager.FindClaimAsync(user, ClaimTypes.DateOfBirth);
            }

            // Only add the email address details if the "email" scope was present in the access token.
            if (principal.HasClaim(OpenIdConnectConstants.Claims.Scope, OpenIdConnectConstants.Scopes.Email)) {
                context.Email = await manager.GetEmailAsync(user);

                // Only add the "email_verified" claim
                // if the email address is non-null.
                if (!string.IsNullOrEmpty(context.Email)) {
                    context.EmailVerified = await manager.IsEmailConfirmedAsync(user);
                }
            };

            // Only add the phone number details if the "phone" scope was present in the access token.
            if (principal.HasClaim(OpenIdConnectConstants.Claims.Scope, OpenIdConnectConstants.Scopes.Phone)) {
                context.PhoneNumber = await manager.GetPhoneNumberAsync(user);

                // Only add the "phone_number_verified"
                // claim if the phone number is non-null.
                if (!string.IsNullOrEmpty(context.PhoneNumber)) {
                    context.PhoneNumberVerified = await manager.IsPhoneNumberConfirmedAsync(user);
                }
            }
        }

        public override async Task GrantClientCredentials([NotNull] GrantClientCredentialsContext context) {
            var manager = context.HttpContext.RequestServices.GetRequiredService<OpenIddictManager<TUser, TApplication>>();

            // Retrieve the application details corresponding to the requested client_id.
            var application = await manager.FindApplicationByIdAsync(context.ClientId);
            Debug.Assert(application != null);

            var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
            identity.AddClaim(ClaimTypes.NameIdentifier, context.ClientId);
            identity.AddClaim(ClaimTypes.Name, await manager.GetDisplayNameAsync(application));

            context.Validated(new ClaimsPrincipal(identity));
        }

        public override async Task GrantResourceOwnerCredentials([NotNull] GrantResourceOwnerCredentialsContext context) {
            var manager = context.HttpContext.RequestServices.GetRequiredService<OpenIddictManager<TUser, TApplication>>();

            var user = await manager.FindByNameAsync(context.UserName);
            if (user == null) {
                context.Rejected(
                    error: OpenIdConnectConstants.Errors.InvalidGrant,
                    description: "Invalid credentials.");

                return;
            }

            // Ensure the user is not already locked out.
            if (manager.SupportsUserLockout && await manager.IsLockedOutAsync(user)) {
                context.Rejected(
                    error: OpenIdConnectConstants.Errors.InvalidGrant,
                    description: "Account locked out.");

                return;
            }
            
            // Ensure the password is valid.
            if (!await manager.CheckPasswordAsync(user, context.Password)) {
                context.Rejected(
                    error: OpenIdConnectConstants.Errors.InvalidGrant,
                    description: "Invalid credentials.");

                if (manager.SupportsUserLockout) {
                    await manager.AccessFailedAsync(user);

                    // Ensure the user is not locked out.
                    if (await manager.IsLockedOutAsync(user)) {
                        context.Rejected(
                            error: OpenIdConnectConstants.Errors.InvalidGrant,
                            description: "Account locked out.");
                    }
                }

                return;
            }

            if (manager.SupportsUserLockout) { 
                await manager.ResetAccessFailedCountAsync(user);
            }

            var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
            identity.AddClaim(ClaimTypes.NameIdentifier, await manager.GetUserIdAsync(user));

            // Resolve the username and the email address associated with the user.
            var username = await manager.GetUserNameAsync(user);
            var email = await manager.GetEmailAsync(user);

            // Only add the name claim if the "profile" scope was present in the token request.
            if (context.Request.ContainsScope(OpenIdConnectConstants.Scopes.Profile)) {
                // Return an error if the username corresponds to the registered
                // email address and if the "email" scope has not been requested.
                if (!context.Request.ContainsScope(OpenIdConnectConstants.Scopes.Email) &&
                     string.Equals(username, email, StringComparison.OrdinalIgnoreCase)) {
                    context.Rejected(
                        error: OpenIdConnectConstants.Errors.InvalidRequest,
                        description: "The 'email' scope is required.");

                    return;
                }

                identity.AddClaim(ClaimTypes.Name, username, destination: "id_token token");
            }

            // Only add the email address if the "email" scope was present in the token request.
            if (context.Request.ContainsScope(OpenIdConnectConstants.Scopes.Email)) {
                identity.AddClaim(ClaimTypes.Email, email, destination: "id_token token");
            }

            context.Validated(new ClaimsPrincipal(identity));
        }
    }
}