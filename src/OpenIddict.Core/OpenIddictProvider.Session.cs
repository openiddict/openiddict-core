/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace OpenIddict {
    public partial class OpenIddictProvider<TUser, TApplication> : OpenIdConnectServerProvider where TUser : class where TApplication : class {
        public override async Task ValidateLogoutRequest([NotNull] ValidateLogoutRequestContext context) {
            var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TUser, TApplication>>();
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<OpenIddictProvider<TUser, TApplication>>>();

            // Skip validation if the optional post_logout_redirect_uri
            // parameter was missing from the logout request.
            if (string.IsNullOrEmpty(context.PostLogoutRedirectUri)) {
                logger.LogDebug("The current logout request is missing the 'post_logout_redirect_uri' parameter, skipping validation.");
                context.Skip();

                return;
            }

            var application = await services.Applications.FindApplicationByLogoutRedirectUri(context.PostLogoutRedirectUri);
            if (application == null) {
                logger.LogWarning("Application not found in the database with post_logout_redirect_uri of '{PostLogoutRedirectUri}'.", context.PostLogoutRedirectUri);
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Invalid post_logout_redirect_uri.");

                return;
            }

            context.Validate();
            logger.LogInformation("The logout request was successfully validated.");
        }

        public override async Task HandleLogoutRequest([NotNull] HandleLogoutRequestContext context) {
            var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TUser, TApplication>>();
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<OpenIddictProvider<TUser, TApplication>>>();

            // Only validate the id_token_hint if the user is still logged in.
            // If the authentication cookie doesn't exist or is no longer valid,
            // the user agent is immediately redirected to the client application.
            if (context.HttpContext.User.Identities.Any(identity => identity.IsAuthenticated)) {
                // Ensure that the authentication cookie contains the required NameIdentifier claim.
                // If it cannot be found, ignore the logout request and continue to the next middleware.
                var identifier = context.HttpContext.User.GetClaim(ClaimTypes.NameIdentifier);
                if (string.IsNullOrEmpty(identifier)) {
                    logger.LogWarning("The current user does not have the '{NameIdentifier}' claim, ignoring the logout request.", ClaimTypes.NameIdentifier);
                    return;
                }

                // When the client application sends an id_token_hint parameter, the corresponding identity can be retrieved using
                // AuthenticateAsync and used as a way to determine whether the logout request has been sent by a legit caller.
                // If the token cannot be extracted, don't handle the logout request at this stage and continue to the next middleware.
                var principal = await context.HttpContext.Authentication.AuthenticateAsync(context.Options.AuthenticationScheme);
                if (principal == null) {
                    logger.LogWarning("The current user '{NameIdentifier}' cannot be logged out, ignoring the logout request.", identifier);
                    return;
                }

                // Ensure that the identity token corresponds to the authenticated user. If the token cannot be
                // validated, don't handle the logout request at this stage and continue to the next middleware.
                if (!principal.HasClaim(ClaimTypes.NameIdentifier, identifier)) {
                    logger.LogWarning("The current user '{NameIdentifier}' does not correspond to the authenticated user, ignoring the logout request.", identifier);
                    return;
                }

                // Delete the ASP.NET Core Identity cookies.
                await services.SignIn.SignOutAsync();
            } else {
                logger.LogDebug("No authenticated identities found to sign out");
            }

            // Redirect the user agent back to the client application.
            await context.HttpContext.Authentication.SignOutAsync(context.Options.AuthenticationScheme);

            // Mark the response as handled
            // to skip the rest of the pipeline.
            context.HandleResponse();
            logger.LogInformation("The logout request was successfully handled.");
        }
    }
}