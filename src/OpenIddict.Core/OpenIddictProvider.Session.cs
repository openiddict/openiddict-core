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

namespace OpenIddict {
    public partial class OpenIddictProvider<TUser, TApplication> : OpenIdConnectServerProvider where TUser : class where TApplication : class {
        public override async Task ValidateLogoutRequest([NotNull] ValidateLogoutRequestContext context) {
            var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TUser, TApplication>>();

            // Skip validation if the optional post_logout_redirect_uri
            // parameter was missing from the logout request.
            if (string.IsNullOrEmpty(context.PostLogoutRedirectUri)) {
                context.Skip();

                return;
            }

            var application = await services.Applications.FindApplicationByLogoutRedirectUri(context.PostLogoutRedirectUri);
            if (application == null) {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Invalid post_logout_redirect_uri.");

                return;
            }

            context.Validate();
        }

        public override async Task HandleLogoutRequest([NotNull] HandleLogoutRequestContext context) {
            var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TUser, TApplication>>();

            // Only validate the id_token_hint if the user is still logged in.
            // If the authentication cookie doesn't exist or is no longer valid,
            // the user agent is immediately redirected to the client application.
            if (context.HttpContext.User.Identities.Any(identity => identity.IsAuthenticated)) {
                // Ensure that the authentication cookie contains the required NameIdentifier claim.
                // If it cannot be found, ignore the logout request and continue to the next middleware.
                var identifier = context.HttpContext.User.GetClaim(ClaimTypes.NameIdentifier);
                if (string.IsNullOrEmpty(identifier)) {
                    return;
                }

                // When the client application sends an id_token_hint parameter, the corresponding identity can be retrieved using
                // AuthenticateAsync and used as a way to determine whether the logout request has been sent by a legit caller.
                // If the token cannot be extracted, don't handle the logout request at this stage and continue to the next middleware.
                var principal = await context.HttpContext.Authentication.AuthenticateAsync(context.Options.AuthenticationScheme);
                if (principal == null) {
                    return;
                }

                // Ensure that the identity token corresponds to the authenticated user. If the token cannot be
                // validated, don't handle the logout request at this stage and continue to the next middleware.
                if (!principal.HasClaim(ClaimTypes.NameIdentifier, identifier)) {
                    return;
                }

                // Delete the ASP.NET Core Identity cookies.
                await services.SignIn.SignOutAsync();
            }

            // Redirect the user agent back to the client application.
            await context.HttpContext.Authentication.SignOutAsync(context.Options.AuthenticationScheme);

            // Mark the response as handled
            // to skip the rest of the pipeline.
            context.HandleResponse();
        }
    }
}