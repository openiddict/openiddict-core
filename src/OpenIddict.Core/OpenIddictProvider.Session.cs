/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

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

            // When the client application sends an id_token_hint parameter, the corresponding identity can be retrieved using
            // AuthenticateAsync and used as a way to determine whether the logout request has been sent by a legit caller.
            // If the token cannot be extracted, don't handle the logout request at this stage and continue to the next middleware.
            var principal = await context.HttpContext.Authentication.AuthenticateAsync(context.Options.AuthenticationScheme);
            if (principal == null) {
                return;
            }

            // Ensure that the identity token corresponds to the authenticated user. If the token cannot be
            // validated, don't handle the logout request at this stage and continue to the next middleware.
            if (!principal.HasClaim(ClaimTypes.NameIdentifier, context.HttpContext.User.GetClaim(ClaimTypes.NameIdentifier))) {
                return;
            }

            // Immediately sign out the user and redirect him
            // to the post_logout_redirect_uri if provided.
            await services.SignIn.SignOutAsync();
            await context.HttpContext.Authentication.SignOutAsync(context.Options.AuthenticationScheme);

            // Mark the response as handled
            // to skip the rest of the pipeline.
            context.HandleResponse();
        }
    }
}