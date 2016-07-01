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
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace OpenIddict.Infrastructure {
    public partial class OpenIddictProvider<TUser, TApplication, TAuthorization, TScope, TToken> : OpenIdConnectServerProvider
        where TUser : class where TApplication : class where TAuthorization : class where TScope : class where TToken : class {
        public override async Task ValidateLogoutRequest([NotNull] ValidateLogoutRequestContext context) {
            var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TUser, TApplication, TAuthorization, TScope, TToken>>();

            // Skip validation if the optional post_logout_redirect_uri
            // parameter was missing from the logout request.
            if (string.IsNullOrEmpty(context.PostLogoutRedirectUri)) {
                services.Logger.LogInformation("The logout request validation process was skipped because " +
                                               "the post_logout_redirect_uri parameter was missing.");

                context.Skip();

                return;
            }

            var application = await services.Applications.FindByLogoutRedirectUri(context.PostLogoutRedirectUri);
            if (application == null) {
                services.Logger.LogError("The logout request was rejected because the client application corresponding " +
                                         "to the specified post_logout_redirect_uri was not found in the database: " +
                                         "'{PostLogoutRedirectUri}'.", context.PostLogoutRedirectUri);

                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Invalid post_logout_redirect_uri.");

                return;
            }

            context.Validate();
        }

        public override async Task HandleLogoutRequest([NotNull] HandleLogoutRequestContext context) {
            var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TUser, TApplication, TAuthorization, TScope, TToken>>();

            // Only validate the id_token_hint if the user is still logged in.
            // If the authentication cookie doesn't exist or is no longer valid,
            // the user agent is immediately redirected to the client application.
            if (context.HttpContext.User.Identities.Any(identity => identity.IsAuthenticated)) {
                // Ensure that the authentication cookie contains the required ClaimTypes.NameIdentifier claim.
                // If it cannot be found, don't handle the logout request at this stage and continue to the next middleware.
                var identifier = context.HttpContext.User.GetClaim(ClaimTypes.NameIdentifier);
                if (string.IsNullOrEmpty(identifier)) {
                    services.Logger.LogWarning("The logout request was not silently processed because the mandatory " +
                                               "ClaimTypes.NameIdentifier claim was missing from the current principal.");

                    context.SkipToNextMiddleware();

                    return;
                }

                // When the client application sends an id_token_hint parameter, the corresponding identity can be retrieved using
                // AuthenticateAsync and used as a way to determine whether the logout request has been sent by a legit caller.
                // If the token cannot be extracted, don't handle the logout request at this stage and continue to the next middleware.
                var principal = await context.HttpContext.Authentication.AuthenticateAsync(context.Options.AuthenticationScheme);
                if (principal == null) {
                    services.Logger.LogInformation("The logout request was not silently processed because " +
                                                   "the id_token_hint parameter was missing or invalid.");

                    context.SkipToNextMiddleware();

                    return;
                }

                // Ensure that the identity token corresponds to the authenticated user. If the token cannot be
                // validated, don't handle the logout request at this stage and continue to the next middleware.
                if (!principal.HasClaim(ClaimTypes.NameIdentifier, identifier)) {
                    services.Logger.LogWarning("The logout request was not silently processed because the principal extracted " +
                                               "from the id_token_hint parameter didn't correspond to the logged in user.");

                    context.SkipToNextMiddleware();

                    return;
                }

                services.Logger.LogInformation("The user '{Username}' was successfully logged out.",
                                               services.Users.GetUserName(principal));

                // Delete the ASP.NET Core Identity cookies.
                await services.SignIn.SignOutAsync();
            }

            services.Logger.LogDebug("The logout request was silently processed without requiring user confirmation.");

            // Redirect the user agent back to the client application.
            await context.HttpContext.Authentication.SignOutAsync(context.Options.AuthenticationScheme);

            // Mark the response as handled
            // to skip the rest of the pipeline.
            context.HandleResponse();
        }

        public override Task ApplyLogoutResponse([NotNull] ApplyLogoutResponseContext context) {
            var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TUser, TApplication, TAuthorization, TScope, TToken>>();

            if (!string.IsNullOrEmpty(context.Response.Error) && services.Options.ErrorHandlingPath.HasValue) {
                // Rewrite the request path to point to the error handler path.
                context.HttpContext.Request.Path = services.Options.ErrorHandlingPath;

                // Replace the default status code to return a 400 response.
                context.HttpContext.Response.StatusCode = 400;

                // Store the OpenID Connect response in the HTTP context to allow retrieving it
                // from user code (e.g from an ASP.NET Core MVC controller or a Nancy module).
                context.HttpContext.SetOpenIdConnectResponse(context.Response);

                context.SkipToNextMiddleware();
            }

            return Task.FromResult(0);
        }
    }
}