using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace OpenIddict.Infrastructure {
    public class OpenIddictMiddleware<TUser, TApplication, TAuthorization, TScope, TToken>
        where TUser : class where TApplication : class
        where TAuthorization : class where TScope : class where TToken : class {
        private readonly RequestDelegate next;

        public OpenIddictMiddleware([NotNull] RequestDelegate next) {
            this.next = next;
        }

        public async Task Invoke([NotNull] HttpContext context) {
            // Invoke the rest of the pipeline to allow handling
            // authorization, logout or token requests in user code.
            await next(context);

            // If the request was already handled, skip the default logic.
            if (context.Response.HasStarted || context.Response.StatusCode != 404) {
                return;
            }

            // If the request doesn't correspond to an OpenID Connect request, ignore it.
            var request = context.GetOpenIdConnectRequest();
            if (request == null || (!request.IsAuthorizationRequest() &&
                                    !request.IsLogoutRequest() &&
                                    !request.IsTokenRequest())) {
                return;
            }

            // If an OpenID Connect response was already prepared, bypass the default logic.
            var response = context.GetOpenIdConnectResponse();
            if (response != null) {
                return;
            }

            // Resolve the OpenIddict services from the scoped container.
            var services = context.RequestServices.GetRequiredService<OpenIddictServices<
                TUser, TApplication, TAuthorization, TScope, TToken>>();

            // Reset the response status code to allow the OpenID Connect server
            // middleware to apply a challenge, signin or logout response.
            context.Response.StatusCode = 200;

            ClaimsPrincipal principal = null;

            if (request.IsAuthorizationRequest()) {
                // If the user is not logged in, return a challenge response.
                if (!context.User.Identities.Any(identity => identity.IsAuthenticated)) {
                    await context.Authentication.ChallengeAsync();

                    return;
                }

                // Retrieve the profile of the logged in user. If the user
                // cannot be found, return a challenge response.
                var user = await services.Users.GetUserAsync(context.User);
                if (user == null) {
                    await context.Authentication.ChallengeAsync();

                    return;
                }

                services.Logger.LogInformation("The authorization request was handled without asking for user consent.");

                principal = new ClaimsPrincipal(await services.Users.CreateIdentityAsync(user, request.GetScopes()));
            }

            else if (request.IsLogoutRequest()) {
                // Ask ASP.NET Core Identity to delete the local and external cookies created
                // when the user agent is redirected from the external identity provider
                // after a successful authentication flow (e.g Google or Facebook).
                await services.SignIn.SignOutAsync();

                await context.Authentication.SignOutAsync(services.Options.AuthenticationScheme);

                services.Logger.LogInformation("The logout request was handled without asking for user consent.");

                return;
            }

            else if (request.IsTokenRequest()) {
                Debug.Assert(request.IsClientCredentialsGrantType() || request.IsPasswordGrantType(),
                             "Only grant_type=client_credentials and grant_type=password requests should be handled here.");

                services.Logger.LogInformation("The token request was automatically handled.");

                if (request.IsClientCredentialsGrantType()) {
                    // Retrieve the application details corresponding to the requested client_id.
                    // Note: this call shouldn't return a null instance, but a race condition may occur
                    // if the application was removed after the initial check made by ValidateTokenRequest.
                    var application = await services.Applications.FindByClientIdAsync(request.ClientId);
                    if (application == null) {
                        services.Logger.LogError("The token request was aborted because the client application " +
                                                 "was not found in the database: '{ClientId}'.", request.ClientId);

                        await context.Authentication.ForbidAsync(services.Options.AuthenticationScheme);

                        return;
                    }

                    var identity = new ClaimsIdentity(services.Options.AuthenticationScheme);

                    // Note: the name identifier is always included in both identity and
                    // access tokens, even if an explicit destination is not specified.
                    identity.AddClaim(ClaimTypes.NameIdentifier, request.ClientId);

                    identity.AddClaim(ClaimTypes.Name, await services.Applications.GetDisplayNameAsync(application),
                        OpenIdConnectConstants.Destinations.AccessToken,
                        OpenIdConnectConstants.Destinations.IdentityToken);

                    principal = new ClaimsPrincipal(identity);
                }

                else if (request.IsPasswordGrantType()) {
                    // Retrieve the user profile corresponding to the specified username.
                    var user = await services.Users.FindByNameAsync(request.Username);
                    if (user == null) {
                        services.Logger.LogError("The token request was rejected because no user profile corresponding to " +
                                                 "the specified username was found: '{Username}'.", request.Username);

                        await context.Authentication.ForbidAsync(services.Options.AuthenticationScheme);

                        return;
                    }

                    // Ensure the username/password couple is valid.
                    if (!await services.Users.CheckPasswordAsync(user, request.Password)) {
                        services.Logger.LogError("The token request was rejected because the password didn't match " +
                                                 "the password associated with the account '{Username}'.", request.Username);

                        if (services.Users.SupportsUserLockout) {
                            await services.Users.AccessFailedAsync(user);

                            if (await services.Users.IsLockedOutAsync(user)) {
                                services.Logger.LogError("The token request was rejected because the account '{Username}' " +
                                                         "was locked out to prevent brute force attacks.", request.Username);
                            }
                        }

                        await context.Authentication.ForbidAsync(services.Options.AuthenticationScheme);

                        return;
                    }

                    if (services.Users.SupportsUserLockout) {
                        await services.Users.ResetAccessFailedCountAsync(user);
                    }

                    principal = new ClaimsPrincipal(await services.Users.CreateIdentityAsync(user, request.GetScopes()));
                }
            }

            // At this stage, don't alter the response
            // if a sign-in operation can't be performed.
            if (principal != null) {
                // Create a new authentication ticket holding the user identity.
                var ticket = new AuthenticationTicket(
                    principal, new AuthenticationProperties(),
                    services.Options.AuthenticationScheme);

                ticket.SetResources(request.GetResources());
                ticket.SetScopes(request.GetScopes());

                await context.Authentication.SignInAsync(ticket.AuthenticationScheme, ticket.Principal, ticket.Properties);
            }
        }
    }
}
