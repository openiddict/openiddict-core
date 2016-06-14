/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace OpenIddict.Mvc {
    // Note: this controller is generic and doesn't need to be marked as internal to prevent MVC from discovering it.
    public class OpenIddictController<TUser, TApplication, TAuthorization, TToken> : Controller
        where TUser : class where TApplication : class where TAuthorization : class where TToken : class {
        [HttpGet, HttpPost]
        public virtual async Task<IActionResult> Authorize([FromServices] OpenIddictApplicationManager<TApplication> applications) {
            // Note: when a fatal error occurs during the request processing, an OpenID Connect response
            // is prematurely forged and added to the ASP.NET Core context by OpenIdConnectServerHandler.
            var response = HttpContext.GetOpenIdConnectResponse();
            if (response != null) {
                return View("Error", response);
            }

            // Extract the authorization request from the ASP.NET environment.
            var request = HttpContext.GetOpenIdConnectRequest();
            if (request == null) {
                return View("Error", new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.ServerError,
                    ErrorDescription = "An internal error has occurred"
                });
            }

            // Note: authentication could be theorically enforced at the filter level via AuthorizeAttribute
            // but this authorization endpoint accepts both GET and POST requests while the cookie middleware
            // only uses 302 responses to redirect the user agent to the login page, making it incompatible with POST.
            // To work around this limitation, the OpenID Connect request is automatically saved in the cache and will be
            // restored by the OpenID Connect server middleware after the external authentication process has been completed.
            if (!User.Identities.Any(identity => identity.IsAuthenticated)) {
                return Challenge(new AuthenticationProperties {
                    RedirectUri = Url.Action(nameof(Authorize), new {
                        request_id = request.GetRequestId()
                    })
                });
            }

            // Note: the OpenID Connect server middleware automatically ensures an application
            // corresponds to the client_id specified in the authorization request using
            // IOpenIdConnectServerProvider.ValidateAuthorizationRequest (see OpenIddictProvider.cs).
            var application = await applications.FindByClientIdAsync(request.ClientId);
            if (application == null) {
                return View("Error", new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidClient,
                    ErrorDescription = "Details concerning the calling client application cannot be found in the database"
                });
            }

            return View("Authorize", Tuple.Create(request, await applications.GetDisplayNameAsync(application)));
        }

        [Authorize, HttpPost, ValidateAntiForgeryToken]
        public virtual async Task<IActionResult> Accept(
            [FromServices] OpenIddictUserManager<TUser> users,
            [FromServices] OpenIddictApplicationManager<TApplication> applications,
            [FromServices] IOptions<OpenIddictOptions> options) {
            var response = HttpContext.GetOpenIdConnectResponse();
            if (response != null) {
                return View("Error", response);
            }

            var request = HttpContext.GetOpenIdConnectRequest();
            if (request == null) {
                return View("Error", new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.ServerError,
                    ErrorDescription = "An internal error has occurred"
                });
            }

            // Retrieve the user data using the unique identifier.
            var user = await users.GetUserAsync(User);
            if (user == null) {
                return View("Error", new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.ServerError,
                    ErrorDescription = "An internal error has occurred"
                });
            }

            // Create a new ClaimsIdentity containing the claims that
            // will be used to create an id_token, a token or a code.
            var identity = await users.CreateIdentityAsync(user, request.GetScopes());
            Debug.Assert(identity != null);

            var application = await applications.FindByClientIdAsync(request.ClientId);
            if (application == null) {
                return View("Error", new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidClient,
                    ErrorDescription = "Details concerning the calling client application cannot be found in the database"
                });
            }

            // Create a new authentication ticket holding the user identity.
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                options.Value.AuthenticationScheme);

            ticket.SetResources(request.GetResources());
            ticket.SetScopes(request.GetScopes());

            // Returning a SignInResult will ask the OpenID Connect server middleware to issue the appropriate tokens.
            // Note: you should always make sure the identities you return contain ClaimTypes.NameIdentifier claim.
            // In this sample, the identity always contains the name identifier returned by the external provider.
            return SignIn(ticket.Principal, ticket.Properties, ticket.AuthenticationScheme);
        }

        [Authorize, HttpPost, ValidateAntiForgeryToken]
        public virtual Task<IActionResult> Deny([FromServices] IOptions<OpenIddictOptions> options) {
            var response = HttpContext.GetOpenIdConnectResponse();
            if (response != null) {
                return Task.FromResult<IActionResult>(View("Error", response));
            }

            var request = HttpContext.GetOpenIdConnectRequest();
            if (request == null) {
                return Task.FromResult<IActionResult>(View("Error", new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.ServerError,
                    ErrorDescription = "An internal error has occurred"
                }));
            }

            // Notify the OpenID Connect server middleware that the authorization grant
            // has been denied by the resource owner to redirect user agent to
            // the client application using the appropriate response_mode.
            return Task.FromResult<IActionResult>(Forbid(options.Value.AuthenticationScheme));
        }

        [HttpGet]
        public virtual Task<IActionResult> Logout() {
            var response = HttpContext.GetOpenIdConnectResponse();
            if (response != null) {
                return Task.FromResult<IActionResult>(View("Error", response));
            }

            var request = HttpContext.GetOpenIdConnectRequest();
            if (request == null) {
                return Task.FromResult<IActionResult>(View("Error", new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.ServerError,
                    ErrorDescription = "An internal error has occurred"
                }));
            }

            return Task.FromResult<IActionResult>(View("Logout", request));
        }

        [ActionName(nameof(Logout)), HttpPost, ValidateAntiForgeryToken]
        public virtual async Task<IActionResult> Signout(
            [FromServices] SignInManager<TUser> signin,
            [FromServices] IOptions<OpenIddictOptions> options) {
            // Instruct the cookies middleware to delete the local cookie created
            // when the user agent is redirected from the external identity provider
            // after a successful authentication flow (e.g Google or Facebook).
            await signin.SignOutAsync();

            // Returning a SignOutResult will ask the OpenID Connect server middleware to redirect
            // the user agent to the post_logout_redirect_uri specified by the client application.
            return SignOut(options.Value.AuthenticationScheme);
        }
    }
}