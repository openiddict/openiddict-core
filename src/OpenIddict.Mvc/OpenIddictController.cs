/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace OpenIddict.Mvc {
    // Note: this controller is generic and doesn't need to be marked as internal to prevent MVC from discovering it.
    public class OpenIddictController<TUser, TApplication> : Controller where TUser : class where TApplication : class {
        public OpenIddictController(
            [NotNull] OpenIddictManager<TUser, TApplication> manager,
            [NotNull] OpenIddictOptions options) {
            Manager = manager;
            Options = options;
        }

        /// <summary>
        /// Gets the OpenIddict manager used by the controller.
        /// </summary>
        protected virtual OpenIddictManager<TUser, TApplication> Manager { get; }

        /// <summary>
        /// Gets the OpenIddict options used by the server.
        /// </summary>
        protected virtual OpenIddictOptions Options { get; }

        [HttpGet, HttpPost]
        public virtual async Task<IActionResult> Authorize() {
            // Note: when a fatal error occurs during the request processing, an OpenID Connect response
            // is prematurely forged and added to the ASP.NET context by OpenIdConnectServerHandler.
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
                return new ChallengeResult(new AuthenticationProperties {
                    RedirectUri = Url.Action(nameof(Authorize), new {
                        request_id = request.GetRequestIdentifier()
                    })
                });
            }

            // Note: ASOS automatically ensures that an application corresponds to the client_id specified
            // in the authorization request by calling IOpenIdConnectServerProvider.ValidateAuthorizationRequest.
            // In theory, this null check shouldn't be needed, but a race condition could occur if you
            // manually removed the application details from the database after the initial check made by ASOS.
            var application = await Manager.FindApplicationByIdAsync(request.ClientId);
            if (application == null) {
                return View("Error", new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidClient,
                    ErrorDescription = "Details concerning the calling client application cannot be found in the database"
                });
            }

            return View("Authorize", Tuple.Create(request, await Manager.GetDisplayNameAsync(application)));
        }

        [Authorize, HttpPost, ValidateAntiForgeryToken]
        public virtual async Task<IActionResult> Accept() {
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
            var user = await Manager.GetUserAsync(User);
            if (user == null) {
                return View("Error", new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.ServerError,
                    ErrorDescription = "An internal error has occurred"
                });
            }

            // Create a new ClaimsIdentity containing the claims that
            // will be used to create an id_token, a token or a code.
            var identity = await Manager.CreateIdentityAsync(user, request.GetScopes());
            Debug.Assert(identity != null);

            // Note: AspNet.Security.OpenIdConnect.Server automatically ensures an application
            // corresponds to the client_id specified in the authorization request using
            // IOpenIdConnectServerProvider.ValidateClientRedirectUri (see OpenIddictProvider.cs).
            var application = await Manager.FindApplicationByIdAsync(request.ClientId);

            // In theory, this null check is thus not strictly necessary. That said, a race condition
            // and a null reference exception could appear here if you manually removed the application
            // details from the database after the initial check made by AspNet.Security.OpenIdConnect.Server.
            if (application == null) {
                return View("Error", new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.InvalidClient,
                    ErrorDescription = "Details concerning the calling client application cannot be found in the database"
                });
            }

            // Create a new ClaimsIdentity containing the claims associated with the application.
            // Note: setting identity.Actor is not mandatory but can be useful to access
            // the whole delegation chain from the resource server (see ResourceController.cs).
            identity.Actor = new ClaimsIdentity(Options.AuthenticationScheme);
            identity.Actor.AddClaim(ClaimTypes.NameIdentifier, request.ClientId);

            identity.Actor.AddClaim(ClaimTypes.Name, await Manager.GetDisplayNameAsync(application),
                OpenIdConnectConstants.Destinations.AccessToken,
                OpenIdConnectConstants.Destinations.IdentityToken);

            // Create a new authentication ticket holding the user identity.
            var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), null, Options.AuthenticationScheme);
            ticket.SetResources(request.GetResources());
            ticket.SetScopes(request.GetScopes());

            // This call will ask ASOS to serialize the specified identity to build appropriate tokens.
            // Note: you should always make sure the identities you return contain ClaimTypes.NameIdentifier claim.
            // In this sample, the identity always contains the name identifier returned by the external provider.
            await HttpContext.Authentication.SignInAsync(ticket.AuthenticationScheme, ticket.Principal, ticket.Properties);

            return new EmptyResult();
        }

        [Authorize, HttpPost, ValidateAntiForgeryToken]
        public virtual async Task<IActionResult> Deny() {
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

            // Notify ASOS that the authorization grant has been denied by the resource owner.
            // Note: OpenIdConnectServerHandler will automatically take care of redirecting
            // the user agent to the client application using the appropriate response_mode.
            await HttpContext.Authentication.ForbidAsync(Options.AuthenticationScheme);

            return new EmptyResult();
        }

        [HttpGet]
        public virtual async Task<ActionResult> Logout() {
            var response = HttpContext.GetOpenIdConnectResponse();
            if (response != null) {
                return View("Error", response);
            }

            // When invoked, the logout endpoint might receive an unauthenticated request if the server cookie has expired.
            // When the client application sends an id_token_hint parameter, the corresponding identity can be retrieved
            // using AuthenticateAsync or using User when the authorization server is declared as AuthenticationMode.Active.
            var identity = await HttpContext.Authentication.AuthenticateAsync(Options.AuthenticationScheme);

            var request = HttpContext.GetOpenIdConnectRequest();
            if (request == null) {
                return View("Error", new OpenIdConnectMessage {
                    Error = OpenIdConnectConstants.Errors.ServerError,
                    ErrorDescription = "An internal error has occurred"
                });
            }

            return View("Logout", Tuple.Create(request, identity));
        }

        [HttpPost, ValidateAntiForgeryToken]
        public virtual async Task Logout(CancellationToken cancellationToken) {
            // Instruct the cookies middleware to delete the local cookie created
            // when the user agent is redirected from the external identity provider
            // after a successful authentication flow (e.g Google or Facebook).
            await HttpContext.Authentication.SignOutAsync("Microsoft.AspNetCore.Identity.Application");

            // Redirect the user agent to the post_logout_redirect_uri specified by the client application.
            await HttpContext.Authentication.SignOutAsync(Options.AuthenticationScheme);
        }
    }
}