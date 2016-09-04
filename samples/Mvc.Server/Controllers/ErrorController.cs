/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using AspNet.Security.OpenIdConnect.Extensions;
using Microsoft.AspNetCore.Mvc;
using Mvc.Server.ViewModels.Shared;

namespace Mvc.Server {
    public class ErrorController : Controller {
        [HttpGet, HttpPost, Route("~/error")]
        public IActionResult Error(OpenIdConnectResponse response) {
            // If the error was not caused by an invalid
            // OIDC request, display a generic error page.
            if (response == null) {
                return View(new ErrorViewModel());
            }

            return View(new ErrorViewModel {
                Error = response.Error,
                ErrorDescription = response.ErrorDescription
            });
        }
    }
}