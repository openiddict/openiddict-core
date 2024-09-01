/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Sandbox.AspNetCore.Client.ViewModels.Shared;

namespace OpenIddict.Sandbox.AspNetCore.Client;

public class ErrorController : Controller
{
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true), Route("~/error")]
    public IActionResult Error()
    {
        // If the error originated from the OpenIddict client, render the error details.
        var response = HttpContext.GetOpenIddictClientResponse();
        if (response is not null)
        {
            return View(new ErrorViewModel
            {
                Error = response.Error,
                ErrorDescription = response.ErrorDescription
            });
        }

        return View(new ErrorViewModel());
    }
}
