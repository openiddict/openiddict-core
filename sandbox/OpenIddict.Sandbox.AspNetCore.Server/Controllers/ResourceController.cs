using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Sandbox.AspNetCore.Server.Models;
using OpenIddict.Abstractions;
using OpenIddict.Validation.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddict.Sandbox.AspNetCore.Server.Controllers;

[Route("api")]
public class ResourceController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;

    public ResourceController(UserManager<ApplicationUser> userManager)
        => _userManager = userManager;

    [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
    [HttpGet("message")]
    public async Task<IActionResult> GetMessage()
    {
        // This demo action requires that the client application be granted the "demo_api" scope.
        // If it was not granted, a detailed error is returned to the client application to inform it
        // that the authorization process must be restarted with the specified scope to access this API.
        if (!User.HasScope("demo_api"))
        {
            return Forbid(
                authenticationSchemes: OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string>
                {
                    [OpenIddictValidationAspNetCoreConstants.Properties.Scope] = "demo_api",
                    [OpenIddictValidationAspNetCoreConstants.Properties.Error] = Errors.InsufficientScope,
                    [OpenIddictValidationAspNetCoreConstants.Properties.ErrorDescription] =
                        "The 'demo_api' scope is required to perform this action."
                }));
        }

        var user = await _userManager.GetUserAsync(User);
        if (user is null)
        {
            return Challenge(
                authenticationSchemes: OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string>
                {
                    [OpenIddictValidationAspNetCoreConstants.Properties.Error] = Errors.InvalidToken,
                    [OpenIddictValidationAspNetCoreConstants.Properties.ErrorDescription] =
                        "The specified access token is bound to an account that no longer exists."
                }));
        }

        return Content($"{user.UserName} has been successfully authenticated.");
    }
}
