using System.Collections.Generic;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using OpenIddict.Validation.Owin;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddict.Sandbox.AspNet.Server.Controllers
{
    public class ResourceController : Controller
    {
        [HttpGet, Route("~/api/message")]
        public async Task<ActionResult> GetMessage()
        {
            var context = HttpContext.GetOwinContext();

            var result = await context.Authentication.AuthenticateAsync(OpenIddictValidationOwinDefaults.AuthenticationType);
            if (result is null)
            {
                context.Authentication.Challenge(OpenIddictValidationOwinDefaults.AuthenticationType);
                return new EmptyResult();
            }

            // This demo action requires that the client application be granted the "demo_api" scope.
            // If it was not granted, a detailed error is returned to the client application to inform it
            // that the authorization process must be restarted with the specified scope to access this API.
            if (!result.Identity.HasClaim(Claims.Private.Scope, "demo_api"))
            {
                context.Authentication.Challenge(
                    authenticationTypes: OpenIddictValidationOwinDefaults.AuthenticationType,
                    properties: new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictValidationOwinConstants.Properties.Scope] = "demo_api",
                        [OpenIddictValidationOwinConstants.Properties.Error] = Errors.InsufficientScope,
                        [OpenIddictValidationOwinConstants.Properties.ErrorDescription] =
                            "The 'demo_api' scope is required to perform this action."
                    }));
                return new EmptyResult();
            }

            var user = await context.GetUserManager<ApplicationUserManager>()
                .FindByIdAsync(result.Identity.FindFirst(Claims.Subject).Value);

            if (user is null)
            {
                context.Authentication.Challenge(
                    authenticationTypes: OpenIddictValidationOwinDefaults.AuthenticationType,
                    properties: new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictValidationOwinConstants.Properties.Error] = Errors.InvalidToken,
                        [OpenIddictValidationOwinConstants.Properties.ErrorDescription] =
                            "The specified access token is bound to an account that no longer exists."
                    }));
                return new EmptyResult();
            }

            return Content($"{user.UserName} has been successfully authenticated.");
        }
    }
}
