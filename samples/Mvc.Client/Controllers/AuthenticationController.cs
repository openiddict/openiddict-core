using System.Threading.Tasks;
using Microsoft.AspNet.Authentication.Cookies;
using Microsoft.AspNet.Authentication.OpenIdConnect;
using Microsoft.AspNet.Http.Authentication;
using Microsoft.AspNet.Mvc;

namespace Mvc.Client.Controllers {
    public class AuthenticationController : Controller {
        [HttpGet("~/signin")]
        public ActionResult SignIn() {
            // Instruct the OIDC client middleware to redirect the user agent to the identity provider.
            // Note: the authenticationType parameter must match the value configured in Startup.cs
            return new ChallengeResult(OpenIdConnectDefaults.AuthenticationScheme, new AuthenticationProperties {
                RedirectUri = "/"
            });
        }

        [HttpGet("~/signout"), HttpPost("~/signout")]
        public async Task SignOut() {
            // Instruct the cookies middleware to delete the local cookie created when the user agent
            // is redirected from the identity provider after a successful authorization flow.
            await HttpContext.Authentication.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            // Instruct the OpenID Connect middleware to redirect the user agent to the identity provider to sign out.
            await HttpContext.Authentication.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);
        }
    }
}