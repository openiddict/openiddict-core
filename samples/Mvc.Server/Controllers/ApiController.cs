using System.Threading.Tasks;
using AspNet.Security.OAuth.Validation;
using AspNet.Security.OpenIdConnect.Extensions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Mvc.Server.Models;
using Newtonsoft.Json.Linq;
using OpenIddict;

namespace Mvc.Server.Controllers {
    [Route("api")]
    public class ApiController : Controller {
        private readonly UserManager<ApplicationUser> _userManager;

        public ApiController(UserManager<ApplicationUser> userManager) {
            _userManager = userManager;
        }

        //
        // GET: /api/userinfo
        [Authorize(ActiveAuthenticationSchemes = OAuthValidationDefaults.AuthenticationScheme)]
        [HttpGet("userinfo"), Produces("application/json")]
        public async Task<IActionResult> Userinfo() {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) {
                return BadRequest(new OpenIdConnectResponse {
                    Error = OpenIdConnectConstants.Errors.InvalidGrant,
                    ErrorDescription = "The user profile is no longer available."
                });
            }

            var claims = new JObject();

            // Note: the "sub" claim is a mandatory claim and must be included in the JSON response.
            claims[OpenIdConnectConstants.Claims.Subject] = user.Id.ToString();
            claims[OpenIdConnectConstants.Claims.PreferredUsername] = user.UserName;

            if (User.HasClaim(OpenIdConnectConstants.Claims.Scope, OpenIdConnectConstants.Scopes.Email)) {
                claims[OpenIdConnectConstants.Claims.Email] = user.Email;
                claims[OpenIdConnectConstants.Claims.EmailVerified] = user.EmailConfirmed;
            }

            if (User.HasClaim(OpenIdConnectConstants.Claims.Scope, OpenIdConnectConstants.Scopes.Phone)) {
                claims[OpenIdConnectConstants.Claims.PhoneNumber] = user.PhoneNumber;
                claims[OpenIdConnectConstants.Claims.PhoneNumberVerified] = user.PhoneNumberConfirmed;
            }

            if (User.HasClaim(OpenIdConnectConstants.Claims.Scope, OpenIddictConstants.Scopes.Roles)) {
                claims[OpenIddictConstants.Claims.Roles] = JArray.FromObject(await _userManager.GetRolesAsync(user));
            }

            // Note: the complete list of standard claims supported by the OpenID Connect specification
            // can be found here: http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims

            return Json(claims);
        }
    }
}