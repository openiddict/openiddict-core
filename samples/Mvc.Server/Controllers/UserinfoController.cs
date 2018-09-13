using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Mvc.Server.Models;
using Newtonsoft.Json.Linq;
using OpenIddict.Abstractions;
using OpenIddict.Validation;

namespace Mvc.Server.Controllers
{
    [Route("api")]
    public class UserinfoController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public UserinfoController(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        //
        // GET: /api/userinfo
        [Authorize(AuthenticationSchemes = OpenIddictValidationDefaults.AuthenticationScheme)]
        [HttpGet("userinfo"), Produces("application/json")]
        public async Task<IActionResult> Userinfo()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return BadRequest(new OpenIdConnectResponse
                {
                    Error = OpenIddictConstants.Errors.InvalidGrant,
                    ErrorDescription = "The user profile is no longer available."
                });
            }

            var claims = new JObject();

            // Note: the "sub" claim is a mandatory claim and must be included in the JSON response.
            claims[OpenIddictConstants.Claims.Subject] = await _userManager.GetUserIdAsync(user);

            if (User.HasClaim(OpenIddictConstants.Claims.Scope, OpenIddictConstants.Scopes.Email))
            {
                claims[OpenIddictConstants.Claims.Email] = await _userManager.GetEmailAsync(user);
                claims[OpenIddictConstants.Claims.EmailVerified] = await _userManager.IsEmailConfirmedAsync(user);
            }

            if (User.HasClaim(OpenIddictConstants.Claims.Scope, OpenIddictConstants.Scopes.Phone))
            {
                claims[OpenIddictConstants.Claims.PhoneNumber] = await _userManager.GetPhoneNumberAsync(user);
                claims[OpenIddictConstants.Claims.PhoneNumberVerified] = await _userManager.IsPhoneNumberConfirmedAsync(user);
            }

            if (User.HasClaim(OpenIddictConstants.Claims.Scope, OpenIddictConstants.Scopes.Roles))
            {
                claims[OpenIddictConstants.Claims.Roles] = JArray.FromObject(await _userManager.GetRolesAsync(user));
            }

            // Note: the complete list of standard claims supported by the OpenID Connect specification
            // can be found here: http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims

            return Json(claims);
        }
    }
}
