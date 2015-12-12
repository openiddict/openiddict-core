using System.Security.Claims;
using AspNet.Security.OAuth.Validation;
using Microsoft.AspNet.Authorization;
using Microsoft.AspNet.Mvc;

namespace Mvc.Server.Controllers {
    [Route("api")]
    public class ResourceController : Controller {
        [Authorize(ActiveAuthenticationSchemes = OAuthValidationDefaults.AuthenticationScheme)]
        [HttpGet("message")]
        public IActionResult GetMessage() {
            var identity = User.Identity as ClaimsIdentity;
            if (identity == null) {
                return HttpBadRequest();
            }

            return Content($"{identity.Name} has been successfully authenticated.");
        }
    }
}