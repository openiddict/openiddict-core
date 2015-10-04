using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNet.Authorization;
using Microsoft.AspNet.Mvc;

namespace Mvc.Server.Controllers {
    [Route("api")]
    public class ResourceController : Controller {
        [Authorize(ActiveAuthenticationSchemes = "Bearer")]
        [HttpGet("message")]
        public IActionResult GetMessage() {
            var identity = User.Identity as ClaimsIdentity;
            if (identity == null) {
                return HttpBadRequest();
            }

            // Note: identity is the ClaimsIdentity representing the resource owner
            // and identity.Actor is the identity corresponding to the client
            // application the access token has been issued to (delegation).
            return Content(string.Format(
                CultureInfo.InvariantCulture,
                "{0} has been successfully authenticated via {1}",
                identity.Name, identity.Actor.Name));
        }
    }
}