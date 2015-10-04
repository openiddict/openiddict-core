using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNet.Authorization;
using Microsoft.AspNet.Mvc;

namespace Mvc.Client.Controllers {
    public class HomeController : Controller {
        [HttpGet("~/")]
        public ActionResult Index() {
            return View("Home");
        }

        [Authorize, HttpPost("~/")]
        public async Task<ActionResult> Index(CancellationToken cancellationToken) {
            using (var client = new HttpClient()) {
                var request = new HttpRequestMessage(HttpMethod.Get, "http://localhost:54540/api/message");
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", AccessToken);

                var response = await client.SendAsync(request, cancellationToken);
                response.EnsureSuccessStatusCode();

                return View("Home", model: await response.Content.ReadAsStringAsync());
            }
        }

        protected string AccessToken {
            get {
                var claim = HttpContext.User?.FindFirst("access_token");
                if (claim == null) {
                    throw new InvalidOperationException();
                }

                return claim.Value;
            }
        }
    }
}