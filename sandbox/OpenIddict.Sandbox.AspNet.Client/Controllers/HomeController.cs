using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.Owin.Security.Cookies;
using static OpenIddict.Client.Owin.OpenIddictClientOwinConstants;

namespace OpenIddict.Sandbox.AspNet.Client.Controllers
{
    public class HomeController : Controller
    {
        private readonly IHttpClientFactory _httpClientFactory;

        public HomeController(IHttpClientFactory httpClientFactory)
            => _httpClientFactory = httpClientFactory;

        [HttpGet, Route("~/")]
        public ActionResult Index() => View();

        [Authorize, HttpPost, Route("~/")]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Index(CancellationToken cancellationToken)
        {
            var context = HttpContext.GetOwinContext();

            var result = await context.Authentication.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationType);
            var token = result.Properties.Dictionary[Tokens.BackchannelAccessToken];

            using var client = _httpClientFactory.CreateClient();

            using var request = new HttpRequestMessage(HttpMethod.Get, "https://localhost:44349/api/message");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

            using var response = await client.SendAsync(request, cancellationToken);
            response.EnsureSuccessStatusCode();

            return View(model: await response.Content.ReadAsStringAsync());
        }
    }
}
