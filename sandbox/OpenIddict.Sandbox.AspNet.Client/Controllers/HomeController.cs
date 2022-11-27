using System;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using OpenIddict.Client;
using static OpenIddict.Client.Owin.OpenIddictClientOwinConstants;

namespace OpenIddict.Sandbox.AspNet.Client.Controllers
{
    public class HomeController : Controller
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly OpenIddictClientService _service;

        public HomeController(
            IHttpClientFactory httpClientFactory,
            OpenIddictClientService service)
        {
            _httpClientFactory = httpClientFactory;
            _service = service;
        }

        [HttpGet, Route("~/")]
        public ActionResult Index() => View();

        [Authorize, HttpPost, Route("~/message")]
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

        [Authorize, HttpPost, Route("~/refresh-token")]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> RefreshToken(CancellationToken cancellationToken)
        {
            var context = HttpContext.GetOwinContext();

            var result = await context.Authentication.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationType);
            if (!result.Properties.Dictionary.TryGetValue(Tokens.RefreshToken, out string token))
            {
                return new HttpStatusCodeResult(400);
            }

            var (response, principal) = await _service.AuthenticateWithRefreshTokenAsync(
                issuer: new Uri(result.Identity.Claims.Select(claim => claim.Issuer).First(), UriKind.Absolute),
                token: token,
                cancellationToken: cancellationToken);

            var properties = new AuthenticationProperties(result.Properties.Dictionary)
            {
                RedirectUri = null
            };

            properties.Dictionary[Tokens.BackchannelAccessToken] = response.AccessToken;

            if (!string.IsNullOrEmpty(response.RefreshToken))
            {
                properties.Dictionary[Tokens.RefreshToken] = response.RefreshToken;
            }

            context.Authentication.SignIn(properties, result.Identity);

            return View("Index", model: response.AccessToken);
        }
    }
}
