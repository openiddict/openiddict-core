using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using OpenIddict.Client;
using static OpenIddict.Abstractions.OpenIddictConstants;
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

            var ticket = await context.Authentication.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationType);
            if (!ticket.Properties.Dictionary.TryGetValue(Tokens.RefreshToken, out string token))
            {
                return new HttpStatusCodeResult(400);
            }

            var result = await _service.AuthenticateWithRefreshTokenAsync(new()
            {
                CancellationToken = cancellationToken,
                RefreshToken = token,
                RegistrationId = ticket.Identity.FindFirst(Claims.Private.RegistrationId)?.Value
            });

            var properties = new AuthenticationProperties(ticket.Properties.Dictionary)
            {
                RedirectUri = null
            };

            properties.Dictionary[Tokens.BackchannelAccessToken] = result.AccessToken;

            if (!string.IsNullOrEmpty(result.RefreshToken))
            {
                properties.Dictionary[Tokens.RefreshToken] = result.RefreshToken;
            }

            context.Authentication.SignIn(properties, ticket.Identity);

            return View("Index", model: result.AccessToken);
        }
    }
}
