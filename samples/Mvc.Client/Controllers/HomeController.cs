using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Mvc.Client.Controllers
{
    public class HomeController : Controller
    {
        private readonly HttpClient _client;

        public HomeController(HttpClient client)
        {
            _client = client;
        }

        [HttpGet("~/")]
        public ActionResult Index()
        {
            return View("Home");
        }

        [Authorize, HttpPost("~/")]
        public async Task<ActionResult> Index(CancellationToken cancellationToken)
        {
            var token = await HttpContext.GetTokenAsync(CookieAuthenticationDefaults.AuthenticationScheme, OpenIdConnectParameterNames.AccessToken);
            if (string.IsNullOrEmpty(token))
            {
                throw new InvalidOperationException("The access token cannot be found in the authentication ticket. " +
                                                    "Make sure that SaveTokens is set to true in the OIDC options.");
            }

            var request = new HttpRequestMessage(HttpMethod.Get, "http://localhost:54540/api/message");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await _client.SendAsync(request, cancellationToken);
            response.EnsureSuccessStatusCode();

            return View("Home", model: await response.Content.ReadAsStringAsync());
        }
    }
}