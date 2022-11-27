using System.Net.Http.Headers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Client;
using static OpenIddict.Client.AspNetCore.OpenIddictClientAspNetCoreConstants;

namespace OpenIddict.Sandbox.AspNetCore.Client.Controllers;

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

    [HttpGet("~/")]
    public ActionResult Index() => View();

    [Authorize, HttpPost("~/message"), ValidateAntiForgeryToken]
    public async Task<ActionResult> GetMessage(CancellationToken cancellationToken)
    {
        var token = await HttpContext.GetTokenAsync(CookieAuthenticationDefaults.AuthenticationScheme, Tokens.BackchannelAccessToken);

        using var client = _httpClientFactory.CreateClient();

        using var request = new HttpRequestMessage(HttpMethod.Get, "https://localhost:44395/api/message");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using var response = await client.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();

        return View("Index", model: await response.Content.ReadAsStringAsync(cancellationToken));
    }

    [Authorize, HttpPost("~/refresh-token"), ValidateAntiForgeryToken]
    public async Task<ActionResult> RefreshToken(CancellationToken cancellationToken)
    {
        var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        var token = result?.Properties.GetTokenValue(Tokens.RefreshToken);
        if (string.IsNullOrEmpty(token))
        {
            return BadRequest();
        }

        var (response, principal) = await _service.AuthenticateWithRefreshTokenAsync(
            issuer: new Uri(result.Principal.Claims.Select(claim => claim.Issuer).First(), UriKind.Absolute),
            token: token,
            cancellationToken: cancellationToken);

        var properties = new AuthenticationProperties(result.Properties.Items)
        {
            RedirectUri = null
        };

        properties.UpdateTokenValue(Tokens.BackchannelAccessToken, response.AccessToken);

        if (!string.IsNullOrEmpty(response.RefreshToken))
        {
            properties.UpdateTokenValue(Tokens.RefreshToken, response.RefreshToken);
        }

        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, result.Principal, properties);

        return View("Index", model: response.AccessToken);
    }
}
