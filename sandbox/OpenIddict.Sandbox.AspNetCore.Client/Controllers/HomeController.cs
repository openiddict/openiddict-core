using System.Net.Http;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Client;
using static OpenIddict.Abstractions.OpenIddictConstants;
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
        // For scenarios where the default authentication handler configured in the ASP.NET Core
        // authentication options shouldn't be used, a specific scheme can be specified here.
        var token = await HttpContext.GetTokenAsync(Tokens.BackchannelAccessToken);

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
        // For scenarios where the default authentication handler configured in the ASP.NET Core
        // authentication options shouldn't be used, a specific scheme can be specified here.
        var ticket = await HttpContext.AuthenticateAsync();
        var token = ticket?.Properties.GetTokenValue(Tokens.RefreshToken);
        if (string.IsNullOrEmpty(token))
        {
            return BadRequest();
        }

        var result = await _service.AuthenticateWithRefreshTokenAsync(new()
        {
            CancellationToken = cancellationToken,
            RefreshToken = token,
            RegistrationId = ticket.Principal.FindFirst(Claims.Private.RegistrationId)?.Value
        });

        var properties = new AuthenticationProperties(ticket.Properties.Items)
        {
            RedirectUri = null
        };

        properties.UpdateTokenValue(Tokens.BackchannelAccessToken, result.AccessToken);

        if (!string.IsNullOrEmpty(result.RefreshToken))
        {
            properties.UpdateTokenValue(Tokens.RefreshToken, result.RefreshToken);
        }

        // For scenarios where the default sign-in handler configured in the ASP.NET Core
        // authentication options shouldn't be used, a specific scheme can be specified here.
        await HttpContext.SignInAsync(ticket.Principal, properties);

        return View("Index", model: result.AccessToken);
    }
}
