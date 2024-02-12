using System.Net.Http;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Client;
using OpenIddict.Sandbox.AspNetCore.Client.ViewModels.Home;
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
    public async Task<ActionResult> Index(CancellationToken cancellationToken) => View(new IndexViewModel
    {
        Providers = from registration in await _service.GetClientRegistrationsAsync(cancellationToken)
                    where !string.IsNullOrEmpty(registration.ProviderName)
                    where !string.IsNullOrEmpty(registration.ProviderDisplayName)
                    select registration
    });

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

        return View("Index", new IndexViewModel
        {
            Message = await response.Content.ReadAsStringAsync(),
            Providers = from registration in await _service.GetClientRegistrationsAsync(cancellationToken)
                        where !string.IsNullOrEmpty(registration.ProviderName)
                        where !string.IsNullOrEmpty(registration.ProviderDisplayName)
                        select registration
        });
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

        return View("Index", new IndexViewModel
        {
            Message = result.AccessToken,
            Providers = from registration in await _service.GetClientRegistrationsAsync(cancellationToken)
                        where !string.IsNullOrEmpty(registration.ProviderName)
                        where !string.IsNullOrEmpty(registration.ProviderDisplayName)
                        select registration
        });
    }
}
