using System;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using OpenIddict.Client;
using OpenIddict.Sandbox.AspNet.Client.ViewModels.Home;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Client.Owin.OpenIddictClientOwinConstants;

namespace OpenIddict.Sandbox.AspNet.Client.Controllers;

public class HomeController([FromKeyedServices("ApiClient")] HttpClient client, OpenIddictClientService service) : Controller
{
    [HttpGet, Route("~/")]
    public async Task<ActionResult> Index(CancellationToken cancellationToken) => View(new IndexViewModel
    {
        Providers = from registration in await service.GetClientRegistrationsAsync(cancellationToken)
                    where !string.IsNullOrEmpty(registration.ProviderName)
                    where !string.IsNullOrEmpty(registration.ProviderDisplayName)
                    select registration
    });

    [Authorize, HttpPost, Route("~/message"), ValidateAntiForgeryToken]
    public async Task<ActionResult> GetMessage(CancellationToken cancellationToken)
    {
        var context = HttpContext.GetOwinContext();

        var result = await context.Authentication.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationType);
        var token = result.Properties.Dictionary[Tokens.BackchannelAccessToken];

        using var request = new HttpRequestMessage(HttpMethod.Get, "api/message");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using var response = await client.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();

        return View("Index", new IndexViewModel
        {
            Message = await response.Content.ReadAsStringAsync(cancellationToken),
            Providers = from registration in await service.GetClientRegistrationsAsync(cancellationToken)
                        where !string.IsNullOrEmpty(registration.ProviderName)
                        where !string.IsNullOrEmpty(registration.ProviderDisplayName)
                        select registration
        });
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

        var result = await service.AuthenticateWithRefreshTokenAsync(new()
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

        return View("Index", new IndexViewModel
        {
            Message = result.AccessToken,
            Providers = from registration in await service.GetClientRegistrationsAsync(cancellationToken)
                        where !string.IsNullOrEmpty(registration.ProviderName)
                        where !string.IsNullOrEmpty(registration.ProviderDisplayName)
                        select registration
        });
    }
}
