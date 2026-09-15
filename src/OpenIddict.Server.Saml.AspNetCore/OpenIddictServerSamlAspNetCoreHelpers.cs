/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Server.Saml;
using OpenIddict.Server.Saml.AspNetCore;

namespace Microsoft.AspNetCore;

/// <summary>
/// Exposes extensions simplifying the integration between the OpenIddict SAML 2.0 identity provider and ASP.NET Core.
/// </summary>
public static class OpenIddictServerSamlAspNetCoreHelpers
{
    /// <summary>
    /// Starts an identity provider-initiated SAML single logout for the user authenticated using the configured authentication
    /// scheme: all the server-side sessions sharing the login identifier of the user are terminated, the user is signed out of
    /// the authentication scheme and the response propagating the logout to the session participants is written (the user agent
    /// is finally redirected to the specified return URL). This method is typically called from an antiforgery-protected action.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <param name="returnUrl">The local URL the user agent is redirected to once the logout is completed, if any.</param>
    /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
    /// <exception cref="ArgumentException">The return URL is not a local URL.</exception>
    public static async Task StartOpenIddictSamlLogoutAsync(this HttpContext context, string? returnUrl = null)
    {
        ArgumentNullException.ThrowIfNull(context);

        // Note: only local URLs are accepted to prevent open redirects.
        Uri? url = null;
        if (!string.IsNullOrEmpty(returnUrl) && (!OpenIddictServerSamlLogoutService.IsLocalUrl(returnUrl) ||
            !Uri.TryCreate(returnUrl, UriKind.Relative, out url)))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID01005), nameof(returnUrl));
        }

        var options = context.RequestServices.GetService<IOptionsMonitor<OpenIddictServerSamlAspNetCoreOptions>>()?.CurrentValue ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0571));

        var service = context.RequestServices.GetRequiredService<OpenIddictServerSamlLogoutService>();

        var authentication = await context.AuthenticateAsync(options.AuthenticationScheme);

        var action = await service.StartLogoutAsync(authentication.Principal ?? new(), url,
            OpenIddictServerSamlAspNetCoreEndpoints.GetBaseUri(context), context.RequestAborted);

        await context.SignOutAsync(options.AuthenticationScheme);

        await OpenIddictServerSamlAspNetCoreEndpoints.WriteLogoutActionAsync(context, action);
    }
}
