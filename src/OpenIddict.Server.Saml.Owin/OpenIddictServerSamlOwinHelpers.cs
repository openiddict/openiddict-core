/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Owin;
using OpenIddict.Server.Saml;
using OpenIddict.Server.Saml.Owin;

namespace Owin;

/// <summary>
/// Exposes companion extensions for the OpenIddict SAML 2.0 identity provider OWIN/Katana integration.
/// </summary>
public static class OpenIddictServerSamlOwinHelpers
{
    /// <summary>
    /// Registers the OpenIddict SAML 2.0 identity provider OWIN middleware (metadata and single sign-on endpoints)
    /// in the application pipeline. The middleware must be registered after the authentication middleware
    /// and requires the scoped <see cref="IServiceProvider"/> to be attached to the OWIN context.
    /// </summary>
    /// <param name="app">The application builder used to register middleware instances.</param>
    /// <returns>The <see cref="IAppBuilder"/> instance.</returns>
    public static IAppBuilder UseOpenIddictSaml(this IAppBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        return app.Use<OpenIddictServerSamlOwinMiddleware>();
    }

    /// <summary>
    /// Starts an identity provider-initiated SAML single logout for the user authenticated using the configured authentication
    /// type: all the server-side sessions sharing the login identifier of the user are terminated, the user is signed out of
    /// the authentication type and the response propagating the logout to the session participants is written (the user agent
    /// is finally redirected to the specified return URL). This method is typically called from an antiforgery-protected action.
    /// </summary>
    /// <param name="context">The OWIN context.</param>
    /// <param name="returnUrl">The local URL the user agent is redirected to once the logout is completed, if any.</param>
    /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
    /// <exception cref="ArgumentException">The return URL is not a local URL.</exception>
    public static async Task StartOpenIddictSamlLogoutAsync(this IOwinContext context, string? returnUrl = null)
    {
        ArgumentNullException.ThrowIfNull(context);

        // Note: only local URLs are accepted to prevent open redirects.
        if (!string.IsNullOrEmpty(returnUrl) && (returnUrl[0] is not '/' ||
            (returnUrl.Length > 1 && returnUrl[1] is '/' or '\\')))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID01005), nameof(returnUrl));
        }

        var provider = context.Get<IServiceProvider>(typeof(IServiceProvider).FullName) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0578));

        var options = provider.GetService<IOptionsMonitor<OpenIddictServerSamlOwinOptions>>()?.CurrentValue ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0578));

        var service = provider.GetRequiredService<OpenIddictServerSamlLogoutService>();

        var authentication = await context.Authentication.AuthenticateAsync(options.AuthenticationType);

        var action = await service.StartLogoutAsync(
            authentication?.Identity is { IsAuthenticated: true } identity ? new ClaimsPrincipal(identity) : new ClaimsPrincipal(),
            string.IsNullOrEmpty(returnUrl) ? null : new Uri(returnUrl, UriKind.Relative),
            context.Request.CallCancelled);

        context.Authentication.SignOut(options.AuthenticationType);

        await OpenIddictServerSamlOwinMiddleware.WriteLogoutActionAsync(context, action);
    }
}
