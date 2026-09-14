/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;

namespace Microsoft.AspNetCore;

/// <summary>
/// Exposes companion extensions for the OpenIddict/ASP.NET Core integration.
/// </summary>
public static class OpenIddictServerAspNetCoreHelpers
{
    /// <summary>
    /// Retrieves the <see cref="HttpRequest"/> instance stored in the <see cref="OpenIddictServerTransaction"/> properties.
    /// </summary>
    /// <param name="transaction">The transaction instance.</param>
    /// <returns>The <see cref="HttpRequest"/> instance or <see langword="null"/> if it couldn't be found.</returns>
    public static HttpRequest? GetHttpRequest(this OpenIddictServerTransaction transaction)
    {
        ArgumentNullException.ThrowIfNull(transaction);

        return transaction.Properties.TryGetValue(typeof(HttpRequest).FullName!, out object? property)
            && property is HttpRequest request ? request : null;

    }

    /// <summary>
    /// Retrieves the <see cref="OpenIddictServerEndpointType"/> instance stored in <see cref="BaseContext"/>.
    /// </summary>
    /// <param name="context">The context instance.</param>
    /// <returns>The <see cref="OpenIddictServerEndpointType"/>.</returns>
    public static OpenIddictServerEndpointType GetOpenIddictServerEndpointType(this HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return context.Features.Get<OpenIddictServerAspNetCoreFeature>()?.Transaction?.EndpointType ?? default;
    }

    /// <summary>
    /// Retrieves the <see cref="OpenIddictRequest"/> instance stored in <see cref="BaseContext"/>.
    /// </summary>
    /// <param name="context">The context instance.</param>
    /// <returns>The <see cref="OpenIddictRequest"/> instance or <see langword="null"/> if it couldn't be found.</returns>
    public static OpenIddictRequest? GetOpenIddictServerRequest(this HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return context.Features.Get<OpenIddictServerAspNetCoreFeature>()?.Transaction?.Request;
    }

    /// <summary>
    /// Retrieves the <see cref="OpenIddictResponse"/> instance stored in <see cref="BaseContext"/>.
    /// </summary>
    /// <param name="context">The context instance.</param>
    /// <returns>The <see cref="OpenIddictResponse"/> instance or <see langword="null"/> if it couldn't be found.</returns>
    public static OpenIddictResponse? GetOpenIddictServerResponse(this HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return context.Features.Get<OpenIddictServerAspNetCoreFeature>()?.Transaction?.Response;
    }
    /// <summary>
    /// Retrieves the front-channel logout URIs resolved when the end session request was processed
    /// (OpenID Connect Front-Channel Logout 1.0). This method is typically used from custom event handlers
    /// or middleware executed after the sign-out operation to render a custom logout page.
    /// </summary>
    /// <param name="context">The context instance.</param>
    /// <returns>The front-channel logout URIs.</returns>
    public static ImmutableArray<Uri> GetOpenIddictServerFrontchannelLogoutUris(this HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return context.Features.Get<OpenIddictServerAspNetCoreFeature>()?.Transaction?.GetProperty<
            OpenIddictServerEvents.ProcessSessionTerminationContext>(
            typeof(OpenIddictServerEvents.ProcessSessionTerminationContext).FullName!) is { } notification
            ? [.. notification.FrontchannelLogoutUris] : [];
    }

    /// <summary>
    /// Retrieves the OP browser state used by OpenID Connect Session Management 1.0, if available.
    /// </summary>
    /// <param name="context">The context instance.</param>
    /// <returns>The OP browser state or <see langword="null"/> if no browser state cookie is present.</returns>
    public static string? GetOpenIddictServerBrowserState(this HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var options = context.RequestServices.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;

        return context.Request.Cookies[options.BrowserStateCookieName];
    }

    /// <summary>
    /// Removes the OP browser state cookie used by OpenID Connect Session Management 1.0, which causes the check
    /// session iframe to report a "changed" state to the client applications. This method is typically called when the
    /// user is signed out of the authorization server without using the end session endpoint.
    /// </summary>
    /// <param name="context">The context instance.</param>
    public static void RemoveOpenIddictServerBrowserState(this HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var options = context.RequestServices.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;

        if (context.Request.Cookies.ContainsKey(options.BrowserStateCookieName))
        {
            context.Response.Cookies.Delete(options.BrowserStateCookieName, CreateBrowserStateCookieOptions(context));
        }
    }

    internal static string EnsureBrowserState(HttpContext context, OpenIddictServerOptions options, string? subject)
    {
        var state = context.Request.Cookies[options.BrowserStateCookieName];
        if (OpenIddictServerHelpers.ValidateBrowserState(state, subject))
        {
            return state!;
        }

        state = OpenIddictServerHelpers.CreateBrowserState(subject);

        context.Response.Cookies.Append(options.BrowserStateCookieName, state, CreateBrowserStateCookieOptions(context));

        return state;
    }

    private static CookieOptions CreateBrowserStateCookieOptions(HttpContext context) => new()
    {
        // Note: the cookie MUST be readable by the check session iframe script and is sent in a third-party
        // context (the iframe is embedded by the client applications), which requires SameSite=None and Secure.
        HttpOnly = false,
        IsEssential = true,
        Path = "/",
        SameSite = context.Request.IsHttps ? SameSiteMode.None : SameSiteMode.Lax,
        Secure = context.Request.IsHttps
    };
}
