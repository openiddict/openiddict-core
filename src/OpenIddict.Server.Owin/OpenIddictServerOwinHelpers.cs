/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using Microsoft.Owin;
using OpenIddict.Server;
using OpenIddict.Server.Owin;

namespace Owin;

/// <summary>
/// Exposes companion extensions for the OpenIddict/OWIN integration.
/// </summary>
public static class OpenIddictServerOwinHelpers
{
    /// <summary>
    /// Registers the OpenIddict server OWIN middleware in the application pipeline.
    /// Note: when using a dependency injection container supporting per-request
    /// middleware resolution (like Autofac), calling this method is NOT recommended.
    /// </summary>
    /// <param name="app">The application builder used to register middleware instances.</param>
    /// <returns>The <see cref="IAppBuilder"/> instance.</returns>
    public static IAppBuilder UseOpenIddictServer(this IAppBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        return app.Use<OpenIddictServerOwinMiddlewareFactory>();
    }

    /// <summary>
    /// Retrieves the <see cref="IOwinRequest"/> instance stored in the <see cref="OpenIddictServerTransaction"/> properties.
    /// </summary>
    /// <param name="transaction">The transaction instance.</param>
    /// <returns>The <see cref="IOwinRequest"/> instance or <see langword="null"/> if it couldn't be found.</returns>
    public static IOwinRequest? GetOwinRequest(this OpenIddictServerTransaction transaction)
    {
        ArgumentNullException.ThrowIfNull(transaction);

        return transaction.Properties.TryGetValue(typeof(IOwinRequest).FullName!, out object? property)
            && property is IOwinRequest request ? request : null;
    }

    /// <summary>
    /// Retrieves the <see cref="OpenIddictServerEndpointType"/> instance stored in <see cref="BaseContext"/>.
    /// </summary>
    /// <param name="context">The context instance.</param>
    /// <returns>The <see cref="OpenIddictServerEndpointType"/>.</returns>
    public static OpenIddictServerEndpointType GetOpenIddictServerEndpointType(this IOwinContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return context.Get<OpenIddictServerTransaction>(typeof(OpenIddictServerTransaction).FullName)?.EndpointType ?? default;
    }

    /// <summary>
    /// Retrieves the <see cref="OpenIddictRequest"/> instance stored in <see cref="BaseContext"/>.
    /// </summary>
    /// <param name="context">The context instance.</param>
    /// <returns>The <see cref="OpenIddictRequest"/> instance or <c>null</c> if it couldn't be found.</returns>
    public static OpenIddictRequest? GetOpenIddictServerRequest(this IOwinContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return context.Get<OpenIddictServerTransaction>(typeof(OpenIddictServerTransaction).FullName)?.Request;
    }

    /// <summary>
    /// Retrieves the <see cref="OpenIddictResponse"/> instance stored in <see cref="BaseContext"/>.
    /// </summary>
    /// <param name="context">The context instance.</param>
    /// <returns>The <see cref="OpenIddictResponse"/> instance or <c>null</c> if it couldn't be found.</returns>
    public static OpenIddictResponse? GetOpenIddictServerResponse(this IOwinContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return context.Get<OpenIddictServerTransaction>(typeof(OpenIddictServerTransaction).FullName)?.Response;
    }
    /// <summary>
    /// Retrieves the front-channel logout URIs resolved when the end session request was processed
    /// (OpenID Connect Front-Channel Logout 1.0). This method is typically used from custom event handlers
    /// or middleware executed after the sign-out operation to render a custom logout page.
    /// </summary>
    /// <param name="context">The context instance.</param>
    /// <returns>The front-channel logout URIs.</returns>
    public static ImmutableArray<Uri> GetOpenIddictServerFrontchannelLogoutUris(this IOwinContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return context.Get<OpenIddictServerTransaction>(typeof(OpenIddictServerTransaction).FullName)?.GetProperty<
            OpenIddictServerEvents.ProcessSessionTerminationContext>(
            typeof(OpenIddictServerEvents.ProcessSessionTerminationContext).FullName!) is { } notification
            ? [.. notification.FrontchannelLogoutUris] : [];
    }

    /// <summary>
    /// Retrieves the OP browser state used by OpenID Connect Session Management 1.0, if available.
    /// </summary>
    /// <param name="context">The context instance.</param>
    /// <returns>The OP browser state or <see langword="null"/> if no browser state cookie is present.</returns>
    public static string? GetOpenIddictServerBrowserState(this IOwinContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return context.Request.Cookies[GetOptions(context).BrowserStateCookieName];
    }

    /// <summary>
    /// Removes the OP browser state cookie used by OpenID Connect Session Management 1.0, which causes the check
    /// session iframe to report a "changed" state to the client applications. This method is typically called when the
    /// user is signed out of the authorization server without using the end session endpoint.
    /// </summary>
    /// <param name="context">The context instance.</param>
    public static void RemoveOpenIddictServerBrowserState(this IOwinContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        RemoveBrowserState(context, GetOptions(context));
    }

    internal static void RemoveBrowserState(IOwinContext context, OpenIddictServerOptions options)
    {
        if (!string.IsNullOrEmpty(context.Request.Cookies[options.BrowserStateCookieName]))
        {
            context.Response.Cookies.Delete(options.BrowserStateCookieName, CreateBrowserStateCookieOptions(context));
        }
    }

    internal static string EnsureBrowserState(IOwinContext context, OpenIddictServerOptions options, string? subject)
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

    private static OpenIddictServerOptions GetOptions(IOwinContext context)
    {
        if (context.Get<OpenIddictServerTransaction>(typeof(OpenIddictServerTransaction).FullName) is { } transaction)
        {
            return transaction.Options;
        }

        var provider = context.Get<IServiceProvider>(typeof(IServiceProvider).FullName)
            ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0121));

        return ((Microsoft.Extensions.Options.IOptionsMonitor<OpenIddictServerOptions>) provider.GetService(
            typeof(Microsoft.Extensions.Options.IOptionsMonitor<OpenIddictServerOptions>))!).CurrentValue;
    }

    private static CookieOptions CreateBrowserStateCookieOptions(IOwinContext context) => new()
    {
        // Note: the cookie MUST be readable by the check session iframe script and is sent in a third-party
        // context (the iframe is embedded by the client applications), which requires SameSite=None and Secure.
        HttpOnly = false,
        Path = "/",
        SameSite = context.Request.IsSecure ? SameSiteMode.None : SameSiteMode.Lax,
        Secure = context.Request.IsSecure
    };
}
