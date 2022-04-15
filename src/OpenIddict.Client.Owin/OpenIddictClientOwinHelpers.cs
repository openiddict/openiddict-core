/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using OpenIddict.Client;
using OpenIddict.Client.Owin;

namespace Owin;

/// <summary>
/// Exposes companion extensions for the OpenIddict/OWIN integration.
/// </summary>
public static class OpenIddictClientOwinHelpers
{
    /// <summary>
    /// Registers the OpenIddict client OWIN middleware in the application pipeline.
    /// Note: when using a dependency injection container supporting per-request
    /// middleware resolution (like Autofac), calling this method is NOT recommended.
    /// </summary>
    /// <param name="app">The application builder used to register middleware instances.</param>
    /// <returns>The <see cref="IAppBuilder"/>.</returns>
    public static IAppBuilder UseOpenIddictClient(this IAppBuilder app!!)
        => app.Use<OpenIddictClientOwinMiddlewareFactory>();

    /// <summary>
    /// Retrieves the <see cref="IOwinRequest"/> instance stored in the <see cref="OpenIddictClientTransaction"/> properties.
    /// </summary>
    /// <param name="transaction">The transaction instance.</param>
    /// <returns>The <see cref="IOwinRequest"/> instance or <see langword="null"/> if it couldn't be found.</returns>
    public static IOwinRequest? GetOwinRequest(this OpenIddictClientTransaction transaction!!)
        => transaction.Properties.TryGetValue(typeof(IOwinRequest).FullName!, out object? property) &&
           property is WeakReference<IOwinRequest> reference &&
           reference.TryGetTarget(out IOwinRequest? request) ? request : null;

    /// <summary>
    /// Retrieves the <see cref="OpenIddictClientEndpointType"/> instance stored in <see cref="BaseContext"/>.
    /// </summary>
    /// <param name="context">The context instance.</param>
    /// <returns>The <see cref="OpenIddictClientEndpointType"/>.</returns>
    public static OpenIddictClientEndpointType GetOpenIddictClientEndpointType(this IOwinContext context!!)
        => context.Get<OpenIddictClientTransaction>(typeof(OpenIddictClientTransaction).FullName)?.EndpointType ?? default;

    /// <summary>
    /// Retrieves the <see cref="OpenIddictRequest"/> instance stored in <see cref="BaseContext"/>.
    /// </summary>
    /// <param name="context">The context instance.</param>
    /// <returns>The <see cref="OpenIddictRequest"/> instance or <see langword="null"/> if it couldn't be found.</returns>
    public static OpenIddictRequest? GetOpenIddictClientRequest(this IOwinContext context!!)
        => context.Get<OpenIddictClientTransaction>(typeof(OpenIddictClientTransaction).FullName)?.Request;

    /// <summary>
    /// Retrieves the <see cref="OpenIddictResponse"/> instance stored in <see cref="BaseContext"/>.
    /// </summary>
    /// <param name="context">The context instance.</param>
    /// <returns>The <see cref="OpenIddictResponse"/> instance or <see langword="null"/> if it couldn't be found.</returns>
    public static OpenIddictResponse? GetOpenIddictClientResponse(this IOwinContext context!!)
        => context.Get<OpenIddictClientTransaction>(typeof(OpenIddictClientTransaction).FullName)?.Response;
}
