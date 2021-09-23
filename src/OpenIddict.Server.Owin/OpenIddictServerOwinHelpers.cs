/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

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
    /// <returns>The <see cref="IAppBuilder"/>.</returns>
    public static IAppBuilder UseOpenIddictServer(this IAppBuilder app)
    {
        if (app is null)
        {
            throw new ArgumentNullException(nameof(app));
        }

        return app.Use<OpenIddictServerOwinMiddlewareFactory>();
    }

    /// <summary>
    /// Retrieves the <see cref="IOwinRequest"/> instance stored in the <see cref="OpenIddictServerTransaction"/> properties.
    /// </summary>
    /// <param name="transaction">The transaction instance.</param>
    /// <returns>The <see cref="IOwinRequest"/> instance or <c>null</c> if it couldn't be found.</returns>
    public static IOwinRequest? GetOwinRequest(this OpenIddictServerTransaction transaction)
    {
        if (transaction is null)
        {
            throw new ArgumentNullException(nameof(transaction));
        }

        if (!transaction.Properties.TryGetValue(typeof(IOwinRequest).FullName!, out object? property))
        {
            return null;
        }

        if (property is WeakReference<IOwinRequest> reference && reference.TryGetTarget(out IOwinRequest? request))
        {
            return request;
        }

        return null;
    }

    /// <summary>
    /// Retrieves the <see cref="OpenIddictServerEndpointType"/> instance stored in <see cref="BaseContext"/>.
    /// </summary>
    /// <param name="context">The context instance.</param>
    /// <returns>The <see cref="OpenIddictServerEndpointType"/>.</returns>
    public static OpenIddictServerEndpointType GetOpenIddictServerEndpointType(this IOwinContext context)
    {
        if (context is null)
        {
            throw new ArgumentNullException(nameof(context));
        }

        return context.Get<OpenIddictServerTransaction>(typeof(OpenIddictServerTransaction).FullName)?.EndpointType ?? default;
    }

    /// <summary>
    /// Retrieves the <see cref="OpenIddictRequest"/> instance stored in <see cref="BaseContext"/>.
    /// </summary>
    /// <param name="context">The context instance.</param>
    /// <returns>The <see cref="OpenIddictRequest"/> instance or <c>null</c> if it couldn't be found.</returns>
    public static OpenIddictRequest? GetOpenIddictServerRequest(this IOwinContext context)
    {
        if (context is null)
        {
            throw new ArgumentNullException(nameof(context));
        }

        return context.Get<OpenIddictServerTransaction>(typeof(OpenIddictServerTransaction).FullName)?.Request;
    }

    /// <summary>
    /// Retrieves the <see cref="OpenIddictResponse"/> instance stored in <see cref="BaseContext"/>.
    /// </summary>
    /// <param name="context">The context instance.</param>
    /// <returns>The <see cref="OpenIddictResponse"/> instance or <c>null</c> if it couldn't be found.</returns>
    public static OpenIddictResponse? GetOpenIddictServerResponse(this IOwinContext context)
    {
        if (context is null)
        {
            throw new ArgumentNullException(nameof(context));
        }

        return context.Get<OpenIddictServerTransaction>(typeof(OpenIddictServerTransaction).FullName)?.Response;
    }
}
