/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using OpenIddict.Validation;
using OpenIddict.Validation.Owin;

namespace Owin;

/// <summary>
/// Exposes companion extensions for the OpenIddict/OWIN integration.
/// </summary>
public static class OpenIddictValidationOwinHelpers
{
    /// <summary>
    /// Registers the OpenIddict validation OWIN middleware in the application pipeline.
    /// Note: when using a dependency injection container supporting per-request
    /// middleware resolution (like Autofac), calling this method is NOT recommended.
    /// </summary>
    /// <param name="app">The application builder used to register middleware instances.</param>
    /// <returns>The <see cref="IAppBuilder"/>.</returns>
    public static IAppBuilder UseOpenIddictValidation(this IAppBuilder app!!)
        => app.Use<OpenIddictValidationOwinMiddlewareFactory>();

    /// <summary>
    /// Retrieves the <see cref="IOwinRequest"/> instance stored in the <see cref="OpenIddictValidationTransaction"/> properties.
    /// </summary>
    /// <param name="transaction">The transaction instance.</param>
    /// <returns>The <see cref="IOwinRequest"/> instance or <see langword="null"/> if it couldn't be found.</returns>
    public static IOwinRequest? GetOwinRequest(this OpenIddictValidationTransaction transaction!!)
        => transaction.Properties.TryGetValue(typeof(IOwinRequest).FullName!, out object? property) &&
           property is WeakReference<IOwinRequest> reference &&
           reference.TryGetTarget(out IOwinRequest? request) ? request : null;

    /// <summary>
    /// Retrieves the <see cref="OpenIddictValidationEndpointType"/> instance stored in <see cref="BaseContext"/>.
    /// </summary>
    /// <param name="context">The context instance.</param>
    /// <returns>The <see cref="OpenIddictValidationEndpointType"/>.</returns>
    public static OpenIddictValidationEndpointType GetOpenIddictValidationEndpointType(this IOwinContext context!!)
        => context.Get<OpenIddictValidationTransaction>(typeof(OpenIddictValidationTransaction).FullName)?.EndpointType ?? default;

    /// <summary>
    /// Retrieves the <see cref="OpenIddictRequest"/> instance stored in <see cref="BaseContext"/>.
    /// </summary>
    /// <param name="context">The context instance.</param>
    /// <returns>The <see cref="OpenIddictRequest"/> instance or <see langword="null"/> if it couldn't be found.</returns>
    public static OpenIddictRequest? GetOpenIddictValidationRequest(this IOwinContext context!!)
        => context.Get<OpenIddictValidationTransaction>(typeof(OpenIddictValidationTransaction).FullName)?.Request;

    /// <summary>
    /// Retrieves the <see cref="OpenIddictResponse"/> instance stored in <see cref="BaseContext"/>.
    /// </summary>
    /// <param name="context">The context instance.</param>
    /// <returns>The <see cref="OpenIddictResponse"/> instance or <see langword="null"/> if it couldn't be found.</returns>
    public static OpenIddictResponse? GetOpenIddictValidationResponse(this IOwinContext context!!)
        => context.Get<OpenIddictValidationTransaction>(typeof(OpenIddictValidationTransaction).FullName)?.Response;
}
