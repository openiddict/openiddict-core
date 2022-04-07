/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using OpenIddict.Client;
using OpenIddict.Client.AspNetCore;

namespace Microsoft.AspNetCore;

/// <summary>
/// Exposes companion extensions for the OpenIddict/ASP.NET Core integration.
/// </summary>
public static class OpenIddictClientAspNetCoreHelpers
{
    /// <summary>
    /// Retrieves the <see cref="HttpRequest"/> instance stored in the <see cref="OpenIddictClientTransaction"/> properties.
    /// </summary>
    /// <param name="transaction">The transaction instance.</param>
    /// <returns>The <see cref="HttpRequest"/> instance or <c>null</c> if it couldn't be found.</returns>
    public static HttpRequest? GetHttpRequest(this OpenIddictClientTransaction transaction!!)
    {
        if (!transaction.Properties.TryGetValue(typeof(HttpRequest).FullName!, out object? property))
        {
            return null;
        }

        if (property is WeakReference<HttpRequest> reference && reference.TryGetTarget(out HttpRequest? request))
        {
            return request;
        }

        return null;
    }

    /// <summary>
    /// Retrieves the <see cref="OpenIddictClientEndpointType"/> instance stored in <see cref="BaseContext"/>.
    /// </summary>
    /// <param name="context">The context instance.</param>
    /// <returns>The <see cref="OpenIddictClientEndpointType"/>.</returns>
    public static OpenIddictClientEndpointType GetOpenIddictClientEndpointType(this HttpContext context!!)
    {
        return context.Features.Get<OpenIddictClientAspNetCoreFeature>()?.Transaction?.EndpointType ?? default;
    }

    /// <summary>
    /// Retrieves the <see cref="OpenIddictRequest"/> instance stored in <see cref="BaseContext"/>.
    /// </summary>
    /// <param name="context">The context instance.</param>
    /// <returns>The <see cref="OpenIddictRequest"/> instance or <c>null</c> if it couldn't be found.</returns>
    public static OpenIddictRequest? GetOpenIddictClientRequest(this HttpContext context!!)
    {
        return context.Features.Get<OpenIddictClientAspNetCoreFeature>()?.Transaction?.Request;
    }

    /// <summary>
    /// Retrieves the <see cref="OpenIddictResponse"/> instance stored in <see cref="BaseContext"/>.
    /// </summary>
    /// <param name="context">The context instance.</param>
    /// <returns>The <see cref="OpenIddictResponse"/> instance or <c>null</c> if it couldn't be found.</returns>
    public static OpenIddictResponse? GetOpenIddictClientResponse(this HttpContext context!!)
    {
        return context.Features.Get<OpenIddictClientAspNetCoreFeature>()?.Transaction?.Response;
    }
}
