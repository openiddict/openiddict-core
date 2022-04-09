/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using OpenIddict.Validation;
using OpenIddict.Validation.AspNetCore;

namespace Microsoft.AspNetCore;

/// <summary>
/// Exposes companion extensions for the OpenIddict/ASP.NET Core integration.
/// </summary>
public static class OpenIddictValidationAspNetCoreHelpers
{
    /// <summary>
    /// Retrieves the <see cref="HttpRequest"/> instance stored in the <see cref="OpenIddictValidationTransaction"/> properties.
    /// </summary>
    /// <param name="transaction">The transaction instance.</param>
    /// <returns>The <see cref="HttpRequest"/> instance or <see langword="null"/> if it couldn't be found.</returns>
    public static HttpRequest? GetHttpRequest(this OpenIddictValidationTransaction transaction!!)
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
    /// Retrieves the <see cref="OpenIddictValidationEndpointType"/> instance stored in <see cref="BaseContext"/>.
    /// </summary>
    /// <param name="context">The context instance.</param>
    /// <returns>The <see cref="OpenIddictValidationEndpointType"/>.</returns>
    public static OpenIddictValidationEndpointType GetOpenIddictValidationEndpointType(this HttpContext context!!)
    {
        return context.Features.Get<OpenIddictValidationAspNetCoreFeature>()?.Transaction?.EndpointType ?? default;
    }

    /// <summary>
    /// Retrieves the <see cref="OpenIddictRequest"/> instance stored in <see cref="BaseContext"/>.
    /// </summary>
    /// <param name="context">The context instance.</param>
    /// <returns>The <see cref="OpenIddictRequest"/> instance or <see langword="null"/> if it couldn't be found.</returns>
    public static OpenIddictRequest? GetOpenIddictValidationRequest(this HttpContext context!!)
    {
        return context.Features.Get<OpenIddictValidationAspNetCoreFeature>()?.Transaction?.Request;
    }

    /// <summary>
    /// Retrieves the <see cref="OpenIddictResponse"/> instance stored in <see cref="BaseContext"/>.
    /// </summary>
    /// <param name="context">The context instance.</param>
    /// <returns>The <see cref="OpenIddictResponse"/> instance or <see langword="null"/> if it couldn't be found.</returns>
    public static OpenIddictResponse? GetOpenIddictValidationResponse(this HttpContext context!!)
    {
        return context.Features.Get<OpenIddictValidationAspNetCoreFeature>()?.Transaction?.Response;
    }
}
