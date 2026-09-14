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
    /// <returns>The <see cref="HttpRequest"/> instance or <see langword="null"/> if it couldn't be found.</returns>
    public static HttpRequest? GetHttpRequest(this OpenIddictClientTransaction transaction)
    {
        ArgumentNullException.ThrowIfNull(transaction);

        return transaction.Properties.TryGetValue(typeof(HttpRequest).FullName!, out object? property)
            && property is HttpRequest request ? request : null;
    }

    /// <summary>
    /// Reads the CIBA ping or push notification sent by the authorization server to the client notification endpoint.
    /// The returned notification is expected to be passed to
    /// <see cref="OpenIddictClientService.AuthenticateWithBackchannelNotificationAsync"/>, that validates it.
    /// </summary>
    /// <param name="request">The HTTP request.</param>
    /// <returns>The notification or <see langword="null"/> if the request is not a valid JSON POST notification.</returns>
    /// <remarks>
    /// Note: per the CIBA specification, the client notification endpoint SHOULD respond with a 204 status code.
    /// </remarks>
    public static async ValueTask<OpenIddictClientModels.BackchannelNotification?> ReadBackchannelNotificationAsync(this HttpRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!HttpMethods.IsPost(request.Method))
        {
            return null;
        }

        return await OpenIddictClientHelpers.CreateBackchannelNotificationAsync(
            authorization: request.Headers.Authorization,
            type: request.ContentType,
            body: request.Body,
            cancellationToken: request.HttpContext.RequestAborted);
    }

    /// <summary>
    /// Retrieves the <see cref="OpenIddictClientEndpointType"/> instance stored in <see cref="BaseContext"/>.
    /// </summary>
    /// <param name="context">The context instance.</param>
    /// <returns>The <see cref="OpenIddictClientEndpointType"/>.</returns>
    public static OpenIddictClientEndpointType GetOpenIddictClientEndpointType(this HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return context.Features.Get<OpenIddictClientAspNetCoreFeature>()?.Transaction?.EndpointType ?? default;
    }

    /// <summary>
    /// Retrieves the <see cref="OpenIddictRequest"/> instance stored in <see cref="BaseContext"/>.
    /// </summary>
    /// <param name="context">The context instance.</param>
    /// <returns>The <see cref="OpenIddictRequest"/> instance or <see langword="null"/> if it couldn't be found.</returns>
    public static OpenIddictRequest? GetOpenIddictClientRequest(this HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return context.Features.Get<OpenIddictClientAspNetCoreFeature>()?.Transaction?.Request;
    }

    /// <summary>
    /// Retrieves the <see cref="OpenIddictResponse"/> instance stored in <see cref="BaseContext"/>.
    /// </summary>
    /// <param name="context">The context instance.</param>
    /// <returns>The <see cref="OpenIddictResponse"/> instance or <see langword="null"/> if it couldn't be found.</returns>
    public static OpenIddictResponse? GetOpenIddictClientResponse(this HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return context.Features.Get<OpenIddictClientAspNetCoreFeature>()?.Transaction?.Response;
    }
}
