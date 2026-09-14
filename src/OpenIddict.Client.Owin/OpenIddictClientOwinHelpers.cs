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
    /// <returns>The <see cref="IAppBuilder"/> instance.</returns>
    public static IAppBuilder UseOpenIddictClient(this IAppBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        return app.Use<OpenIddictClientOwinMiddlewareFactory>();
    }

    /// <summary>
    /// Retrieves the <see cref="IOwinRequest"/> instance stored in the <see cref="OpenIddictClientTransaction"/> properties.
    /// </summary>
    /// <param name="transaction">The transaction instance.</param>
    /// <returns>The <see cref="IOwinRequest"/> instance or <see langword="null"/> if it couldn't be found.</returns>
    public static IOwinRequest? GetOwinRequest(this OpenIddictClientTransaction transaction)
    {
        ArgumentNullException.ThrowIfNull(transaction);

        return transaction.Properties.TryGetValue(typeof(IOwinRequest).FullName!, out object? property)
            && property is IOwinRequest request ? request : null;
    }

    /// <summary>
    /// Reads the CIBA ping or push notification sent by the authorization server to the client notification endpoint.
    /// The returned notification is expected to be passed to
    /// <see cref="OpenIddictClientService.AuthenticateWithBackchannelNotificationAsync"/>, that validates it.
    /// </summary>
    /// <param name="request">The OWIN request.</param>
    /// <returns>The notification or <see langword="null"/> if the request is not a valid JSON POST notification.</returns>
    /// <remarks>
    /// Note: per the CIBA specification, the client notification endpoint SHOULD respond with a 204 status code.
    /// </remarks>
    public static async Task<OpenIddictClientModels.BackchannelNotification?> ReadBackchannelNotificationAsync(this IOwinRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!string.Equals(request.Method, "POST", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return await OpenIddictClientHelpers.CreateBackchannelNotificationAsync(
            authorization: request.Headers.Get("Authorization"),
            type: request.ContentType,
            body: request.Body,
            cancellationToken: request.CallCancelled);
    }

    /// <summary>
    /// Retrieves the <see cref="OpenIddictClientEndpointType"/> instance stored in <see cref="BaseContext"/>.
    /// </summary>
    /// <param name="context">The context instance.</param>
    /// <returns>The <see cref="OpenIddictClientEndpointType"/>.</returns>
    public static OpenIddictClientEndpointType GetOpenIddictClientEndpointType(this IOwinContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return context.Get<OpenIddictClientTransaction>(typeof(OpenIddictClientTransaction).FullName)?.EndpointType ?? default;
    }

    /// <summary>
    /// Retrieves the <see cref="OpenIddictRequest"/> instance stored in <see cref="BaseContext"/>.
    /// </summary>
    /// <param name="context">The context instance.</param>
    /// <returns>The <see cref="OpenIddictRequest"/> instance or <see langword="null"/> if it couldn't be found.</returns>
    public static OpenIddictRequest? GetOpenIddictClientRequest(this IOwinContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return context.Get<OpenIddictClientTransaction>(typeof(OpenIddictClientTransaction).FullName)?.Request;
    }

    /// <summary>
    /// Retrieves the <see cref="OpenIddictResponse"/> instance stored in <see cref="BaseContext"/>.
    /// </summary>
    /// <param name="context">The context instance.</param>
    /// <returns>The <see cref="OpenIddictResponse"/> instance or <see langword="null"/> if it couldn't be found.</returns>
    public static OpenIddictResponse? GetOpenIddictClientResponse(this IOwinContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return context.Get<OpenIddictClientTransaction>(typeof(OpenIddictClientTransaction).FullName)?.Response;
    }
}
