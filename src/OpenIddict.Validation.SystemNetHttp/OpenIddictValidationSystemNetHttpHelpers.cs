/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using OpenIddict.Validation;

namespace System.Net.Http;

/// <summary>
/// Exposes companion extensions for the OpenIddict/System.Net.Http integration.
/// </summary>
public static class OpenIddictValidationSystemNetHttpHelpers
{
    /// <summary>
    /// Gets the <see cref="HttpRequestMessage"/> associated with the current context.
    /// </summary>
    /// <param name="transaction">The transaction instance.</param>
    /// <returns>The <see cref="HttpRequestMessage"/> instance or <c>null</c> if it couldn't be found.</returns>
    public static HttpRequestMessage? GetHttpRequestMessage(this OpenIddictValidationTransaction transaction)
        => transaction.GetProperty<HttpRequestMessage>(typeof(HttpRequestMessage).FullName!);

    /// <summary>
    /// Gets the <see cref="HttpResponseMessage"/> associated with the current context.
    /// </summary>
    /// <param name="transaction">The transaction instance.</param>
    /// <returns>The <see cref="HttpResponseMessage"/> instance or <c>null</c> if it couldn't be found.</returns>
    public static HttpResponseMessage? GetHttpResponseMessage(this OpenIddictValidationTransaction transaction)
        => transaction.GetProperty<HttpResponseMessage>(typeof(HttpResponseMessage).FullName!);
}
