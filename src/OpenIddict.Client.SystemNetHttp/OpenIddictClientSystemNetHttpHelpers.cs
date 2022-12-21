/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using OpenIddict.Client;

namespace System.Net.Http;

/// <summary>
/// Exposes companion extensions for the OpenIddict/System.Net.Http integration.
/// </summary>
public static class OpenIddictClientSystemNetHttpHelpers
{
    /// <summary>
    /// Gets the <see cref="HttpClient"/> associated with the current context.
    /// </summary>
    /// <param name="transaction">The transaction instance.</param>
    /// <returns>The <see cref="HttpClient"/> instance or <see langword="null"/> if it couldn't be found.</returns>
    public static HttpClient? GetHttpClient(this OpenIddictClientTransaction transaction)
        => transaction.GetProperty<HttpClient>(typeof(HttpClient).FullName!);

    /// <summary>
    /// Gets the <see cref="HttpRequestMessage"/> associated with the current context.
    /// </summary>
    /// <param name="transaction">The transaction instance.</param>
    /// <returns>The <see cref="HttpRequestMessage"/> instance or <see langword="null"/> if it couldn't be found.</returns>
    public static HttpRequestMessage? GetHttpRequestMessage(this OpenIddictClientTransaction transaction)
        => transaction.GetProperty<HttpRequestMessage>(typeof(HttpRequestMessage).FullName!);

    /// <summary>
    /// Gets the <see cref="HttpResponseMessage"/> associated with the current context.
    /// </summary>
    /// <param name="transaction">The transaction instance.</param>
    /// <returns>The <see cref="HttpResponseMessage"/> instance or <see langword="null"/> if it couldn't be found.</returns>
    public static HttpResponseMessage? GetHttpResponseMessage(this OpenIddictClientTransaction transaction)
        => transaction.GetProperty<HttpResponseMessage>(typeof(HttpResponseMessage).FullName!);
}
