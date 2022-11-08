/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Net;
using System.Net.Http.Headers;
using Polly;
using Polly.Extensions.Http;

namespace OpenIddict.Client.SystemNetHttp;

/// <summary>
/// Provides various settings needed to configure the OpenIddict client/System.Net.Http integration.
/// </summary>
public sealed class OpenIddictClientSystemNetHttpOptions
{
    /// <summary>
    /// Gets or sets the HTTP Polly error policy used by the internal OpenIddict HTTP clients.
    /// </summary>
    public IAsyncPolicy<HttpResponseMessage>? HttpErrorPolicy { get; set; }
        = HttpPolicyExtensions.HandleTransientHttpError()
            .OrResult(response => response.StatusCode == HttpStatusCode.NotFound)
            .WaitAndRetryAsync(4, attempt => TimeSpan.FromSeconds(Math.Pow(2, attempt)));

    /// <summary>
    /// Gets or sets the product information used in the user agent header that is
    /// attached to the backchannel HTTP requests sent to the authorization server.
    /// </summary>
    public ProductInfoHeaderValue? ProductInformation { get; set; }
}
