/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Net.Http;
using System.Net.Http.Headers;

namespace OpenIddict.Server.SystemNetHttp;

/// <summary>
/// Provides various settings needed to configure the OpenIddict server/System.Net.Http integration.
/// </summary>
public sealed class OpenIddictServerSystemNetHttpOptions
{
    /// <summary>
    /// Gets or sets the timeout applied to the HTTP requests sent to client notification and back-channel logout endpoints.
    /// The default value is 30 seconds.
    /// </summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Gets or sets the product information used in the "User-Agent" header that is
    /// attached to the HTTP requests sent to client notification endpoints.
    /// </summary>
    public ProductInfoHeaderValue? ProductInformation { get; set; }

    /// <summary>
    /// Gets the user-defined actions used to amend the <see cref="HttpClient"/>
    /// instances created by the OpenIddict server/System.Net.Http integration.
    /// </summary>
    public List<Action<HttpClient>> HttpClientActions { get; } = [];

    /// <summary>
    /// Gets the user-defined actions used to amend the <see cref="HttpClientHandler"/>
    /// instances created by the OpenIddict server/System.Net.Http integration.
    /// </summary>
    public List<Action<HttpClientHandler>> HttpClientHandlerActions { get; } = [];
}
