/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.Logging;

namespace OpenIddict.Client;

/// <summary>
/// Represents the context associated with an OpenID Connect client request.
/// </summary>
public class OpenIddictClientTransaction
{
    /// <summary>
    /// Gets or sets the type of the endpoint processing the current request.
    /// </summary>
    public OpenIddictClientEndpointType EndpointType { get; set; }

    /// <summary>
    /// Gets or sets the issuer address associated with the current transaction, if available.
    /// </summary>
    public Uri? Issuer { get; set; }

    /// <summary>
    /// Gets or sets the logger associated with the current request.
    /// </summary>
    public ILogger Logger { get; set; } = default!;

    /// <summary>
    /// Gets or sets the options associated with the current request.
    /// </summary>
    public OpenIddictClientOptions Options { get; set; } = default!;

    /// <summary>
    /// Gets the additional properties associated with the current request.
    /// </summary>
    public Dictionary<string, object?> Properties { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Gets or sets the client registration used for the current request.
    /// </summary>
    public OpenIddictClientRegistration Registration { get; set; } = default!;

    /// <summary>
    /// Gets or sets the server configuration used for the current request.
    /// </summary>
    public OpenIddictConfiguration Configuration { get; set; } = default!;

    /// <summary>
    /// Gets or sets the current OpenID Connect request.
    /// </summary>
    public OpenIddictRequest? Request { get; set; }

    /// <summary>
    /// Gets or sets the current OpenID Connect response being returned.
    /// </summary>
    public OpenIddictResponse? Response { get; set; }
}
