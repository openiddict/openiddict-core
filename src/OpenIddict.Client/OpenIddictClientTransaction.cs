/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;

namespace OpenIddict.Client;

/// <summary>
/// Represents the context associated with an OpenID Connect client operation.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictClientTransaction
{
    /// <summary>
    /// Gets the cancellation token used to determine if the operation was aborted.
    /// </summary>
    public required CancellationToken CancellationToken { get; init; }

    /// <summary>
    /// Gets or sets the type of the endpoint processing the current transaction.
    /// </summary>
    public OpenIddictClientEndpointType EndpointType { get; set; }

    /// <summary>
    /// Gets or sets the request <see cref="Uri"/> of the current transaction, if available.
    /// </summary>
    public Uri? RequestUri { get; set; }

    /// <summary>
    /// Gets or sets the base <see cref="Uri"/> of the host, if available.
    /// </summary>
    public Uri? BaseUri { get; set; }

    /// <summary>
    /// Gets the options associated with the current transaction.
    /// </summary>
    public required OpenIddictClientOptions Options
    {
        get;
        init { ArgumentNullException.ThrowIfNull(value); field = value; } 
    }

    /// <summary>
    /// Gets the additional properties associated with the current transaction.
    /// </summary>
    public Dictionary<string, object?> Properties { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Gets or sets the client registration used for the current transaction.
    /// </summary>
    public OpenIddictClientRegistration Registration
    {
        get;
        set { ArgumentNullException.ThrowIfNull(value); field = value; }
    } = default!;

    /// <summary>
    /// Gets or sets the server configuration used for the current transaction.
    /// </summary>
    public OpenIddictConfiguration Configuration
    {
        get;
        set { ArgumentNullException.ThrowIfNull(value); field = value; }
    } = default!;

    /// <summary>
    /// Gets or sets the current OpenID Connect request.
    /// </summary>
    public OpenIddictRequest? Request { get; set; }

    /// <summary>
    /// Gets or sets the current OpenID Connect response being returned.
    /// </summary>
    public OpenIddictResponse? Response { get; set; }

    /// <summary>
    /// Gets the service provider used to resolve services.
    /// </summary>
    public required IServiceProvider ServiceProvider
    {
        get;
        init { ArgumentNullException.ThrowIfNull(value); field = value; }
    }
}
