/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Server;

/// <summary>
/// Represents the context used by <see cref="IOpenIddictServerIssuerResolver"/> to resolve the issuer of a request.
/// </summary>
public sealed class OpenIddictServerIssuerResolutionContext
{
    /// <summary>
    /// Gets the base URI of the host (e.g the scheme, host and path base of the HTTP request).
    /// </summary>
    public required Uri BaseUri
    {
        get;
        init { ArgumentNullException.ThrowIfNull(value); field = value; }
    }

    /// <summary>
    /// Gets the <see cref="System.Threading.CancellationToken"/> that can be used to abort the operation.
    /// </summary>
    public CancellationToken CancellationToken { get; init; }

    /// <summary>
    /// Gets the server options.
    /// </summary>
    public required OpenIddictServerOptions Options
    {
        get;
        init { ArgumentNullException.ThrowIfNull(value); field = value; }
    }

    /// <summary>
    /// Gets the host-specific properties associated with the current request (e.g the ASP.NET Core
    /// HttpRequest or the OWIN request, stored using their full type name as the property name).
    /// </summary>
    public required IReadOnlyDictionary<string, object?> Properties
    {
        get;
        init { ArgumentNullException.ThrowIfNull(value); field = value; }
    }

    /// <summary>
    /// Gets the absolute URI of the current request.
    /// </summary>
    public required Uri RequestUri
    {
        get;
        init { ArgumentNullException.ThrowIfNull(value); field = value; }
    }

    /// <summary>
    /// Gets the service provider used to resolve services.
    /// </summary>
    public required IServiceProvider ServiceProvider
    {
        get;
        init { ArgumentNullException.ThrowIfNull(value); field = value; }
    }
}
