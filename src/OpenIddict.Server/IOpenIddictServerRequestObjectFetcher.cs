/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Server;

/// <summary>
/// Retrieves the request objects passed by reference using an external "request_uri" parameter
/// (RFC 9101, section 5.2 and OpenID Connect Core, section 6.2).
/// </summary>
/// <remarks>
/// Implementations are responsible for the transport-level protections (e.g SSRF mitigations,
/// timeouts, response size limits and caching). The OpenIddict server validates the URI format,
/// the per-client registration, the optional SHA-256 fragment and the request object itself.
/// </remarks>
public interface IOpenIddictServerRequestObjectFetcher
{
    /// <summary>
    /// Retrieves the request object referenced by the specified absolute HTTPS URI.
    /// </summary>
    /// <param name="uri">The absolute HTTPS URI referencing the request object.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation, whose result
    /// returns the raw request object or <see langword="null"/> if it couldn't be retrieved.
    /// </returns>
    ValueTask<string?> FetchAsync(Uri uri, CancellationToken cancellationToken);
}
