/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Client.Saml;

/// <summary>
/// Stores the identifiers of the assertions already consumed by the service provider to prevent replay attacks
/// (SAML profiles, 4.1.4.5). The default implementation is in-memory: applications deployed on multiple
/// instances SHOULD register an implementation backed by a distributed store.
/// </summary>
public interface IOpenIddictClientSamlReplayCache
{
    /// <summary>
    /// Atomically adds the specified key to the cache if it is not already present.
    /// </summary>
    /// <param name="key">The key identifying the assertion.</param>
    /// <param name="expirationDate">The date after which the entry can be removed.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns><see langword="true"/> if the key was added, <see langword="false"/> if it was already present.</returns>
    ValueTask<bool> TryAddAsync(string key, DateTimeOffset expirationDate, CancellationToken cancellationToken);
}
