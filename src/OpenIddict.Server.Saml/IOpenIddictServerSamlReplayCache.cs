/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Server.Saml;

/// <summary>
/// Provides methods allowing to detect replayed SAML messages (authentication request
/// identifiers and request states) when request replay protection is enabled.
/// </summary>
/// <remarks>
/// Implementations are resolved from the request services and can be registered with any lifetime.
/// In load-balanced deployments, implementations must be shared by all the instances and should
/// use an atomic "add if not exists" operation to prevent concurrent requests from being accepted.
/// </remarks>
public interface IOpenIddictServerSamlReplayCache
{
    /// <summary>
    /// Adds the specified identifier to the cache, unless it is already present.
    /// </summary>
    /// <param name="identifier">The identifier (an opaque value that doesn't need to be hashed by the implementation).</param>
    /// <param name="expirationDate">The date after which the identifier can be removed from the cache.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// <see langword="true"/> if the identifier was added (first use), <see langword="false"/> if it was already present.
    /// </returns>
    ValueTask<bool> TryAddAsync(string identifier, DateTimeOffset expirationDate, CancellationToken cancellationToken);
}
