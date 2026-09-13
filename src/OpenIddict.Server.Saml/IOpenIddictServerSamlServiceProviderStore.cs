/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Server.Saml;

/// <summary>
/// Provides methods allowing to resolve the SAML service providers allowed to use the identity provider.
/// </summary>
/// <remarks>
/// Implementations are resolved from the request services and can be registered with any lifetime.
/// The returned service providers are validated before being used.
/// </remarks>
public interface IOpenIddictServerSamlServiceProviderStore
{
    /// <summary>
    /// Retrieves a service provider using its entity identifier.
    /// </summary>
    /// <param name="entityId">The entity identifier (compared using an ordinal comparison).</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The service provider corresponding to the entity identifier, or <see langword="null"/>.</returns>
    ValueTask<OpenIddictServerSamlServiceProvider?> FindByEntityIdAsync(string entityId, CancellationToken cancellationToken);
}
