/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;

namespace OpenIddict.Client.Saml;

/// <summary>
/// Represents a source of SAML identity provider registrations resolved at runtime (e.g from a database).
/// </summary>
/// <remarks>
/// <list type="bullet">
///   <item><description>
///     Multiple providers can be registered: they are queried in registration order, after the
///     built-in provider returning the static registrations attached to the SAML options.
///   </description></item>
///   <item><description>
///     Dynamic registrations are validated when they are first resolved and cached by identifier for
///     <see cref="OpenIddictClientSamlOptions.DynamicRegistrationCacheLifetime"/>.
///   </description></item>
/// </list>
/// </remarks>
public interface IOpenIddictClientSamlRegistrationProvider
{
    /// <summary>
    /// Resolves the registration corresponding to the specified identifier.
    /// </summary>
    /// <param name="identifier">The registration identifier.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The registration, or <see langword="null"/> if it cannot be found.</returns>
    ValueTask<OpenIddictClientSamlRegistration?> FindByIdAsync(string identifier, CancellationToken cancellationToken);

    /// <summary>
    /// Resolves the registrations corresponding to the specified identity provider entity identifier
    /// (used to resolve the registration of unsolicited responses).
    /// </summary>
    /// <param name="entityId">The entity identifier of the identity provider.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The registrations corresponding to the specified entity identifier.</returns>
    ValueTask<ImmutableArray<OpenIddictClientSamlRegistration>> FindByEntityIdAsync(string entityId, CancellationToken cancellationToken);

    /// <summary>
    /// Resolves the registrations corresponding to the specified provider name.
    /// </summary>
    /// <param name="name">The provider name.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The registrations corresponding to the specified provider name.</returns>
    ValueTask<ImmutableArray<OpenIddictClientSamlRegistration>> FindByProviderNameAsync(string name, CancellationToken cancellationToken);

    /// <summary>
    /// Lists the registrations managed by this provider.
    /// </summary>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// The registrations managed by this provider. Providers that
    /// cannot enumerate their registrations can return an empty array.
    /// </returns>
    ValueTask<ImmutableArray<OpenIddictClientSamlRegistration>> ListAsync(CancellationToken cancellationToken);
}
