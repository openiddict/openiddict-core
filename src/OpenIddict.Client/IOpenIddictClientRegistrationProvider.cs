/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;

namespace OpenIddict.Client;

/// <summary>
/// Represents a source of client registrations resolved at runtime by the OpenIddict client services.
/// </summary>
/// <remarks>
/// <list type="bullet">
///   <item><description>
///     Multiple providers can be registered: they are queried in registration order, after the
///     built-in provider returning the static registrations attached to the client options.
///   </description></item>
///   <item><description>
///     Dynamic registrations are initialized (default registration identifier, client type, configuration manager)
///     and validated by OpenIddict when they are first resolved. They MUST only use redirect and post-logout
///     redirect URIs that are declared in the client options (e.g using <c>SetRedirectionEndpointUris()</c>).
///   </description></item>
///   <item><description>
///     Registrations resolved by identifier are cached for <see cref="OpenIddictClientOptions.DynamicRegistrationCacheLifetime"/>.
///   </description></item>
/// </list>
/// </remarks>
public interface IOpenIddictClientRegistrationProvider
{
    /// <summary>
    /// Resolves the client registration corresponding to the specified identifier.
    /// </summary>
    /// <param name="identifier">The registration identifier.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The client registration, or <see langword="null"/> if it cannot be found.</returns>
    ValueTask<OpenIddictClientRegistration?> FindByIdAsync(string identifier, CancellationToken cancellationToken);

    /// <summary>
    /// Resolves the client registrations corresponding to the specified issuer.
    /// </summary>
    /// <param name="issuer">The issuer.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The client registrations corresponding to the specified issuer.</returns>
    ValueTask<ImmutableArray<OpenIddictClientRegistration>> FindByIssuerAsync(Uri issuer, CancellationToken cancellationToken);

    /// <summary>
    /// Resolves the client registrations corresponding to the specified provider name.
    /// </summary>
    /// <param name="name">The provider name.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The client registrations corresponding to the specified provider name.</returns>
    ValueTask<ImmutableArray<OpenIddictClientRegistration>> FindByProviderNameAsync(string name, CancellationToken cancellationToken);

    /// <summary>
    /// Lists the client registrations managed by this provider.
    /// </summary>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// The client registrations managed by this provider. Providers that
    /// cannot enumerate their registrations can return an empty array.
    /// </returns>
    ValueTask<ImmutableArray<OpenIddictClientRegistration>> ListAsync(CancellationToken cancellationToken);
}
