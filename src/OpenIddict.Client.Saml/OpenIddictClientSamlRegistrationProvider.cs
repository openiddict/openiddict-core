/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using Microsoft.Extensions.Options;

namespace OpenIddict.Client.Saml;

/// <summary>
/// Provides the static registrations attached to <see cref="OpenIddictClientSamlOptions.Registrations"/>.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictClientSamlRegistrationProvider : IOpenIddictClientSamlRegistrationProvider
{
    private readonly IOptionsMonitor<OpenIddictClientSamlOptions> _options;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientSamlRegistrationProvider"/> class.
    /// </summary>
    /// <param name="options">The SAML options.</param>
    public OpenIddictClientSamlRegistrationProvider(IOptionsMonitor<OpenIddictClientSamlOptions> options)
        => _options = options ?? throw new ArgumentNullException(nameof(options));

    /// <inheritdoc/>
    public ValueTask<OpenIddictClientSamlRegistration?> FindByIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        return new(_options.CurrentValue.Registrations.Find(registration => string.Equals(
            registration.RegistrationId, identifier, StringComparison.Ordinal)));
    }

    /// <inheritdoc/>
    public ValueTask<ImmutableArray<OpenIddictClientSamlRegistration>> FindByEntityIdAsync(string entityId, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(entityId);

        return new([.. _options.CurrentValue.Registrations.FindAll(registration => string.Equals(
            registration.IdentityProviderEntityId, entityId, StringComparison.Ordinal))]);
    }

    /// <inheritdoc/>
    public ValueTask<ImmutableArray<OpenIddictClientSamlRegistration>> FindByProviderNameAsync(string name, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);

        return new([.. _options.CurrentValue.Registrations.FindAll(registration => string.Equals(
            registration.ProviderName, name, StringComparison.Ordinal))]);
    }

    /// <inheritdoc/>
    public ValueTask<ImmutableArray<OpenIddictClientSamlRegistration>> ListAsync(CancellationToken cancellationToken)
        => new([.. _options.CurrentValue.Registrations]);
}
