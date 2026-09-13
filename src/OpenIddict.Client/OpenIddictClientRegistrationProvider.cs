/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using Microsoft.Extensions.Options;

namespace OpenIddict.Client;

/// <summary>
/// Provides the static client registrations attached to <see cref="OpenIddictClientOptions.Registrations"/>.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictClientRegistrationProvider : IOpenIddictClientRegistrationProvider
{
    private readonly IOptionsMonitor<OpenIddictClientOptions> _options;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientRegistrationProvider"/> class.
    /// </summary>
    /// <param name="options">The OpenIddict client options.</param>
    public OpenIddictClientRegistrationProvider(IOptionsMonitor<OpenIddictClientOptions> options)
        => _options = options ?? throw new ArgumentNullException(nameof(options));

    /// <inheritdoc/>
    public ValueTask<OpenIddictClientRegistration?> FindByIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        return new(_options.CurrentValue.Registrations.Find(registration => string.Equals(
            registration.RegistrationId, identifier, StringComparison.Ordinal)));
    }

    /// <inheritdoc/>
    public ValueTask<ImmutableArray<OpenIddictClientRegistration>> FindByIssuerAsync(Uri issuer, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(issuer);

        return new([.. _options.CurrentValue.Registrations.FindAll(registration => registration.Issuer == issuer)]);
    }

    /// <inheritdoc/>
    public ValueTask<ImmutableArray<OpenIddictClientRegistration>> FindByProviderNameAsync(string name, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);

        return new([.. _options.CurrentValue.Registrations.FindAll(registration => string.Equals(
            registration.ProviderName, name, StringComparison.Ordinal))]);
    }

    /// <inheritdoc/>
    public ValueTask<ImmutableArray<OpenIddictClientRegistration>> ListAsync(CancellationToken cancellationToken)
        => new([.. _options.CurrentValue.Registrations]);
}
