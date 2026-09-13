/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.Options;

namespace OpenIddict.Server.Saml;

/// <summary>
/// Resolves the SAML service providers registered in <see cref="OpenIddictServerSamlOptions.ServiceProviders"/>.
/// </summary>
public sealed class OpenIddictServerSamlServiceProviderStore : IOpenIddictServerSamlServiceProviderStore
{
    private readonly IOptionsMonitor<OpenIddictServerSamlOptions> _options;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictServerSamlServiceProviderStore"/> class.
    /// </summary>
    /// <param name="options">The SAML options.</param>
    public OpenIddictServerSamlServiceProviderStore(IOptionsMonitor<OpenIddictServerSamlOptions> options)
        => _options = options ?? throw new ArgumentNullException(nameof(options));

    /// <inheritdoc/>
    public ValueTask<OpenIddictServerSamlServiceProvider?> FindByEntityIdAsync(string entityId, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(entityId);

        return new(_options.CurrentValue.ServiceProviders.Find(provider =>
            string.Equals(provider.EntityId, entityId, StringComparison.Ordinal)));
    }
}
