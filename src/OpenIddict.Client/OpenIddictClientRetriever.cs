/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.IdentityModel.Protocols;

namespace OpenIddict.Client;

public class OpenIddictClientRetriever : IConfigurationRetriever<OpenIddictConfiguration>
{
    private readonly OpenIddictClientService _service;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientRetriever"/> class.
    /// </summary>
    /// <param name="service">The validation service.</param>
    public OpenIddictClientRetriever(OpenIddictClientService service!!)
        => _service = service;

    /// <summary>
    /// Retrieves the OpenID Connect server configuration from the specified address.
    /// </summary>
    /// <param name="address">The address of the remote metadata endpoint.</param>
    /// <param name="retriever">The retriever used by IdentityModel.</param>
    /// <param name="cancel">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The OpenID Connect server configuration retrieved from the remote server.</returns>
    async Task<OpenIddictConfiguration> IConfigurationRetriever<OpenIddictConfiguration>.GetConfigurationAsync(
        string address, IDocumentRetriever retriever, CancellationToken cancel)
    {
        if (string.IsNullOrEmpty(address))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0143), nameof(address));
        }

        if (!Uri.TryCreate(address, UriKind.Absolute, out Uri? uri) || !uri.IsWellFormedOriginalString())
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0144), nameof(address));
        }

        cancel.ThrowIfCancellationRequested();

        var configuration = await _service.GetConfigurationAsync(uri, cancel) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0145));

        if (configuration.JwksUri is null)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0146));
        }

        configuration.JsonWebKeySet = await _service.GetSecurityKeysAsync(configuration.JwksUri, cancel) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0147));

        // Copy the signing keys found in the JSON Web Key Set to the SigningKeys collection.
        foreach (var key in configuration.JsonWebKeySet.GetSigningKeys())
        {
            configuration.SigningKeys.Add(key);
        }

        return configuration;
    }
}
