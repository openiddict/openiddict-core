/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Client.Saml;

/// <summary>
/// Retrieves SAML metadata documents.
/// </summary>
public interface IOpenIddictClientSamlMetadataRetriever
{
    /// <summary>
    /// Retrieves the metadata document located at the specified address.
    /// </summary>
    /// <param name="address">The address (HTTPS or file URI) of the metadata document.</param>
    /// <param name="maximumSize">The maximum size, in bytes, of the document.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The raw metadata document.</returns>
    /// <exception cref="InvalidOperationException">The document cannot be retrieved or is too large.</exception>
    ValueTask<byte[]> RetrieveAsync(Uri address, int maximumSize, CancellationToken cancellationToken);
}
