/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Server.Saml;

/// <summary>
/// Sends SAML messages using the SOAP binding (SAML bindings, 3.2), e.g back-channel logout requests.
/// </summary>
public interface IOpenIddictServerSamlSoapClient
{
    /// <summary>
    /// Sends the specified SOAP envelope and returns the SOAP envelope returned by the remote endpoint.
    /// </summary>
    /// <param name="url">The URL of the SOAP endpoint.</param>
    /// <param name="envelope">The serialized SOAP envelope.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// The serialized SOAP envelope returned by the endpoint, or <see langword="null"/>
    /// if the request failed (e.g network error, SOAP fault or unsuccessful status code).
    /// </returns>
    ValueTask<string?> SendAsync(Uri url, string envelope, CancellationToken cancellationToken);
}
