/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Server;

/// <summary>
/// Protects the private key material of the keys created by the automatic key management feature.
/// </summary>
/// <remarks>
/// Implementations must be able to unprotect payloads protected by any instance of the application.
/// </remarks>
public interface IOpenIddictServerKeyProtector
{
    /// <summary>
    /// Protects the specified key material.
    /// </summary>
    /// <param name="payload">The serialized key material.</param>
    /// <returns>The protected key material.</returns>
    string Protect(string payload);

    /// <summary>
    /// Unprotects the specified key material.
    /// </summary>
    /// <param name="payload">The protected key material.</param>
    /// <returns>The serialized key material.</returns>
    string Unprotect(string payload);
}
