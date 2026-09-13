/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Server;

/// <summary>
/// Represents the signing and encryption credentials used by the server for a given operation.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictServerCredentials
{
    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictServerCredentials"/> class.
    /// </summary>
    /// <param name="signingCredentials">The signing credentials, the preferred credentials first.</param>
    /// <param name="encryptionCredentials">The encryption credentials, the preferred credentials first.</param>
    public OpenIddictServerCredentials(
        IReadOnlyList<SigningCredentials> signingCredentials,
        IReadOnlyList<EncryptingCredentials> encryptionCredentials)
    {
        SigningCredentials = signingCredentials ?? throw new ArgumentNullException(nameof(signingCredentials));
        EncryptionCredentials = encryptionCredentials ?? throw new ArgumentNullException(nameof(encryptionCredentials));
    }

    /// <summary>
    /// Gets the encryption credentials, the preferred credentials first.
    /// </summary>
    public IReadOnlyList<EncryptingCredentials> EncryptionCredentials { get; }

    /// <summary>
    /// Gets the signing credentials, the preferred credentials first.
    /// </summary>
    /// <remarks>
    /// Note: keys that are announced but not active yet are included, so they can be published.
    /// </remarks>
    public IReadOnlyList<SigningCredentials> SigningCredentials { get; }
}
