/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Client;

/// <summary>
/// Exposes the constants defined by the FAPI 2.0 security profile for client applications
/// (https://openid.net/specs/fapi-security-profile-2_0-final.html).
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public static class OpenIddictClientFapi2Profile
{
    /// <summary>
    /// Gets the JWS algorithms allowed by the profile (section 5.4.1).
    /// </summary>
    public static ImmutableArray<string> SigningAlgorithms { get; } =
    [
        SecurityAlgorithms.RsaSsaPssSha256,
        SecurityAlgorithms.EcdsaSha256,
        "EdDSA"
    ];

    /// <summary>
    /// Gets the client authentication methods allowed by the profile (section 5.3.2.1, item 6).
    /// </summary>
    public static ImmutableArray<string> ClientAuthenticationMethods { get; } =
    [
        OpenIddictConstants.ClientAuthenticationMethods.PrivateKeyJwt,
        OpenIddictConstants.ClientAuthenticationMethods.TlsClientAuth,
        OpenIddictConstants.ClientAuthenticationMethods.SelfSignedTlsClientAuth
    ];

    /// <summary>
    /// Gets the token binding methods allowed by the profile (section 5.3.3.1, item 2).
    /// </summary>
    public static ImmutableArray<string> TokenBindingMethods { get; } =
    [
        OpenIddictConstants.TokenBindingMethods.Private.DPoP,
        OpenIddictConstants.TokenBindingMethods.Private.SelfSignedTlsClientCertificate,
        OpenIddictConstants.TokenBindingMethods.Private.TlsClientCertificate
    ];

    /// <summary>
    /// Determines whether the specified algorithm is allowed by the profile,
    /// taking the XML digital signature aliases used by IdentityModel into account.
    /// </summary>
    /// <param name="algorithm">The algorithm.</param>
    /// <returns><see langword="true"/> if the algorithm is allowed, <see langword="false"/> otherwise.</returns>
    public static bool IsSigningAlgorithmAllowed(string? algorithm) => algorithm switch
    {
        SecurityAlgorithms.RsaSsaPssSha256Signature => true,
        SecurityAlgorithms.EcdsaSha256Signature     => true,
        { Length: > 0 } value => SigningAlgorithms.Contains(value, StringComparer.Ordinal),
        _ => false
    };
}
