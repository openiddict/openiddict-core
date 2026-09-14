/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Server;

/// <summary>
/// Exposes the constants defined by the FAPI 2.0 security profile
/// (https://openid.net/specs/fapi-security-profile-2_0-final.html).
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public static class OpenIddictServerFapi2Profile
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
        OpenIddictConstants.ClientAuthenticationMethods.SelfSignedTlsClientAuth,
        OpenIddictConstants.ClientAuthenticationMethods.TlsClientAuth
    ];

    /// <summary>
    /// Gets the maximum lifetime of authorization codes (section 5.3.2.1, item 11).
    /// </summary>
    public static TimeSpan MaximumAuthorizationCodeLifetime { get; } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Gets the exclusive upper bound of the lifetime of pushed authorization request URIs (section 5.3.2.2, item 12).
    /// </summary>
    public static TimeSpan MaximumRequestUriLifetime { get; } = TimeSpan.FromSeconds(600);

    /// <summary>
    /// Gets the request URI lifetime applied by the profile when the configured value is not compliant.
    /// </summary>
    public static TimeSpan DefaultRequestUriLifetime { get; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Gets the maximum offset allowed for "iat" and "nbf" dates in the future (section 5.3.2.1, item 13).
    /// </summary>
    public static TimeSpan MaximumFutureDateOffset { get; } = TimeSpan.FromSeconds(60);
}
