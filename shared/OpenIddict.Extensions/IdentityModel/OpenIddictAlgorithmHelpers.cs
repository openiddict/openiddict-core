/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Extensions;

/// <summary>
/// Exposes the helpers used to restrict the algorithms accepted when validating JSON Web Tokens.
/// </summary>
internal static class OpenIddictAlgorithmHelpers
{
    /// <summary>
    /// Creates an <see cref="AlgorithmValidator"/> that only restricts the JWS signing algorithms.
    /// </summary>
    /// <remarks>
    /// Unlike <see cref="TokenValidationParameters.ValidAlgorithms"/>, which IdentityModel also applies to
    /// the JWE key management and content encryption algorithms ("alg"/"enc" headers of encrypted tokens),
    /// the returned validator ignores the algorithms of encrypted tokens (which are implicitly restricted
    /// by the configured decryption keys) and only applies the list to the signature of the (inner) JWS.
    /// If <paramref name="parameters"/> already defines an algorithm validator or valid algorithms,
    /// they are also enforced.
    /// </remarks>
    /// <param name="algorithms">The allowed signing algorithms.</param>
    /// <param name="parameters">The token validation parameters whose existing restrictions must be preserved.</param>
    /// <returns>The algorithm validator.</returns>
    public static AlgorithmValidator CreateSigningAlgorithmValidator(
        IEnumerable<string> algorithms, TokenValidationParameters? parameters = null)
    {
        ArgumentNullException.ThrowIfNull(algorithms);

        var allowed = new HashSet<string>(algorithms, StringComparer.Ordinal);
        var validator = parameters?.AlgorithmValidator;
        var list = parameters?.ValidAlgorithms?.ToArray();

        return (algorithm, key, token, parameters) =>
        {
            if (validator is not null)
            {
                if (!validator(algorithm, key, token, parameters))
                {
                    return false;
                }
            }

            else if (list is { Length: > 0 } && !list.Contains(algorithm, StringComparer.Ordinal))
            {
                return false;
            }

            // Note: the "alg" and "enc" headers of JWE tokens are not signing algorithms.
            if (token is JsonWebToken { IsEncrypted: true })
            {
                return true;
            }

            return allowed.Contains(algorithm);
        };
    }
}
