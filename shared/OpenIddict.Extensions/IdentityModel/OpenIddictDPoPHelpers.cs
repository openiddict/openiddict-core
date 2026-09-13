/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Buffers.Text;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Extensions;

/// <summary>
/// Exposes the helpers used to create and validate OAuth 2.0 Demonstrating Proof of Possession (DPoP) proofs.
/// </summary>
/// <remarks>
/// See https://datatracker.ietf.org/doc/html/rfc9449 for more information.
/// </remarks>
internal static class OpenIddictDPoPHelpers
{
    /// <summary>
    /// Represents the errors that can be returned when validating a DPoP proof.
    /// </summary>
    internal enum ProofError
    {
        None = 0,
        Malformed,
        InvalidType,
        InvalidAlgorithm,
        InvalidKey,
        InvalidSignature,
        InvalidClaim
    }

    /// <summary>
    /// Represents the result of a DPoP proof validation.
    /// </summary>
    /// <param name="Error">The error, if applicable.</param>
    /// <param name="Claim">The name of the missing or invalid claim, if applicable.</param>
    /// <param name="Token">The validated proof.</param>
    /// <param name="Thumbprint">The RFC 7638 thumbprint of the public key contained in the proof.</param>
    internal sealed record class ProofValidationResult(
        ProofError Error, string? Claim, JsonWebToken? Token, string? Thumbprint);

    /// <summary>
    /// Gets the asymmetric signing algorithms that can be used to create DPoP proofs.
    /// </summary>
    internal static IReadOnlyList<string> SupportedAlgorithms { get; } =
    [
        SecurityAlgorithms.EcdsaSha256,
        SecurityAlgorithms.EcdsaSha384,
        SecurityAlgorithms.EcdsaSha512,
        SecurityAlgorithms.RsaSha256,
        SecurityAlgorithms.RsaSha384,
        SecurityAlgorithms.RsaSha512,
        SecurityAlgorithms.RsaSsaPssSha256,
        SecurityAlgorithms.RsaSsaPssSha384,
        SecurityAlgorithms.RsaSsaPssSha512
    ];

    /// <summary>
    /// Computes the "ath" value (i.e the base64url-encoded SHA-256 hash of the ASCII representation) of an access token.
    /// </summary>
    /// <param name="token">The access token.</param>
    /// <returns>The base64url-encoded hash.</returns>
    internal static string ComputeAccessTokenHash(string token)
    {
        ArgumentException.ThrowIfNullOrEmpty(token);

        return Base64Url.EncodeToString(SHA256.HashData(Encoding.ASCII.GetBytes(token)));
    }

    /// <summary>
    /// Determines whether the two specified strings are equal using a time-constant comparison.
    /// </summary>
    /// <param name="left">The first string.</param>
    /// <param name="right">The second string.</param>
    /// <returns><see langword="true"/> if the two strings are equal, <see langword="false"/> otherwise.</returns>
    internal static bool FixedTimeEquals(string? left, string? right)
    {
        if (left is null || right is null)
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(
            left : MemoryMarshal.AsBytes(left.AsSpan()),
            right: MemoryMarshal.AsBytes(right.AsSpan()));
    }

    /// <summary>
    /// Determines whether the specified "htu" value matches the specified request URI,
    /// ignoring the query string and fragment components, as required by RFC 9449.
    /// </summary>
    /// <param name="value">The "htu" value extracted from the DPoP proof.</param>
    /// <param name="uri">The request URI.</param>
    /// <returns><see langword="true"/> if the URIs match, <see langword="false"/> otherwise.</returns>
    internal static bool MatchesHttpUri(string? value, Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);

        if (string.IsNullOrEmpty(value) || !Uri.TryCreate(value, UriKind.Absolute, out Uri? candidate))
        {
            return false;
        }

        // Note: System.Uri automatically applies the syntax-based normalization rules defined in RFC 3986
        // (e.g scheme and host case normalization, removal of dot segments and default port elision).
        return string.Equals(candidate.Scheme, uri.Scheme, StringComparison.OrdinalIgnoreCase) &&
               string.Equals(candidate.Host, uri.Host, StringComparison.OrdinalIgnoreCase) &&
               candidate.Port == uri.Port &&
               string.Equals(candidate.AbsolutePath, uri.AbsolutePath, StringComparison.Ordinal);
    }

    /// <summary>
    /// Computes the RFC 7638 thumbprint of the public key attached to the specified signing credentials.
    /// </summary>
    /// <param name="credentials">The signing credentials.</param>
    /// <returns>The base64url-encoded thumbprint.</returns>
    internal static string ComputeJsonWebKeyThumbprint(SigningCredentials credentials)
    {
        ArgumentNullException.ThrowIfNull(credentials);

        return Base64UrlEncoder.Encode(new JsonWebKey(CreatePublicJsonWebKey(credentials.Key).ToJsonString()).ComputeJwkThumbprint());
    }

    /// <summary>
    /// Creates a DPoP proof using the specified signing credentials.
    /// </summary>
    /// <param name="credentials">The asymmetric signing credentials.</param>
    /// <param name="method">The HTTP method of the request.</param>
    /// <param name="uri">The URI of the request.</param>
    /// <param name="date">The issuance date.</param>
    /// <param name="token">The access token, if applicable.</param>
    /// <param name="nonce">The server-provided nonce, if applicable.</param>
    /// <returns>The DPoP proof.</returns>
    internal static string CreateProof(SigningCredentials credentials, string method,
        Uri uri, DateTimeOffset date, string? token, string? nonce)
    {
        ArgumentNullException.ThrowIfNull(credentials);
        ArgumentException.ThrowIfNullOrEmpty(method);
        ArgumentNullException.ThrowIfNull(uri);

        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [OpenIddictConstants.Claims.JwtId] = Guid.NewGuid().ToString(),
            [OpenIddictConstants.Claims.HttpMethod] = method,
            [OpenIddictConstants.Claims.HttpUri] = uri.GetLeftPart(UriPartial.Path),
            [OpenIddictConstants.Claims.IssuedAt] = date.ToUnixTimeSeconds()
        };

        if (!string.IsNullOrEmpty(token))
        {
            claims[OpenIddictConstants.Claims.DPoPAccessTokenHash] = ComputeAccessTokenHash(token);
        }

        if (!string.IsNullOrEmpty(nonce))
        {
            claims[OpenIddictConstants.Claims.Nonce] = nonce;
        }

        var key = CreatePublicJsonWebKey(credentials.Key);

        var handler = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false };

        return handler.CreateToken(new SecurityTokenDescriptor
        {
            AdditionalHeaderClaims = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [JwtHeaderParameterNames.Jwk] = key.ToDictionary(
                    static node => node.Key, static node => (object) (string) node.Value!, StringComparer.Ordinal)
            },
            Claims = claims,
            // Note: the key identifier is deliberately not included as the key is embedded in the proof.
            SigningCredentials = new SigningCredentials(CreateKeyWithoutIdentifier(credentials.Key), credentials.Algorithm),
            TokenType = OpenIddictConstants.JsonWebTokenTypes.DPoPProof
        });

        static SecurityKey CreateKeyWithoutIdentifier(SecurityKey key) => key switch
        {
            ECDsaSecurityKey { ECDsa: ECDsa algorithm } => new ECDsaSecurityKey(algorithm),
            RsaSecurityKey { Rsa: RSA algorithm } => new RsaSecurityKey(algorithm),
            RsaSecurityKey { Parameters: var parameters } => new RsaSecurityKey(parameters),
            X509SecurityKey { Certificate: X509Certificate2 certificate } => new X509SecurityKey(certificate) { KeyId = null },
            _ => key
        };
    }

    /// <summary>
    /// Validates the specified DPoP proof.
    /// </summary>
    /// <param name="proof">The DPoP proof.</param>
    /// <param name="method">The HTTP method of the request.</param>
    /// <param name="uri">The URI of the request.</param>
    /// <param name="algorithms">The allowed signing algorithms.</param>
    /// <param name="date">The current date.</param>
    /// <param name="lifetime">The maximum difference allowed between the current date and the "iat" claim.</param>
    /// <param name="token">The access token, if the "ath" claim must be validated.</param>
    /// <returns>The validation result.</returns>
    internal static async ValueTask<ProofValidationResult> ValidateProofAsync(string proof, string method, Uri uri,
        IReadOnlyCollection<string> algorithms, DateTimeOffset date, TimeSpan lifetime, string? token)
    {
        ArgumentException.ThrowIfNullOrEmpty(proof);
        ArgumentException.ThrowIfNullOrEmpty(method);
        ArgumentNullException.ThrowIfNull(uri);
        ArgumentNullException.ThrowIfNull(algorithms);

        var handler = new JsonWebTokenHandler();

        JsonWebToken jwt;

        try
        {
            if (!handler.CanReadToken(proof))
            {
                return new(ProofError.Malformed, null, null, null);
            }

            jwt = new JsonWebToken(proof);
        }

        catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
        {
            return new(ProofError.Malformed, null, null, null);
        }

        // DPoP proofs MUST be signed JSON Web Tokens (encrypted proofs are not allowed).
        if (jwt.IsEncrypted)
        {
            return new(ProofError.Malformed, null, null, null);
        }

        // DPoP proofs MUST use the "dpop+jwt" type.
        if (!string.Equals(jwt.Typ, OpenIddictConstants.JsonWebTokenTypes.DPoPProof, StringComparison.OrdinalIgnoreCase))
        {
            return new(ProofError.InvalidType, null, null, null);
        }

        // DPoP proofs MUST use an asymmetric algorithm (symmetric algorithms and "none" are never allowed).
        if (string.IsNullOrEmpty(jwt.Alg) || !SupportedAlgorithms.Contains(jwt.Alg, StringComparer.Ordinal) ||
            !algorithms.Contains(jwt.Alg, StringComparer.Ordinal))
        {
            return new(ProofError.InvalidAlgorithm, null, null, null);
        }

        // Resolve the public key from the "jwk" header.
        JsonWebKey key;
        string thumbprint;

        try
        {
            if (JsonNode.Parse(Base64Url.DecodeFromChars(jwt.EncodedHeader)) is not JsonObject header ||
                header[JwtHeaderParameterNames.Jwk] is not JsonObject node)
            {
                return new(ProofError.InvalidKey, null, null, null);
            }

            // The JSON Web Key MUST NOT contain a private key.
            foreach (var name in (string[]) [JsonWebKeyParameterNames.D, JsonWebKeyParameterNames.DP,
                JsonWebKeyParameterNames.DQ, JsonWebKeyParameterNames.K, JsonWebKeyParameterNames.Oth,
                JsonWebKeyParameterNames.P, JsonWebKeyParameterNames.Q, JsonWebKeyParameterNames.QI])
            {
                if (node.ContainsKey(name))
                {
                    return new(ProofError.InvalidKey, null, null, null);
                }
            }

            // Note: only elliptic curve and RSA keys are supported. To ensure the signature is always validated
            // using the key members the thumbprint is computed from, a minimal JSON Web Key containing only the
            // required members is created (e.g "x5c" or "x5u" must never be used to resolve the verification key).
            var minimal = (string?) node[JsonWebKeyParameterNames.Kty] switch
            {
                JsonWebAlgorithmsKeyTypes.EllipticCurve => new JsonObject
                {
                    [JsonWebKeyParameterNames.Crv] = (string?) node[JsonWebKeyParameterNames.Crv],
                    [JsonWebKeyParameterNames.Kty] = JsonWebAlgorithmsKeyTypes.EllipticCurve,
                    [JsonWebKeyParameterNames.X] = (string?) node[JsonWebKeyParameterNames.X],
                    [JsonWebKeyParameterNames.Y] = (string?) node[JsonWebKeyParameterNames.Y]
                },

                JsonWebAlgorithmsKeyTypes.RSA => new JsonObject
                {
                    [JsonWebKeyParameterNames.E] = (string?) node[JsonWebKeyParameterNames.E],
                    [JsonWebKeyParameterNames.Kty] = JsonWebAlgorithmsKeyTypes.RSA,
                    [JsonWebKeyParameterNames.N] = (string?) node[JsonWebKeyParameterNames.N]
                },

                _ => null
            };

            if (minimal is null || minimal.Any(static member => string.IsNullOrEmpty((string?) member.Value)))
            {
                return new(ProofError.InvalidKey, null, null, null);
            }

            // Ensure the algorithm is compatible with the key type (and with the curve, for elliptic curve keys).
            if (!IsCompatibleAlgorithm(jwt.Alg, (string) minimal[JsonWebKeyParameterNames.Kty]!,
                (string?) minimal[JsonWebKeyParameterNames.Crv]))
            {
                return new(ProofError.InvalidKey, null, null, null);
            }

            key = new JsonWebKey(minimal.ToJsonString());

            thumbprint = Base64UrlEncoder.Encode(key.ComputeJwkThumbprint());
        }

        catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
        {
            return new(ProofError.InvalidKey, null, null, null);
        }

        var result = await handler.ValidateTokenAsync(jwt, new TokenValidationParameters
        {
            IssuerSigningKey = key,
            RequireExpirationTime = false,
            RequireSignedTokens = true,
            TryAllIssuerSigningKeys = true,
            ValidAlgorithms = [jwt.Alg],
            ValidateAudience = false,
            ValidateIssuer = false,
            ValidateIssuerSigningKey = false,
            ValidateLifetime = false,
            ValidTypes =
            [
                OpenIddictConstants.JsonWebTokenTypes.DPoPProof,
                OpenIddictConstants.JsonWebTokenTypes.Prefixes.Application + OpenIddictConstants.JsonWebTokenTypes.DPoPProof
            ]
        });

        if (!result.IsValid)
        {
            return new(ProofError.InvalidSignature, null, null, null);
        }

        // DPoP proofs MUST contain a unique identifier.
        if (!jwt.TryGetPayloadValue(OpenIddictConstants.Claims.JwtId, out string? identifier) || string.IsNullOrEmpty(identifier))
        {
            return new(ProofError.InvalidClaim, OpenIddictConstants.Claims.JwtId, null, null);
        }

        // DPoP proofs MUST contain a "htm" claim matching the HTTP method of the request.
        if (!jwt.TryGetPayloadValue(OpenIddictConstants.Claims.HttpMethod, out string? htm) ||
            !string.Equals(htm, method, StringComparison.Ordinal))
        {
            return new(ProofError.InvalidClaim, OpenIddictConstants.Claims.HttpMethod, null, null);
        }

        // DPoP proofs MUST contain a "htu" claim matching the URI of the request (without query and fragment).
        if (!jwt.TryGetPayloadValue(OpenIddictConstants.Claims.HttpUri, out string? htu) || !MatchesHttpUri(htu, uri))
        {
            return new(ProofError.InvalidClaim, OpenIddictConstants.Claims.HttpUri, null, null);
        }

        // DPoP proofs MUST contain an "iat" claim within the acceptable window.
        if (!jwt.TryGetPayloadValue(OpenIddictConstants.Claims.IssuedAt, out object? _) ||
            new DateTimeOffset(jwt.IssuedAt, TimeSpan.Zero) is var issued &&
            (issued < date - lifetime || issued > date + lifetime))
        {
            return new(ProofError.InvalidClaim, OpenIddictConstants.Claims.IssuedAt, null, null);
        }

        // When an access token is presented, DPoP proofs MUST contain a matching "ath" claim.
        if (!string.IsNullOrEmpty(token) &&
            (!jwt.TryGetPayloadValue(OpenIddictConstants.Claims.DPoPAccessTokenHash, out string? hash) ||
             !FixedTimeEquals(hash, ComputeAccessTokenHash(token))))
        {
            return new(ProofError.InvalidClaim, OpenIddictConstants.Claims.DPoPAccessTokenHash, null, null);
        }

        return new(ProofError.None, null, jwt, thumbprint);

        static bool IsCompatibleAlgorithm(string algorithm, string type, string? curve) => (algorithm, type, curve) switch
        {
            (SecurityAlgorithms.EcdsaSha256, JsonWebAlgorithmsKeyTypes.EllipticCurve, JsonWebKeyECTypes.P256) => true,
            (SecurityAlgorithms.EcdsaSha384, JsonWebAlgorithmsKeyTypes.EllipticCurve, JsonWebKeyECTypes.P384) => true,
            (SecurityAlgorithms.EcdsaSha512, JsonWebAlgorithmsKeyTypes.EllipticCurve, JsonWebKeyECTypes.P521) => true,

            (SecurityAlgorithms.RsaSha256 or SecurityAlgorithms.RsaSha384 or SecurityAlgorithms.RsaSha512 or
             SecurityAlgorithms.RsaSsaPssSha256 or SecurityAlgorithms.RsaSsaPssSha384 or SecurityAlgorithms.RsaSsaPssSha512,
             JsonWebAlgorithmsKeyTypes.RSA, _) => true,

            _ => false
        };
    }

    /// <summary>
    /// Resolves the unique identifier ("jti") of the specified DPoP proof.
    /// </summary>
    /// <param name="token">The DPoP proof.</param>
    /// <returns>The unique identifier.</returns>
    internal static string? GetJwtId(JsonWebToken token)
        => token.TryGetPayloadValue(OpenIddictConstants.Claims.JwtId, out string? value) ? value : null;

    /// <summary>
    /// Resolves the nonce attached to the specified DPoP proof, if applicable.
    /// </summary>
    /// <param name="token">The DPoP proof.</param>
    /// <returns>The nonce, if applicable.</returns>
    internal static string? GetNonce(JsonWebToken token)
        => token.TryGetPayloadValue(OpenIddictConstants.Claims.Nonce, out string? value) ? value : null;

    /// <summary>
    /// Creates a JSON Web Key containing only the public members of the specified asymmetric key.
    /// </summary>
    /// <param name="key">The asymmetric key.</param>
    /// <returns>The JSON representation of the public key.</returns>
    private static JsonObject CreatePublicJsonWebKey(SecurityKey key)
    {
        switch (key)
        {
            case ECDsaSecurityKey { ECDsa: ECDsa algorithm }:
                return CreateEllipticCurveKey(algorithm.ExportParameters(includePrivateParameters: false));

            case RsaSecurityKey { Rsa: RSA algorithm }:
                return CreateRsaKey(algorithm.ExportParameters(includePrivateParameters: false));

            case RsaSecurityKey { Parameters: RSAParameters { Modulus: not null, Exponent: not null } parameters }:
                return CreateRsaKey(parameters);

            case X509SecurityKey { Certificate: X509Certificate2 certificate } when certificate.GetECDsaPublicKey() is ECDsa algorithm:
                using (algorithm)
                {
                    return CreateEllipticCurveKey(algorithm.ExportParameters(includePrivateParameters: false));
                }

            case X509SecurityKey { Certificate: X509Certificate2 certificate } when certificate.GetRSAPublicKey() is RSA algorithm:
                using (algorithm)
                {
                    return CreateRsaKey(algorithm.ExportParameters(includePrivateParameters: false));
                }

            case JsonWebKey { Kty: JsonWebAlgorithmsKeyTypes.EllipticCurve } value:
                return new JsonObject
                {
                    [JsonWebKeyParameterNames.Crv] = value.Crv,
                    [JsonWebKeyParameterNames.Kty] = value.Kty,
                    [JsonWebKeyParameterNames.X] = value.X,
                    [JsonWebKeyParameterNames.Y] = value.Y
                };

            case JsonWebKey { Kty: JsonWebAlgorithmsKeyTypes.RSA } value:
                return new JsonObject
                {
                    [JsonWebKeyParameterNames.E] = value.E,
                    [JsonWebKeyParameterNames.Kty] = value.Kty,
                    [JsonWebKeyParameterNames.N] = value.N
                };

            default: throw new InvalidOperationException(SR.GetResourceString(SR.ID0548));
        }

        static JsonObject CreateEllipticCurveKey(ECParameters parameters) => new()
        {
            [JsonWebKeyParameterNames.Crv] = (parameters.Curve.Oid?.Value, parameters.Curve.Oid?.FriendlyName) switch
            {
                ("1.2.840.10045.3.1.7", _) or (_, "nistP256" or "ECDSA_P256") => JsonWebKeyECTypes.P256,
                ("1.3.132.0.34",        _) or (_, "nistP384" or "ECDSA_P384") => JsonWebKeyECTypes.P384,
                ("1.3.132.0.35",        _) or (_, "nistP521" or "ECDSA_P521") => JsonWebKeyECTypes.P521,

                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0548))
            },
            [JsonWebKeyParameterNames.Kty] = JsonWebAlgorithmsKeyTypes.EllipticCurve,
            [JsonWebKeyParameterNames.X] = Base64UrlEncoder.Encode(parameters.Q.X),
            [JsonWebKeyParameterNames.Y] = Base64UrlEncoder.Encode(parameters.Q.Y)
        };

        static JsonObject CreateRsaKey(RSAParameters parameters) => new()
        {
            [JsonWebKeyParameterNames.E] = Base64UrlEncoder.Encode(parameters.Exponent),
            [JsonWebKeyParameterNames.Kty] = JsonWebAlgorithmsKeyTypes.RSA,
            [JsonWebKeyParameterNames.N] = Base64UrlEncoder.Encode(parameters.Modulus)
        };
    }
}
