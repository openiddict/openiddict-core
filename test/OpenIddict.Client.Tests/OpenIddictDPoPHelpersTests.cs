using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace OpenIddict.Client.Tests;

public class OpenIddictDPoPHelpersTests
{
    private static readonly Uri RequestUri = new("https://www.contoso.com/connect/token");

    [Fact]
    public async Task ValidateProofAsync_ProofSignedUsingEmbeddedCertificateKeyIsRejected()
    {
        // Arrange: the "n" and "e" members belong to a victim key (whose thumbprint is used for
        // token binding) while the attacker-controlled "x5c" certificate is used to sign the proof.
        using var victim = RSA.Create(2048);
        using var attacker = RSA.Create(2048);
        using var certificate = new CertificateRequest("CN=attacker", attacker, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        var parameters = victim.ExportParameters(includePrivateParameters: false);
        var jwk = new JsonObject
        {
            ["kty"] = "RSA",
            ["n"] = Base64UrlEncoder.Encode(parameters.Modulus),
            ["e"] = Base64UrlEncoder.Encode(parameters.Exponent),
            ["x5c"] = new JsonArray(Convert.ToBase64String(certificate.RawData))
        };

        var proof = CreateProof(jwk, "RS256", data => attacker.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));

        // Act
        var result = await ValidateAsync(proof);

        // Assert
        Assert.Equal(OpenIddictDPoPHelpers.ProofError.InvalidSignature, result.Error);
    }

    [Fact]
    public async Task ValidateProofAsync_EllipticCurveAlgorithmNotMatchingCurveIsRejected()
    {
        // Arrange
        using var algorithm = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var parameters = algorithm.ExportParameters(includePrivateParameters: false);
        var jwk = new JsonObject
        {
            ["kty"] = "EC",
            ["crv"] = "P-384",
            ["x"] = Base64UrlEncoder.Encode(parameters.Q.X),
            ["y"] = Base64UrlEncoder.Encode(parameters.Q.Y)
        };

        var proof = CreateProof(jwk, "ES256", data => algorithm.SignData(data, HashAlgorithmName.SHA256));

        // Act
        var result = await ValidateAsync(proof);

        // Assert
        Assert.Equal(OpenIddictDPoPHelpers.ProofError.InvalidKey, result.Error);
    }

    [Fact]
    public async Task ValidateProofAsync_ValidEllipticCurveProofIsAccepted()
    {
        // Arrange
        using var algorithm = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameters = algorithm.ExportParameters(includePrivateParameters: false);
        var jwk = new JsonObject
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = Base64UrlEncoder.Encode(parameters.Q.X),
            ["y"] = Base64UrlEncoder.Encode(parameters.Q.Y),
            ["use"] = "sig"
        };

        var proof = CreateProof(jwk, "ES256", data => algorithm.SignData(data, HashAlgorithmName.SHA256));

        // Act
        var result = await ValidateAsync(proof);

        // Assert
        Assert.Equal(OpenIddictDPoPHelpers.ProofError.None, result.Error);
        Assert.Equal(Base64UrlEncoder.Encode(new JsonWebKey(jwk.ToJsonString()).ComputeJwkThumbprint()), result.Thumbprint);
    }

    [Fact]
    public async Task ValidateProofAsync_SymmetricKeyIsRejected()
    {
        // Arrange
        var secret = Encoding.UTF8.GetBytes("7Fjfp0ZBr1KtDRbnfVdmIw_7Fjfp0ZBr1KtDRbnfVdmIw");
        var jwk = new JsonObject
        {
            ["kty"] = "oct"
        };

        var proof = CreateProof(jwk, "HS256", data => { using var hmac = new HMACSHA256(secret); return hmac.ComputeHash(data); });

        // Act
        var result = await ValidateAsync(proof);

        // Assert
        Assert.Equal(OpenIddictDPoPHelpers.ProofError.InvalidAlgorithm, result.Error);
    }

    [Fact]
    public async Task ValidateProofAsync_NonNumericIssuedAtIsRejected()
    {
        // Arrange
        using var algorithm = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameters = algorithm.ExportParameters(includePrivateParameters: false);
        var jwk = new JsonObject
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = Base64UrlEncoder.Encode(parameters.Q.X),
            ["y"] = Base64UrlEncoder.Encode(parameters.Q.Y)
        };

        var proof = CreateProof(jwk, "ES256", data => algorithm.SignData(data, HashAlgorithmName.SHA256), issuedAt: "invalid");

        // Act
        var result = await ValidateAsync(proof);

        // Assert
        Assert.NotEqual(OpenIddictDPoPHelpers.ProofError.None, result.Error);
    }

    private static ValueTask<OpenIddictDPoPHelpers.ProofValidationResult> ValidateAsync(string proof)
        => OpenIddictDPoPHelpers.ValidateProofAsync(proof, "POST", RequestUri,
            OpenIddictDPoPHelpers.SupportedAlgorithms, DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5), token: null);

    private static string CreateProof(JsonObject jwk, string algorithm, Func<byte[], byte[]> sign, JsonNode? issuedAt = null)
    {
        var header = new JsonObject
        {
            ["typ"] = "dpop+jwt",
            ["alg"] = algorithm,
            ["jwk"] = jwk.DeepClone()
        };

        var payload = new JsonObject
        {
            ["jti"] = Guid.NewGuid().ToString(),
            ["htm"] = "POST",
            ["htu"] = RequestUri.AbsoluteUri,
            ["iat"] = issuedAt ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        };

        var value = Base64UrlEncoder.Encode(header.ToJsonString()) + "." + Base64UrlEncoder.Encode(payload.ToJsonString());

        return value + "." + Base64UrlEncoder.Encode(sign(Encoding.ASCII.GetBytes(value)));
    }
}
