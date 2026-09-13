/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Concurrent;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using static OpenIddict.Validation.OpenIddictValidationEvents;
using static OpenIddict.Validation.OpenIddictValidationHandlers.Protection;

namespace OpenIddict.Validation.IntegrationTests;

public abstract partial class OpenIddictValidationIntegrationTests
{
    private const string DPoPResourceUri = "http://localhost/authenticate";

    private static readonly ECDsa DPoPAlgorithm = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    [Fact]
    public async Task ProcessAuthentication_DPoPBoundAccessTokenIsAcceptedWithValidProof()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => ConfigureDPoPToken(options, bound: true));
        await using var client = await server.CreateClientAsync();

        client.RequestHeaders["Authorization"] = ["DPoP access_token"];
        client.RequestHeaders["DPoP"] = [CreateDPoPProof(accessToken: "access_token")];

        // Act
        var response = await client.GetAsync("/authenticate", new OpenIddictRequest());

        // Assert
        Assert.Null(response.Error);
        Assert.Equal("Bob le Magnifique", (string?) response[Claims.Subject]);
    }

    [Fact]
    public async Task ProcessAuthentication_DPoPBoundAccessTokenIsRejectedWhenSentAsBearerToken()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => ConfigureDPoPToken(options, bound: true));
        await using var client = await server.CreateClientAsync();

        client.RequestHeaders["Authorization"] = ["Bearer access_token"];
        client.RequestHeaders["DPoP"] = [CreateDPoPProof(accessToken: "access_token")];

        // Act
        var response = await client.GetAsync("/authenticate", new OpenIddictRequest());

        // Assert
        Assert.Equal(Errors.InvalidToken, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2230), response.ErrorDescription);
        Assert.StartsWith(Schemes.Bearer, Assert.Single(client.ResponseHeaders["WWW-Authenticate"]), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ProcessAuthentication_MissingProofIsRejectedWhenDPoPSchemeIsUsed()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => ConfigureDPoPToken(options, bound: true));
        await using var client = await server.CreateClientAsync();

        client.RequestHeaders["Authorization"] = ["DPoP access_token"];

        // Act
        var response = await client.GetAsync("/authenticate", new OpenIddictRequest());

        // Assert
        Assert.Equal(Errors.InvalidDPoPProof, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2228), response.ErrorDescription);

        var header = Assert.Single(client.ResponseHeaders["WWW-Authenticate"]);
        Assert.StartsWith(Schemes.DPoP + " ", header, StringComparison.Ordinal);
        Assert.Contains("algs=\"", header, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("ath")]
    [InlineData("htm")]
    [InlineData("htu")]
    [InlineData("iat")]
    public async Task ProcessAuthentication_ProofWithInvalidClaimIsRejected(string claim)
    {
        // Arrange
        await using var server = await CreateServerAsync(options => ConfigureDPoPToken(options, bound: true));
        await using var client = await server.CreateClientAsync();

        client.RequestHeaders["Authorization"] = ["DPoP access_token"];
        client.RequestHeaders["DPoP"] = [claim switch
        {
            "ath" => CreateDPoPProof(accessToken: "another_token"),
            "htm" => CreateDPoPProof(accessToken: "access_token", method: "POST"),
            "htu" => CreateDPoPProof(accessToken: "access_token", uri: "http://localhost/other"),
            "iat" => CreateDPoPProof(accessToken: "access_token", issuedAt: DateTimeOffset.UtcNow - TimeSpan.FromHours(1)),

            _ => throw new NotSupportedException()
        }];

        // Act
        var response = await client.GetAsync("/authenticate", new OpenIddictRequest());

        // Assert
        Assert.Equal(Errors.InvalidDPoPProof, response.Error);
        Assert.Equal(SR.FormatID2226(claim), response.ErrorDescription);
    }

    [Fact]
    public async Task ProcessAuthentication_UnboundAccessTokenIsRejectedWhenDPoPSchemeIsUsed()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => ConfigureDPoPToken(options, bound: false));
        await using var client = await server.CreateClientAsync();

        client.RequestHeaders["Authorization"] = ["DPoP access_token"];
        client.RequestHeaders["DPoP"] = [CreateDPoPProof(accessToken: "access_token")];

        // Act
        var response = await client.GetAsync("/authenticate", new OpenIddictRequest());

        // Assert
        Assert.Equal(Errors.InvalidToken, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2232), response.ErrorDescription);
    }

    [Fact]
    public async Task ProcessAuthentication_ProofSignedWithDifferentKeyIsRejected()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => ConfigureDPoPToken(options, bound: true));
        await using var client = await server.CreateClientAsync();

        using var algorithm = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        client.RequestHeaders["Authorization"] = ["DPoP access_token"];
        client.RequestHeaders["DPoP"] = [CreateDPoPProof(accessToken: "access_token", algorithm: algorithm)];

        // Act
        var response = await client.GetAsync("/authenticate", new OpenIddictRequest());

        // Assert
        Assert.Equal(Errors.InvalidToken, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2231), response.ErrorDescription);
    }

    [Fact]
    public async Task ProcessAuthentication_ReplayedProofIsRejectedWhenDistributedCacheIsAvailable()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            ConfigureDPoPToken(options, bound: true);

            options.Services.AddSingleton<IDistributedCache, DictionaryDistributedCache>();
        });

        await using var client = await server.CreateClientAsync();

        client.RequestHeaders["Authorization"] = ["DPoP access_token"];
        client.RequestHeaders["DPoP"] = [CreateDPoPProof(accessToken: "access_token")];

        // Act
        var response = await client.GetAsync("/authenticate", new OpenIddictRequest());

        // Assert
        Assert.Null(response.Error);

        // Act
        response = await client.GetAsync("/authenticate", new OpenIddictRequest());

        // Assert
        Assert.Equal(Errors.InvalidDPoPProof, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2227), response.ErrorDescription);
    }

    private static void ConfigureDPoPToken(OpenIddictValidationBuilder options, bool bound)
    {
        options.AddEventHandler<ValidateTokenContext>(builder =>
        {
            builder.UseInlineHandler(context =>
            {
                Assert.Equal("access_token", context.Token);

                context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                    .SetTokenType(TokenTypeIdentifiers.AccessToken)
                    .SetClaim(Claims.Subject, "Bob le Magnifique");

                if (bound)
                {
                    context.Principal.SetClaim(Claims.Confirmation, new JsonObject
                    {
                        [Claims.JsonWebKeyThumbprint] = Base64UrlEncoder.Encode(new JsonWebKey(
                            JsonSerializer.Serialize(CreateJsonWebKey(DPoPAlgorithm))).ComputeJwkThumbprint())
                    });
                }

                return ValueTask.CompletedTask;
            });

            builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
        });
    }

    private static Dictionary<string, object> CreateJsonWebKey(ECDsa algorithm)
    {
        var parameters = algorithm.ExportParameters(includePrivateParameters: false);

        return new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [JsonWebKeyParameterNames.Crv] = JsonWebKeyECTypes.P256,
            [JsonWebKeyParameterNames.Kty] = JsonWebAlgorithmsKeyTypes.EllipticCurve,
            [JsonWebKeyParameterNames.X] = Base64UrlEncoder.Encode(parameters.Q.X),
            [JsonWebKeyParameterNames.Y] = Base64UrlEncoder.Encode(parameters.Q.Y)
        };
    }

    private static string CreateDPoPProof(string accessToken, string method = "GET", string uri = DPoPResourceUri,
        DateTimeOffset? issuedAt = null, ECDsa? algorithm = null)
    {
        algorithm ??= DPoPAlgorithm;

        return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor
        {
            AdditionalHeaderClaims = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [JwtHeaderParameterNames.Jwk] = CreateJsonWebKey(algorithm)
            },
            Claims = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [Claims.DPoPAccessTokenHash] = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken))),
                [Claims.HttpMethod] = method,
                [Claims.HttpUri] = uri,
                [Claims.IssuedAt] = (issuedAt ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds(),
                [Claims.JwtId] = Guid.NewGuid().ToString()
            },
            SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(algorithm), SecurityAlgorithms.EcdsaSha256),
            TokenType = JsonWebTokenTypes.DPoPProof
        });
    }

    private sealed class DictionaryDistributedCache : IDistributedCache
    {
        private readonly ConcurrentDictionary<string, byte[]> _entries = new(StringComparer.Ordinal);

        public byte[]? Get(string key) => _entries.TryGetValue(key, out var value) ? value : null;

        public Task<byte[]?> GetAsync(string key, CancellationToken token = default) => Task.FromResult(Get(key));

        public void Refresh(string key)
        {
        }

        public Task RefreshAsync(string key, CancellationToken token = default) => Task.CompletedTask;

        public void Remove(string key) => _entries.TryRemove(key, out _);

        public Task RemoveAsync(string key, CancellationToken token = default)
        {
            Remove(key);
            return Task.CompletedTask;
        }

        public void Set(string key, byte[] value, DistributedCacheEntryOptions options) => _entries[key] = value;

        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
        {
            Set(key, value, options);
            return Task.CompletedTask;
        }
    }
}
