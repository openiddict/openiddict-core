/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers;
using static OpenIddict.Server.OpenIddictServerHandlers.Protection;

namespace OpenIddict.Server.IntegrationTests;

public abstract partial class OpenIddictServerIntegrationTests
{
    private const string DPoPTokenEndpoint = "http://localhost/connect/token";
    private const string DPoPUserInfoEndpoint = "http://localhost/connect/userinfo";

    private static readonly ECDsa DPoPAlgorithm = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    [Fact]
    public async Task HandleConfigurationRequest_DPoPSigningAlgorithmsAreReturnedWhenDPoPIsEnabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.EnableDPoPSupport();
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        var algorithms = (ImmutableArray<string?>?) response[Metadata.DPoPSigningAlgValuesSupported];
        Assert.NotNull(algorithms);
        Assert.Contains(SecurityAlgorithms.EcdsaSha256, algorithms.Value, StringComparer.Ordinal);
        Assert.Contains(SecurityAlgorithms.RsaSsaPssSha256, algorithms.Value, StringComparer.Ordinal);
        Assert.DoesNotContain(SecurityAlgorithms.HmacSha256, algorithms.Value, StringComparer.Ordinal);
    }

    [Fact]
    public async Task HandleConfigurationRequest_DPoPSigningAlgorithmsAreNotReturnedWhenDPoPIsDisabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.Null(response[Metadata.DPoPSigningAlgValuesSupported]);
    }

    [Fact]
    public async Task ProcessSignIn_DPoPBoundAccessTokenIsReturnedWhenValidProofIsSent()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            ConfigureDPoPPasswordServer(options);

            options.AddEventHandler<ProcessSignInContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.NotNull(context.AccessTokenPrincipal);
                    Assert.Equal(ComputeDPoPThumbprint(), GetConfirmationThumbprint(context.AccessTokenPrincipal));

                    return ValueTask.CompletedTask;
                });

                builder.SetOrder(PrepareAccessTokenPrincipal.Descriptor.Order + 1);
            });
        });

        await using var client = await server.CreateClientAsync();
        client.RequestHeaders["DPoP"] = [CreateDPoPProof()];

        // Act
        var response = await client.PostAsync("/connect/token", CreateDPoPPasswordRequest());

        // Assert
        Assert.Null(response.Error);
        Assert.NotNull(response.AccessToken);
        Assert.Equal(TokenTypes.DPoP, response.TokenType);
    }

    [Fact]
    public async Task ProcessSignIn_BearerAccessTokenIsReturnedWhenNoProofIsSent()
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureDPoPPasswordServer);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", CreateDPoPPasswordRequest());

        // Assert
        Assert.NotNull(response.AccessToken);
        Assert.Equal(TokenTypes.Bearer, response.TokenType);
    }

    [Fact]
    public async Task ProcessSignIn_DPoPProofIsIgnoredWhenDPoPSupportIsDisabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return ValueTask.CompletedTask;
                }));
        });

        await using var client = await server.CreateClientAsync();
        client.RequestHeaders["DPoP"] = ["invalid_proof"];

        // Act
        var response = await client.PostAsync("/connect/token", CreateDPoPPasswordRequest());

        // Assert
        Assert.Equal(TokenTypes.Bearer, response.TokenType);
    }

    [Fact]
    public async Task ProcessSignIn_DPoPBoundRefreshTokenIsReturnedInDegradedMode()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            ConfigureDPoPPasswordServer(options);

            options.AddEventHandler<ProcessSignInContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.NotNull(context.RefreshTokenPrincipal);
                    Assert.Equal(ComputeDPoPThumbprint(), GetConfirmationThumbprint(context.RefreshTokenPrincipal));

                    return ValueTask.CompletedTask;
                });

                builder.SetOrder(PrepareRefreshTokenPrincipal.Descriptor.Order + 1);
            });
        });

        await using var client = await server.CreateClientAsync();
        client.RequestHeaders["DPoP"] = [CreateDPoPProof()];

        // Act
        var request = CreateDPoPPasswordRequest();
        request.ClientId = "Fabrikam";

        var response = await client.PostAsync("/connect/token", request);

        // Assert
        Assert.NotNull(response.RefreshToken);
    }

    [Theory]
    [InlineData(ClientTypes.Public, true)]
    [InlineData(ClientTypes.Confidential, false)]
    public async Task ProcessSignIn_RefreshTokenIsOnlyBoundForPublicClients(string type, bool bound)
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()))
                .ReturnsAsync(type is ClientTypes.Public);

            mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Confidential, It.IsAny<CancellationToken>()))
                .ReturnsAsync(type is ClientTypes.Confidential);

            mock.Setup(manager => manager.ValidateClientSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.GetSettingsAsync(application, It.IsAny<CancellationToken>()))
                .ReturnsAsync(ImmutableDictionary.Create<string, string>(StringComparer.Ordinal));
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDPoPSupport();
            options.DisableTokenStorage();
            options.DisableAuthorizationStorage();
            options.Services.AddSingleton(manager);

            // Note: the device authorization flow requires token storage.
            options.Configure(options =>
            {
                options.GrantTypes.Remove(GrantTypes.DeviceCode);
                options.DeviceAuthorizationEndpointUris.Clear();
                options.EndUserVerificationEndpointUris.Clear();
            });

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetScopes(Scopes.OfflineAccess)
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return ValueTask.CompletedTask;
                }));

            options.AddEventHandler<ProcessSignInContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.NotNull(context.RefreshTokenPrincipal);
                    Assert.Equal(bound ? ComputeDPoPThumbprint() : null, GetConfirmationThumbprint(context.RefreshTokenPrincipal));

                    return ValueTask.CompletedTask;
                });

                builder.SetOrder(PrepareRefreshTokenPrincipal.Descriptor.Order + 1);
            });
        });

        await using var client = await server.CreateClientAsync();
        client.RequestHeaders["DPoP"] = [CreateDPoPProof()];

        // Act
        var request = CreateDPoPPasswordRequest();
        request.ClientId = "Fabrikam";
        request.ClientSecret = type is ClientTypes.Confidential ? "7Fjfp0ZBr1KtDRbnfVdmIw" : null;

        var response = await client.PostAsync("/connect/token", request);

        // Assert
        Assert.Null(response.Error);
        Assert.NotNull(response.RefreshToken);
    }

    [Fact]
    public async Task ValidateTokenRequest_MissingProofIsRejectedWhenDPoPIsGloballyRequired()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            ConfigureDPoPPasswordServer(options);
            options.RequireDPoP();
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", CreateDPoPPasswordRequest());

        // Assert
        Assert.Equal(Errors.InvalidDPoPProof, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2228), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2228), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateTokenRequest_MissingProofIsRejectedWhenDPoPIsRequiredForClient()
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.HasRequirementAsync(application, Requirements.Features.DPoP, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDPoPSupport();
            options.Services.AddSingleton(manager);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var request = CreateDPoPPasswordRequest();
        request.ClientId = "Fabrikam";

        var response = await client.PostAsync("/connect/token", request);

        // Assert
        Assert.Equal(Errors.InvalidDPoPProof, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2228), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2228), response.ErrorUri);

        Mock.Get(manager).Verify(manager => manager.HasRequirementAsync(application, Requirements.Features.DPoP, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Theory]
    [InlineData("method")]
    [InlineData("uri")]
    [InlineData("uri_with_different_path")]
    [InlineData("expired")]
    [InlineData("future")]
    [InlineData("jti")]
    public async Task ValidateTokenRequest_ProofWithInvalidClaimIsRejected(string scenario)
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureDPoPPasswordServer);
        await using var client = await server.CreateClientAsync();

        client.RequestHeaders["DPoP"] = [scenario switch
        {
            "method"                  => CreateDPoPProof(method: "GET"),
            "uri"                     => CreateDPoPProof(uri: "https://localhost/connect/token"),
            "uri_with_different_path" => CreateDPoPProof(uri: "http://localhost/connect/token2"),
            "expired"                 => CreateDPoPProof(issuedAt: DateTimeOffset.UtcNow - TimeSpan.FromHours(1)),
            "future"                  => CreateDPoPProof(issuedAt: DateTimeOffset.UtcNow + TimeSpan.FromHours(1)),
            "jti"                     => CreateDPoPProof(jti: string.Empty),

            _ => throw new NotSupportedException()
        }];

        var claim = scenario switch
        {
            "method" => Claims.HttpMethod,
            "uri" or "uri_with_different_path" => Claims.HttpUri,
            "expired" or "future" => Claims.IssuedAt,
            _ => Claims.JwtId
        };

        // Act
        var response = await client.PostAsync("/connect/token", CreateDPoPPasswordRequest());

        // Assert
        Assert.Equal(Errors.InvalidDPoPProof, response.Error);
        Assert.Equal(SR.FormatID2226(claim), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2226), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateTokenRequest_ProofWithQueryStringInUriIsAccepted()
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureDPoPPasswordServer);
        await using var client = await server.CreateClientAsync();

        client.RequestHeaders["DPoP"] = [CreateDPoPProof(uri: "HTTP://LOCALHOST:80/connect/token?query=value#fragment")];

        // Act
        var response = await client.PostAsync("/connect/token", CreateDPoPPasswordRequest());

        // Assert
        Assert.Null(response.Error);
        Assert.Equal(TokenTypes.DPoP, response.TokenType);
    }

    [Theory]
    [InlineData("type")]
    [InlineData("private_key")]
    [InlineData("symmetric")]
    [InlineData("none")]
    [InlineData("signature")]
    [InlineData("malformed")]
    public async Task ValidateTokenRequest_InvalidProofIsRejected(string scenario)
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureDPoPPasswordServer);
        await using var client = await server.CreateClientAsync();

        client.RequestHeaders["DPoP"] = [scenario switch
        {
            "type"        => CreateDPoPProof(type: JsonWebTokenTypes.GenericJsonWebToken),
            "private_key" => CreateDPoPProof(includePrivateKey: true),
            "symmetric"   => CreateSymmetricDPoPProof(),
            "none"        => CreateUnsignedDPoPProof(),
            "signature"   => CreateDPoPProof(jwk: CreateJsonWebKey(ECDsa.Create(ECCurve.NamedCurves.nistP256))),
            "malformed"   => "malformed_proof",

            _ => throw new NotSupportedException()
        }];

        // Act
        var response = await client.PostAsync("/connect/token", CreateDPoPPasswordRequest());

        // Assert
        Assert.Equal(Errors.InvalidDPoPProof, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2225), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2225), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateTokenRequest_MultipleProofsAreRejected()
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureDPoPPasswordServer);
        await using var client = await server.CreateClientAsync();

        client.RequestHeaders["DPoP"] = [CreateDPoPProof(), CreateDPoPProof()];

        // Act
        var response = await client.PostAsync("/connect/token", CreateDPoPPasswordRequest());

        // Assert
        Assert.Equal(Errors.InvalidDPoPProof, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2234), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2234), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateTokenRequest_ReplayedProofIsRejected()
    {
        // Arrange
        var token = new OpenIddictToken();

        var manager = CreateTokenManager(mock =>
        {
            mock.Setup(manager => manager.FindByReferenceIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(token);
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDPoPSupport();
            options.Services.AddSingleton(manager);
        });

        await using var client = await server.CreateClientAsync();
        client.RequestHeaders["DPoP"] = [CreateDPoPProof(jti: "replayed_identifier")];

        // Act
        var response = await client.PostAsync("/connect/token", CreateDPoPPasswordRequest());

        // Assert
        Assert.Equal(Errors.InvalidDPoPProof, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2227), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2227), response.ErrorUri);

        Mock.Get(manager).Verify(manager => manager.FindByReferenceIdAsync(
            ComputeDPoPThumbprint() + ".replayed_identifier", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ValidateTokenRequest_TokenEntryIsCreatedForNewProofWhenTokenStorageIsEnabled()
    {
        // Arrange
        var manager = CreateTokenManager(mock =>
        {
            mock.Setup(manager => manager.FindByReferenceIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(value: null);

            mock.Setup(manager => manager.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new OpenIddictToken());
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDPoPSupport();
            options.Services.AddSingleton(manager);

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Reject(error: "custom_error");

                    return ValueTask.CompletedTask;
                }));
        });

        await using var client = await server.CreateClientAsync();
        client.RequestHeaders["DPoP"] = [CreateDPoPProof(jti: "new_identifier")];

        // Act
        var response = await client.PostAsync("/connect/token", CreateDPoPPasswordRequest());

        // Assert
        Assert.Equal("custom_error", response.Error);

        Mock.Get(manager).Verify(manager => manager.CreateAsync(
            It.Is<OpenIddictTokenDescriptor>(descriptor =>
                descriptor.ReferenceId == ComputeDPoPThumbprint() + ".new_identifier" &&
                descriptor.Status == Statuses.Redeemed &&
                descriptor.Type == TokenTypeIdentifiers.Private.DPoPProof &&
                descriptor.ExpirationDate != null),
            It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ValidateTokenRequest_NonceIsRequiredAndAcceptedWhenNoncesAreEnabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            ConfigureDPoPPasswordServer(options);
            options.RequireDPoPNonces();
        });

        await using var client = await server.CreateClientAsync();
        client.RequestHeaders["DPoP"] = [CreateDPoPProof()];

        // Act
        var response = await client.PostAsync("/connect/token", CreateDPoPPasswordRequest());

        // Assert
        Assert.Equal(Errors.UseDPoPNonce, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2229), response.ErrorDescription);
        Assert.True(client.ResponseHeaders.TryGetValue("DPoP-Nonce", out var nonces));

        var nonce = Assert.Single(nonces);

        // Act
        client.RequestHeaders["DPoP"] = [CreateDPoPProof(nonce: nonce)];
        response = await client.PostAsync("/connect/token", CreateDPoPPasswordRequest());

        // Assert
        Assert.Null(response.Error);
        Assert.Equal(TokenTypes.DPoP, response.TokenType);

        // Act
        client.RequestHeaders["DPoP"] = [CreateDPoPProof(nonce: "invalid_nonce")];
        response = await client.PostAsync("/connect/token", CreateDPoPPasswordRequest());

        // Assert
        Assert.Equal(Errors.UseDPoPNonce, response.Error);
    }

    [Fact]
    public async Task ValidateTokenRequest_RefreshTokenBoundToDPoPKeyRequiresMatchingProof()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.EnableDPoPSupport();

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("8xLOxBtZp8", context.Token);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeIdentifiers.RefreshToken)
                        .SetClaim(Claims.Subject, "Bob le Magnifique")
                        .SetClaim(Claims.Confirmation, new JsonObject { [Claims.JsonWebKeyThumbprint] = ComputeDPoPThumbprint() });

                    return ValueTask.CompletedTask;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            GrantType = GrantTypes.RefreshToken,
            RefreshToken = "8xLOxBtZp8"
        });

        // Assert
        Assert.Equal(Errors.InvalidGrant, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2230), response.ErrorDescription);

        using var algorithm = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        // Act
        client.RequestHeaders["DPoP"] = [CreateDPoPProof(jwk: CreateJsonWebKey(algorithm), signingKey: new ECDsaSecurityKey(algorithm))];
        response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            GrantType = GrantTypes.RefreshToken,
            RefreshToken = "8xLOxBtZp8"
        });

        // Assert
        Assert.Equal(Errors.InvalidGrant, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2231), response.ErrorDescription);

        // Act
        client.RequestHeaders["DPoP"] = [CreateDPoPProof()];
        response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            GrantType = GrantTypes.RefreshToken,
            RefreshToken = "8xLOxBtZp8"
        });

        // Assert
        Assert.Null(response.Error);
        Assert.Equal(TokenTypes.DPoP, response.TokenType);
    }

    [Fact]
    public async Task ValidateTokenRequest_AuthorizationCodeBoundToDPoPKeyRequiresMatchingProof()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.EnableDPoPSupport();

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeIdentifiers.Private.AuthorizationCode)
                        .SetPresenters("Fabrikam")
                        .SetClaim(Claims.Subject, "Bob le Bricoleur")
                        .SetClaim(Claims.Private.DPoPJwkThumbprint, ComputeDPoPThumbprint());

                    return ValueTask.CompletedTask;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        var request = new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Code = "SplxlOBeZQQYbYS6WxSbIA",
            GrantType = GrantTypes.AuthorizationCode
        };

        // Act
        var response = await client.PostAsync("/connect/token", request);

        // Assert
        Assert.Equal(Errors.InvalidDPoPProof, response.Error);
        Assert.Equal(SR.FormatID2233(Parameters.DPoPJkt), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2233), response.ErrorUri);

        // Act
        client.RequestHeaders["DPoP"] = [CreateDPoPProof()];
        response = await client.PostAsync("/connect/token", request);

        // Assert
        Assert.Null(response.Error);
        Assert.Equal(TokenTypes.DPoP, response.TokenType);
    }

    [Fact]
    public async Task ProcessSignIn_DPoPJktParameterIsAttachedToAuthorizationCode()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.EnableDPoPSupport();

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return ValueTask.CompletedTask;
                }));

            options.AddEventHandler<ProcessSignInContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.NotNull(context.AuthorizationCodePrincipal);
                    Assert.Equal("jkt_value", context.AuthorizationCodePrincipal.GetClaim(Claims.Private.DPoPJwkThumbprint));

                    return ValueTask.CompletedTask;
                });

                builder.SetOrder(PrepareAuthorizationCodePrincipal.Descriptor.Order + 1);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            DPoPJkt = "jkt_value",
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Null(response.Error);
        Assert.NotNull(response.Code);
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_ProofThumbprintIsAttachedAsDPoPJkt()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.EnableDPoPSupport();

            options.AddEventHandler<ProcessSignInContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal(ComputeDPoPThumbprint(), context.Request.DPoPJkt);

                    return ValueTask.CompletedTask;
                });

                builder.SetOrder(PrepareRequestTokenPrincipal.Descriptor.Order - 1);
            });
        });

        await using var client = await server.CreateClientAsync();
        client.RequestHeaders["DPoP"] = [CreateDPoPProof(uri: "http://localhost/connect/par")];

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Null(response.Error);
        Assert.NotNull(response.RequestUri);
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_MismatchingDPoPJktIsRejected()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.EnableDPoPSupport();
        });

        await using var client = await server.CreateClientAsync();
        client.RequestHeaders["DPoP"] = [CreateDPoPProof(uri: "http://localhost/connect/par")];

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            DPoPJkt = "invalid_thumbprint",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code
        });

        // Assert
        Assert.Equal(Errors.InvalidDPoPProof, response.Error);
        Assert.Equal(SR.FormatID2233(Parameters.DPoPJkt), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2233), response.ErrorUri);
    }

    [Fact]
    public async Task HandleUserInfoRequest_DPoPBoundAccessTokenIsAcceptedWithValidProof()
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureDPoPUserInfoServer);
        await using var client = await server.CreateClientAsync();

        client.RequestHeaders["Authorization"] = ["DPoP SlAV32hkKG"];
        client.RequestHeaders["DPoP"] = [CreateDPoPProof(uri: DPoPUserInfoEndpoint, accessToken: "SlAV32hkKG")];

        // Act
        var response = await client.PostAsync("/connect/userinfo", new OpenIddictRequest());

        // Assert
        Assert.Null(response.Error);
        Assert.Equal("Bob le Magnifique", (string?) response[Claims.Subject]);
    }

    [Fact]
    public async Task HandleUserInfoRequest_DPoPBoundAccessTokenIsRejectedWhenSentAsBearerToken()
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureDPoPUserInfoServer);
        await using var client = await server.CreateClientAsync();

        client.RequestHeaders["Authorization"] = ["Bearer SlAV32hkKG"];
        client.RequestHeaders["DPoP"] = [CreateDPoPProof(uri: DPoPUserInfoEndpoint, accessToken: "SlAV32hkKG")];

        // Act
        var response = await client.PostAsync("/connect/userinfo", new OpenIddictRequest());

        // Assert
        Assert.Equal(Errors.InvalidToken, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2230), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2230), response.ErrorUri);

        var headers = client.ResponseHeaders["WWW-Authenticate"];
        Assert.Equal(2, headers.Length);
        Assert.StartsWith(Schemes.Bearer + " ", headers[0], StringComparison.Ordinal);
        Assert.Contains("error=\"invalid_token\"", headers[0], StringComparison.Ordinal);
        Assert.StartsWith(Schemes.DPoP + " algs=\"", headers[1], StringComparison.Ordinal);
        Assert.DoesNotContain("error=", headers[1], StringComparison.Ordinal);
    }

    [Fact]
    public async Task HandleUserInfoRequest_BearerAndDPoPChallengesAreReturnedWhenAccessTokenIsMissing()
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureDPoPUserInfoServer);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/userinfo", new OpenIddictRequest());

        // Assert
        Assert.Null(response.Error);

        var headers = client.ResponseHeaders["WWW-Authenticate"];
        Assert.Equal(2, headers.Length);
        Assert.Equal(Schemes.Bearer, headers[0]);
        Assert.StartsWith(Schemes.DPoP + " algs=\"", headers[1], StringComparison.Ordinal);
    }

    [Fact]
    public async Task HandleUserInfoRequest_OnlyBearerChallengeIsReturnedWhenDPoPIsDisabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/userinfo", new OpenIddictRequest());

        // Assert
        Assert.Equal(Schemes.Bearer, Assert.Single(client.ResponseHeaders["WWW-Authenticate"]));
    }

    [Fact]
    public async Task HandleUserInfoRequest_ProofWithInvalidAccessTokenHashIsRejected()
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureDPoPUserInfoServer);
        await using var client = await server.CreateClientAsync();

        client.RequestHeaders["Authorization"] = ["DPoP SlAV32hkKG"];
        client.RequestHeaders["DPoP"] = [CreateDPoPProof(uri: DPoPUserInfoEndpoint, accessToken: "another_token")];

        // Act
        var response = await client.PostAsync("/connect/userinfo", new OpenIddictRequest());

        // Assert
        Assert.Equal(Errors.InvalidDPoPProof, response.Error);
        Assert.Equal(SR.FormatID2226(Claims.DPoPAccessTokenHash), response.ErrorDescription);

        var header = Assert.Single(client.ResponseHeaders["WWW-Authenticate"]);
        Assert.StartsWith(Schemes.DPoP + " ", header, StringComparison.Ordinal);
        Assert.Contains("algs=\"", header, StringComparison.Ordinal);
    }

    [Fact]
    public async Task HandleUserInfoRequest_MissingProofIsRejectedWhenDPoPSchemeIsUsed()
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureDPoPUserInfoServer);
        await using var client = await server.CreateClientAsync();

        client.RequestHeaders["Authorization"] = ["DPoP SlAV32hkKG"];

        // Act
        var response = await client.PostAsync("/connect/userinfo", new OpenIddictRequest());

        // Assert
        Assert.Equal(Errors.InvalidDPoPProof, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2228), response.ErrorDescription);
    }

    [Fact]
    public async Task HandleUserInfoRequest_ProofSignedWithDifferentKeyIsRejected()
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureDPoPUserInfoServer);
        await using var client = await server.CreateClientAsync();

        using var algorithm = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        client.RequestHeaders["Authorization"] = ["DPoP SlAV32hkKG"];
        client.RequestHeaders["DPoP"] = [CreateDPoPProof(uri: DPoPUserInfoEndpoint, accessToken: "SlAV32hkKG",
            jwk: CreateJsonWebKey(algorithm), signingKey: new ECDsaSecurityKey(algorithm))];

        // Act
        var response = await client.PostAsync("/connect/userinfo", new OpenIddictRequest());

        // Assert
        Assert.Equal(Errors.InvalidToken, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2231), response.ErrorDescription);
    }

    [Fact]
    public async Task HandleUserInfoRequest_UnboundAccessTokenIsRejectedWhenDPoPSchemeIsUsed()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.EnableDPoPSupport();

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeIdentifiers.AccessToken)
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return ValueTask.CompletedTask;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        client.RequestHeaders["Authorization"] = ["DPoP SlAV32hkKG"];
        client.RequestHeaders["DPoP"] = [CreateDPoPProof(uri: DPoPUserInfoEndpoint, accessToken: "SlAV32hkKG")];

        // Act
        var response = await client.PostAsync("/connect/userinfo", new OpenIddictRequest());

        // Assert
        Assert.Equal(Errors.InvalidToken, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2232), response.ErrorDescription);
    }

    [Fact]
    public async Task HandleIntrospectionRequest_DPoPTokenTypeIsReturnedForDPoPBoundToken()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeIdentifiers.AccessToken)
                        .SetClaim(Claims.Subject, "Bob le Magnifique")
                        .SetClaim(Claims.Confirmation, new JsonObject { [Claims.JsonWebKeyThumbprint] = "jkt_value" });

                    return ValueTask.CompletedTask;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });

            options.RemoveEventHandler(ValidateExpirationDate.Descriptor);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest
        {
            Token = "2YotnFZFEjr1zCsicMWpAA",
            TokenTypeHint = TokenTypeHints.AccessToken
        });

        // Assert
        Assert.True((bool) response[Claims.Active]);
        Assert.Equal(TokenTypes.DPoP, (string?) response[Claims.TokenType]);
        Assert.Equal("jkt_value", (string?) response[Claims.Confirmation]?[Claims.JsonWebKeyThumbprint]);
    }

    private static void ConfigureDPoPPasswordServer(OpenIddictServerBuilder options)
    {
        options.EnableDegradedMode();
        options.EnableDPoPSupport();

        options.AddEventHandler<HandleTokenRequestContext>(builder =>
            builder.UseInlineHandler(context =>
            {
                context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                    .SetScopes(Scopes.OfflineAccess)
                    .SetClaim(Claims.Subject, "Bob le Magnifique");

                return ValueTask.CompletedTask;
            }));
    }

    private static void ConfigureDPoPUserInfoServer(OpenIddictServerBuilder options)
    {
        options.EnableDegradedMode();
        options.EnableDPoPSupport();

        options.AddEventHandler<ValidateTokenContext>(builder =>
        {
            builder.UseInlineHandler(context =>
            {
                Assert.Equal("SlAV32hkKG", context.Token);

                context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                    .SetTokenType(TokenTypeIdentifiers.AccessToken)
                    .SetClaim(Claims.Subject, "Bob le Magnifique")
                    .SetClaim(Claims.Confirmation, new JsonObject { [Claims.JsonWebKeyThumbprint] = ComputeDPoPThumbprint() });

                return ValueTask.CompletedTask;
            });

            builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
        });
    }

    private static OpenIddictRequest CreateDPoPPasswordRequest() => new()
    {
        GrantType = GrantTypes.Password,
        Username = "johndoe",
        Password = "A3ddj3w",
        Scope = Scopes.OfflineAccess
    };

    private static string? GetConfirmationThumbprint(ClaimsPrincipal principal)
        => principal.GetClaim(Claims.Confirmation) is { Length: > 0 } value
            ? (string?) JsonNode.Parse(value)?[Claims.JsonWebKeyThumbprint]
            : null;

    private static Dictionary<string, object> CreateJsonWebKey(ECDsa algorithm, bool includePrivateKey = false)
    {
        var parameters = algorithm.ExportParameters(includePrivateParameters: includePrivateKey);

        var key = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [JsonWebKeyParameterNames.Crv] = JsonWebKeyECTypes.P256,
            [JsonWebKeyParameterNames.Kty] = JsonWebAlgorithmsKeyTypes.EllipticCurve,
            [JsonWebKeyParameterNames.X] = Base64UrlEncoder.Encode(parameters.Q.X),
            [JsonWebKeyParameterNames.Y] = Base64UrlEncoder.Encode(parameters.Q.Y)
        };

        if (includePrivateKey)
        {
            key[JsonWebKeyParameterNames.D] = Base64UrlEncoder.Encode(parameters.D);
        }

        return key;
    }

    private static string ComputeDPoPThumbprint()
        => Base64UrlEncoder.Encode(new JsonWebKey(JsonSerializer.Serialize(CreateJsonWebKey(DPoPAlgorithm))).ComputeJwkThumbprint());

    private static string CreateDPoPProof(
        string method = "POST",
        string uri = DPoPTokenEndpoint,
        string type = JsonWebTokenTypes.DPoPProof,
        string? algorithm = SecurityAlgorithms.EcdsaSha256,
        DateTimeOffset? issuedAt = null,
        string? accessToken = null,
        string? nonce = null,
        string? jti = null,
        bool includePrivateKey = false,
        Dictionary<string, object>? jwk = null,
        SecurityKey? signingKey = null)
    {
        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [Claims.HttpMethod] = method,
            [Claims.HttpUri] = uri,
            [Claims.IssuedAt] = (issuedAt ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds(),
            [Claims.JwtId] = jti ?? Guid.NewGuid().ToString()
        };

        if (!string.IsNullOrEmpty(accessToken))
        {
            claims[Claims.DPoPAccessTokenHash] = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken)));
        }

        if (!string.IsNullOrEmpty(nonce))
        {
            claims[Claims.Nonce] = nonce;
        }

        return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor
        {
            AdditionalHeaderClaims = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [JwtHeaderParameterNames.Jwk] = jwk ?? CreateJsonWebKey(DPoPAlgorithm, includePrivateKey)
            },
            Claims = claims,
            SigningCredentials = new SigningCredentials(signingKey ?? new ECDsaSecurityKey(DPoPAlgorithm), algorithm ?? SecurityAlgorithms.EcdsaSha256),
            TokenType = type
        });
    }

    private static string CreateSymmetricDPoPProof()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);

        return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor
        {
            AdditionalHeaderClaims = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [JwtHeaderParameterNames.Jwk] = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    [JsonWebKeyParameterNames.Kty] = JsonWebAlgorithmsKeyTypes.Octet,
                    [JsonWebKeyParameterNames.K] = Base64UrlEncoder.Encode(bytes)
                }
            },
            Claims = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [Claims.HttpMethod] = "POST",
                [Claims.HttpUri] = DPoPTokenEndpoint,
                [Claims.IssuedAt] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                [Claims.JwtId] = Guid.NewGuid().ToString()
            },
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(bytes), SecurityAlgorithms.HmacSha256),
            TokenType = JsonWebTokenTypes.DPoPProof
        });
    }

    private static string CreateUnsignedDPoPProof()
    {
        var header = new JsonObject
        {
            [JwtHeaderParameterNames.Alg] = "none",
            [JwtHeaderParameterNames.Typ] = JsonWebTokenTypes.DPoPProof,
            [JwtHeaderParameterNames.Jwk] = JsonSerializer.SerializeToNode(CreateJsonWebKey(DPoPAlgorithm))
        };

        var payload = new JsonObject
        {
            [Claims.HttpMethod] = "POST",
            [Claims.HttpUri] = DPoPTokenEndpoint,
            [Claims.IssuedAt] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            [Claims.JwtId] = Guid.NewGuid().ToString()
        };

        return Base64UrlEncoder.Encode(header.ToJsonString()) + "." + Base64UrlEncoder.Encode(payload.ToJsonString()) + ".";
    }
}
