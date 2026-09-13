/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers.Protection;

namespace OpenIddict.Server.IntegrationTests;

public abstract partial class OpenIddictServerIntegrationTests
{
    private const string IntrospectionResponseMediaType = "application/token-introspection+jwt";

    [Fact]
    public async Task HandleConfigurationRequest_IntrospectionResponseAlgorithmsAreReturnedWhenEnabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableJsonWebTokenIntrospectionResponses());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        var algorithms = (ImmutableArray<string?>?) response[Metadata.IntrospectionSigningAlgValuesSupported];
        Assert.NotNull(algorithms);
        Assert.Contains(SecurityAlgorithms.RsaSha256, algorithms.Value, StringComparer.Ordinal);
        Assert.Equal([SecurityAlgorithms.RsaOAEP], (ImmutableArray<string?>?) response[Metadata.IntrospectionEncryptionAlgValuesSupported]);
        Assert.Equal([SecurityAlgorithms.Aes256CbcHmacSha512], (ImmutableArray<string?>?) response[Metadata.IntrospectionEncryptionEncValuesSupported]);
    }

    [Fact]
    public async Task HandleConfigurationRequest_IntrospectionEncryptionAlgorithmsAreNotReturnedInDegradedMode()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.EnableJsonWebTokenIntrospectionResponses();
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.NotNull(response[Metadata.IntrospectionSigningAlgValuesSupported]);
        Assert.Null(response[Metadata.IntrospectionEncryptionAlgValuesSupported]);
        Assert.Null(response[Metadata.IntrospectionEncryptionEncValuesSupported]);
    }

    [Fact]
    public async Task HandleConfigurationRequest_IntrospectionResponseAlgorithmsAreNotReturnedWhenDisabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.Null(response[Metadata.IntrospectionSigningAlgValuesSupported]);
        Assert.Null(response[Metadata.IntrospectionEncryptionAlgValuesSupported]);
    }

    [Fact]
    public async Task ApplyIntrospectionResponse_JsonResponseIsReturnedWhenNoTokenIsRequested()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.EnableJsonWebTokenIntrospectionResponses();

            ConfigureIntrospectedToken(options);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/introspect", CreateIntrospectionRequest());

        // Assert
        Assert.Equal("application/json", client.ResponseMediaType);
        Assert.True((bool) response[Claims.Active]);
        Assert.Null(client.ResponseToken);
    }

    [Fact]
    public async Task ApplyIntrospectionResponse_JsonResponseIsReturnedWhenTokenResponsesAreDisabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            ConfigureIntrospectedToken(options);
        });

        await using var client = await server.CreateClientAsync();
        client.RequestHeaders["Accept"] = [IntrospectionResponseMediaType];

        // Act
        var response = await client.PostAsync("/connect/introspect", CreateIntrospectionRequest());

        // Assert
        Assert.Equal("application/json", client.ResponseMediaType);
        Assert.True((bool) response[Claims.Active]);
    }

    [Theory]
    [InlineData("application/json")]
    [InlineData("*/*")]
    [InlineData("application/token-introspection+jwt;q=0")]
    public async Task ApplyIntrospectionResponse_JsonResponseIsReturnedWhenTokenIsNotExplicitlyAccepted(string header)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.EnableJsonWebTokenIntrospectionResponses();

            ConfigureIntrospectedToken(options);
        });

        await using var client = await server.CreateClientAsync();
        client.RequestHeaders["Accept"] = [header];

        // Act
        var response = await client.PostAsync("/connect/introspect", CreateIntrospectionRequest());

        // Assert
        Assert.Equal("application/json", client.ResponseMediaType);
        Assert.True((bool) response[Claims.Active]);
    }

    [Theory]
    [InlineData(IntrospectionResponseMediaType)]
    [InlineData("application/json;q=0.5, application/token-introspection+jwt")]
    public async Task ApplyIntrospectionResponse_SignedTokenIsReturnedWhenRequested(string header)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.EnableJsonWebTokenIntrospectionResponses();

            ConfigureIntrospectedToken(options);
        });

        await using var client = await server.CreateClientAsync();
        client.RequestHeaders["Accept"] = [header];

        // Act
        await client.PostAsync("/connect/introspect", CreateIntrospectionRequest());

        // Assert
        Assert.Equal(IntrospectionResponseMediaType, client.ResponseMediaType);
        Assert.NotNull(client.ResponseToken);

        var token = await ValidateIntrospectionResponseTokenAsync(client, client.ResponseToken);
        Assert.Equal(JsonWebTokenTypes.IntrospectionResponse, token.Typ);
        Assert.Equal(SecurityAlgorithms.RsaSha256, token.Alg);
        Assert.Equal("http://localhost/", token.Issuer);
        Assert.Equal("Fabrikam", Assert.Single(token.Audiences));
        Assert.True(token.TryGetPayloadValue<long>(Claims.IssuedAt, out _));
        Assert.False(token.TryGetPayloadValue<long>(Claims.ExpiresAt, out _));

        var introspection = token.GetPayloadValue<JsonElement>(Claims.TokenIntrospection);
        Assert.True(introspection.GetProperty(Claims.Active).GetBoolean());
        Assert.Equal("Bob le Magnifique", introspection.GetProperty(Claims.Subject).GetString());
        Assert.Equal("access_token", introspection.GetProperty(Claims.TokenUsage).GetString());
        Assert.Equal("http://localhost/", introspection.GetProperty(Claims.Issuer).GetString());
    }

    [Fact]
    public async Task ApplyIntrospectionResponse_InactiveResponseIsReturnedAsSignedToken()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.EnableJsonWebTokenIntrospectionResponses();

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    context.Reject(error: Errors.InvalidToken);

                    return ValueTask.CompletedTask;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });
        });

        await using var client = await server.CreateClientAsync();
        client.RequestHeaders["Accept"] = [IntrospectionResponseMediaType];

        // Act
        await client.PostAsync("/connect/introspect", CreateIntrospectionRequest());

        // Assert
        Assert.Equal(IntrospectionResponseMediaType, client.ResponseMediaType);
        Assert.NotNull(client.ResponseToken);

        var token = await ValidateIntrospectionResponseTokenAsync(client, client.ResponseToken);
        var introspection = token.GetPayloadValue<JsonElement>(Claims.TokenIntrospection);
        Assert.False(introspection.GetProperty(Claims.Active).GetBoolean());
        Assert.Single(introspection.EnumerateObject());
    }

    [Fact]
    public async Task ApplyIntrospectionResponse_ErrorsAreReturnedAsJson()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.EnableJsonWebTokenIntrospectionResponses();
        });

        await using var client = await server.CreateClientAsync();
        client.RequestHeaders["Accept"] = [IntrospectionResponseMediaType];

        // Act
        var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest { ClientId = "Fabrikam" });

        // Assert
        Assert.Equal("application/json", client.ResponseMediaType);
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2029(Parameters.Token), response.ErrorDescription);
    }

    [Fact]
    public async Task ApplyIntrospectionResponse_JsonResponseIsReturnedWhenClientIsUnknown()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.EnableJsonWebTokenIntrospectionResponses();

            ConfigureIntrospectedToken(options);
        });

        await using var client = await server.CreateClientAsync();
        client.RequestHeaders["Accept"] = [IntrospectionResponseMediaType];

        // Act
        var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest
        {
            Token = "2YotnFZFEjr1zCsicMWpAA"
        });

        // Assert
        Assert.Equal("application/json", client.ResponseMediaType);
        Assert.True((bool) response[Claims.Active]);
    }

    [Fact]
    public async Task ApplyIntrospectionResponse_JsonResponseIsReturnedToPublicClients()
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.EnableJsonWebTokenIntrospectionResponses();
            options.Services.AddSingleton(manager);

            ConfigureIntrospectedToken(options);
        });

        await using var client = await server.CreateClientAsync();
        client.RequestHeaders["Accept"] = [IntrospectionResponseMediaType];

        // Act
        var response = await client.PostAsync("/connect/introspect", CreateIntrospectionRequest());

        // Assert
        Assert.Equal("application/json", client.ResponseMediaType);
        Assert.True((bool) response[Claims.Active]);
        Assert.Null(client.ResponseToken);
    }

    [Fact]
    public async Task ApplyIntrospectionResponse_TokenContainsCustomParameters()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.EnableJsonWebTokenIntrospectionResponses();

            ConfigureIntrospectedToken(options);

            options.AddEventHandler<ApplyIntrospectionResponseContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Response["custom_parameter"] = "custom_value";

                    return ValueTask.CompletedTask;
                }));
        });

        await using var client = await server.CreateClientAsync();
        client.RequestHeaders["Accept"] = [IntrospectionResponseMediaType];

        // Act
        await client.PostAsync("/connect/introspect", CreateIntrospectionRequest());

        // Assert
        Assert.NotNull(client.ResponseToken);

        var token = await ValidateIntrospectionResponseTokenAsync(client, client.ResponseToken);
        var introspection = token.GetPayloadValue<JsonElement>(Claims.TokenIntrospection);
        Assert.Equal("custom_value", introspection.GetProperty("custom_parameter").GetString());
    }

    [Fact]
    public async Task ApplyIntrospectionResponse_TokenIsEncryptedWhenClientHasEncryptionKey()
    {
        // Arrange
        using var algorithm = RSA.Create(keySizeInBits: 2048);

        var key = JsonWebKeyConverter.ConvertFromRSASecurityKey(new RsaSecurityKey(algorithm.ExportParameters(includePrivateParameters: false)));
        key.Kid = "encryption_key";
        key.Use = JsonWebKeyUseNames.Enc;

        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Confidential, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.ValidateClientSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.GetJsonWebKeySetAsync(application, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new JsonWebKeySet { Keys = { key } });
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.EnableJsonWebTokenIntrospectionResponses();
            options.Services.AddSingleton(manager);

            ConfigureIntrospectedToken(options);
        });

        await using var client = await server.CreateClientAsync();
        client.RequestHeaders["Accept"] = [IntrospectionResponseMediaType];

        // Act
        await client.PostAsync("/connect/introspect", CreateIntrospectionRequest(secret: "7Fjfp0ZBr1KtDRbnfVdmIw"));

        // Assert
        Assert.Equal(IntrospectionResponseMediaType, client.ResponseMediaType);
        Assert.NotNull(client.ResponseToken);

        var envelope = new JsonWebToken(client.ResponseToken);
        Assert.Equal(SecurityAlgorithms.RsaOAEP, envelope.Alg);
        Assert.Equal(SecurityAlgorithms.Aes256CbcHmacSha512, envelope.Enc);
        Assert.Equal("encryption_key", envelope.Kid);

        var token = await ValidateIntrospectionResponseTokenAsync(client, client.ResponseToken, new RsaSecurityKey(algorithm));
        Assert.Equal(JsonWebTokenTypes.IntrospectionResponse, token.Typ);
        Assert.True(token.GetPayloadValue<JsonElement>(Claims.TokenIntrospection).GetProperty(Claims.Active).GetBoolean());
    }

    [Fact]
    public async Task ApplyIntrospectionResponse_TokenIsNotEncryptedWhenClientHasNoEncryptionKey()
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Confidential, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.ValidateClientSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.GetJsonWebKeySetAsync(application, It.IsAny<CancellationToken>()))
                .ReturnsAsync(CreateRequestObjectJsonWebKeySet());
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.EnableJsonWebTokenIntrospectionResponses();
            options.Services.AddSingleton(manager);

            ConfigureIntrospectedToken(options);
        });

        await using var client = await server.CreateClientAsync();
        client.RequestHeaders["Accept"] = [IntrospectionResponseMediaType];

        // Act
        await client.PostAsync("/connect/introspect", CreateIntrospectionRequest(secret: "7Fjfp0ZBr1KtDRbnfVdmIw"));

        // Assert
        Assert.NotNull(client.ResponseToken);
        Assert.False(new JsonWebToken(client.ResponseToken).IsEncrypted);
    }

    private static OpenIddictRequest CreateIntrospectionRequest(string? secret = null) => new()
    {
        ClientId = "Fabrikam",
        ClientSecret = secret,
        Token = "2YotnFZFEjr1zCsicMWpAA",
        TokenTypeHint = TokenTypeHints.AccessToken
    };

    private static void ConfigureIntrospectedToken(OpenIddictServerBuilder options)
    {
        options.AddEventHandler<ValidateTokenContext>(builder =>
        {
            builder.UseInlineHandler(context =>
            {
                context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                    .SetTokenType(TokenTypeIdentifiers.AccessToken)
                    .SetAudiences("Fabrikam")
                    .SetPresenters("Fabrikam")
                    .SetClaim(Claims.Subject, "Bob le Magnifique");

                return ValueTask.CompletedTask;
            });

            builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
        });
    }

    private static async Task<JsonWebToken> ValidateIntrospectionResponseTokenAsync(
        OpenIddictServerIntegrationTestClient client, string token, SecurityKey? decryptionKey = null)
    {
        var keys = await client.GetAsync("/.well-known/jwks");

        var result = await new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
        {
            IssuerSigningKeys = new JsonWebKeySet(JsonSerializer.Serialize(keys)).GetSigningKeys(),
            RequireExpirationTime = false,
            TokenDecryptionKey = decryptionKey,
            ValidAudience = "Fabrikam",
            ValidIssuer = "http://localhost/",
            ValidTypes = [JsonWebTokenTypes.IntrospectionResponse]
        });

        Assert.True(result.IsValid, result.Exception?.ToString());

        var jwt = (JsonWebToken) result.SecurityToken;
        return jwt.InnerToken ?? jwt;
    }
}
