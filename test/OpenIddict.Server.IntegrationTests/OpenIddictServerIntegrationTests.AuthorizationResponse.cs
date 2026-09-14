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
using OpenIddict.Core;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Server.IntegrationTests;

public abstract partial class OpenIddictServerIntegrationTests
{
    [Fact]
    public async Task HandleConfigurationRequest_JwtResponseModesAndAlgorithmsAreReturnedWhenEnabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableJwtSecuredAuthorizationResponses());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        var modes = (ImmutableArray<string?>?) response[Metadata.ResponseModesSupported];
        Assert.NotNull(modes);
        Assert.Contains(ResponseModes.Jwt, modes.Value, StringComparer.Ordinal);
        Assert.Contains(ResponseModes.QueryJwt, modes.Value, StringComparer.Ordinal);
        Assert.Contains(ResponseModes.FragmentJwt, modes.Value, StringComparer.Ordinal);
        Assert.Contains(ResponseModes.FormPostJwt, modes.Value, StringComparer.Ordinal);

        var algorithms = (ImmutableArray<string?>?) response[Metadata.AuthorizationSigningAlgValuesSupported];
        Assert.NotNull(algorithms);
        Assert.Contains(SecurityAlgorithms.RsaSha256, algorithms.Value, StringComparer.Ordinal);
        Assert.Equal([SecurityAlgorithms.RsaOAEP], (ImmutableArray<string?>?) response[Metadata.AuthorizationEncryptionAlgValuesSupported]);
        Assert.Equal([SecurityAlgorithms.Aes128CbcHmacSha256, SecurityAlgorithms.Aes256CbcHmacSha512],
            (ImmutableArray<string?>?) response[Metadata.AuthorizationEncryptionEncValuesSupported]);
    }

    [Fact]
    public async Task HandleConfigurationRequest_JwtResponseModesOnlyIncludeEnabledBaseModes()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.EnableJwtSecuredAuthorizationResponses();
            options.Configure(options => options.ResponseModes.Remove(ResponseModes.FormPost));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        var modes = (ImmutableArray<string?>?) response[Metadata.ResponseModesSupported];
        Assert.NotNull(modes);
        Assert.Contains(ResponseModes.QueryJwt, modes.Value, StringComparer.Ordinal);
        Assert.DoesNotContain(ResponseModes.FormPostJwt, modes.Value, StringComparer.Ordinal);
        Assert.Null(response[Metadata.AuthorizationEncryptionAlgValuesSupported]);
    }

    [Fact]
    public async Task HandleConfigurationRequest_JwtResponseModesAreNotReturnedWhenDisabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        var modes = (ImmutableArray<string?>?) response[Metadata.ResponseModesSupported];
        Assert.NotNull(modes);
        Assert.DoesNotContain(ResponseModes.Jwt, modes.Value, StringComparer.Ordinal);
        Assert.DoesNotContain(ResponseModes.QueryJwt, modes.Value, StringComparer.Ordinal);
        Assert.Null(response[Metadata.AuthorizationSigningAlgValuesSupported]);
    }

    [Theory]
    [InlineData(ResponseModes.Jwt)]
    [InlineData(ResponseModes.QueryJwt)]
    [InlineData(ResponseModes.FragmentJwt)]
    [InlineData(ResponseModes.FormPostJwt)]
    public async Task ValidateAuthorizationRequest_JwtResponseModesAreRejectedWhenDisabled(string mode)
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseMode = mode,
            ResponseType = ResponseTypes.Code
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2032(Parameters.ResponseMode), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2032), response.ErrorUri);
        Assert.Null(response[Parameters.Response]);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_JwtResponseModeIsRejectedWhenBaseModeIsDisabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.EnableJwtSecuredAuthorizationResponses();
            options.Configure(options => options.ResponseModes.Remove(ResponseModes.FormPost));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseMode = ResponseModes.FormPostJwt,
            ResponseType = ResponseTypes.Code
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2032(Parameters.ResponseMode), response.ErrorDescription);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(ResponseModes.Query)]
    [InlineData(ResponseModes.FormPost)]
    public async Task ValidateAuthorizationRequest_NonJwtResponseModeIsRejectedWhenGloballyRequired(string? mode)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.EnableJwtSecuredAuthorizationResponses();
            options.RequireJwtSecuredAuthorizationResponses();
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseMode = mode,
            ResponseType = ResponseTypes.Code
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2320(Parameters.ResponseMode), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2320), response.ErrorUri);
    }

    [Theory]
    [InlineData("code id_token")]
    [InlineData("code token")]
    [InlineData("id_token")]
    [InlineData("token")]
    public async Task ValidateAuthorizationRequest_QueryJwtWithTokensIsRejectedInDegradedMode(string type)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.EnableJwtSecuredAuthorizationResponses();
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseMode = ResponseModes.QueryJwt,
            ResponseType = type,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2033(Parameters.ResponseType, Parameters.ResponseMode), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2033), response.ErrorUri);
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_NonJwtResponseModeIsRejectedWhenGloballyRequired()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.EnableJwtSecuredAuthorizationResponses();
            options.RequireJwtSecuredAuthorizationResponses();

            options.AddEventHandler<ValidatePushedAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context => ValueTask.CompletedTask));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseMode = ResponseModes.Query,
            ResponseType = ResponseTypes.Code
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2320(Parameters.ResponseMode), response.ErrorDescription);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_NonJwtResponseModeIsRejectedWhenRequiredByClient()
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateJwtResponseApplicationManager(application, mock =>
            mock.Setup(manager => manager.HasRequirementAsync(application,
                Requirements.Features.JwtSecuredAuthorizationResponses, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true));

        await using var server = await CreateServerAsync(options =>
        {
            options.EnableJwtSecuredAuthorizationResponses();
            options.Services.AddSingleton(manager);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2320(Parameters.ResponseMode), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2320), response.ErrorUri);

        Mock.Get(manager).Verify(manager => manager.HasRequirementAsync(application,
            Requirements.Features.JwtSecuredAuthorizationResponses, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_QueryJwtWithTokensIsRejectedWhenClientDidNotOptInForEncryption()
    {
        // Arrange
        var application = new OpenIddictApplication();
        var manager = CreateJwtResponseApplicationManager(application);

        await using var server = await CreateServerAsync(options =>
        {
            options.EnableJwtSecuredAuthorizationResponses();
            options.Services.AddSingleton(manager);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseMode = ResponseModes.QueryJwt,
            ResponseType = "code id_token",
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2033(Parameters.ResponseType, Parameters.ResponseMode), response.ErrorDescription);
    }

    [Theory]
    [InlineData(ResponseTypes.Code, ResponseModes.Jwt, '?')]
    [InlineData(ResponseTypes.Code, ResponseModes.QueryJwt, '?')]
    [InlineData(ResponseTypes.Code, ResponseModes.FragmentJwt, '#')]
    [InlineData("code id_token", ResponseModes.Jwt, '#')]
    [InlineData("id_token token", ResponseModes.Jwt, '#')]
    [InlineData("id_token", ResponseModes.FragmentJwt, '#')]
    public async Task ApplyAuthorizationResponse_ResponseIsReturnedAsSignedJwt(string type, string mode, char delimiter)
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureJwtResponseServer);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseMode = mode,
            ResponseType = type,
            Scope = Scopes.OpenId,
            State = "af0ifjsldkj"
        });

        // Assert
        var location = Assert.Single(client.ResponseHeaders["Location"]);
        Assert.StartsWith("http://www.fabrikam.com/path" + delimiter + Parameters.Response + "=", location, StringComparison.Ordinal);

        Assert.Equal([Parameters.Response], response.GetParameters().Select(static parameter => parameter.Key).ToArray());

        var token = await ValidateAuthorizationResponseTokenAsync(client, (string?) response[Parameters.Response]);
        Assert.Equal(JsonWebTokenTypes.GenericJsonWebToken, token.Typ);
        Assert.Equal("http://localhost/", token.Issuer);
        Assert.Equal("Fabrikam", Assert.Single(token.Audiences));
        Assert.True(token.TryGetPayloadValue<long>(Claims.ExpiresAt, out _));
        Assert.Equal("af0ifjsldkj", token.GetPayloadValue<string>(Parameters.State));
        Assert.False(token.TryGetPayloadValue<string>(Claims.Private.Audience, out _));

        if (type.Contains(ResponseTypes.Code, StringComparison.Ordinal))
        {
            Assert.False(string.IsNullOrEmpty(token.GetPayloadValue<string>(Parameters.Code)));
        }

        if (type.Contains(ResponseTypes.IdToken, StringComparison.Ordinal))
        {
            Assert.False(string.IsNullOrEmpty(token.GetPayloadValue<string>(Parameters.IdToken)));
        }
    }

    [Fact]
    public async Task ApplyAuthorizationResponse_FormPostJwtResponseIsReturnedAsHtmlForm()
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureJwtResponseServer);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseMode = ResponseModes.FormPostJwt,
            ResponseType = ResponseTypes.Code,
            State = "af0ifjsldkj"
        });

        // Assert
        Assert.Equal("text/html", client.ResponseMediaType);
        Assert.Equal([Parameters.Response], response.GetParameters().Select(static parameter => parameter.Key).ToArray());

        var token = await ValidateAuthorizationResponseTokenAsync(client, (string?) response[Parameters.Response]);
        Assert.False(string.IsNullOrEmpty(token.GetPayloadValue<string>(Parameters.Code)));
        Assert.Equal("af0ifjsldkj", token.GetPayloadValue<string>(Parameters.State));
    }

    [Fact]
    public async Task ApplyAuthorizationResponse_ErrorsAreReturnedAsSignedJwt()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.EnableJwtSecuredAuthorizationResponses();

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Reject(error: Errors.AccessDenied, description: "The user denied the request.");

                    return ValueTask.CompletedTask;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseMode = ResponseModes.Jwt,
            ResponseType = ResponseTypes.Code,
            State = "af0ifjsldkj"
        });

        // Assert
        Assert.Null(response.Error);

        var token = await ValidateAuthorizationResponseTokenAsync(client, (string?) response[Parameters.Response]);
        Assert.Equal(Errors.AccessDenied, token.GetPayloadValue<string>(Parameters.Error));
        Assert.Equal("The user denied the request.", token.GetPayloadValue<string>(Parameters.ErrorDescription));
        Assert.Equal("af0ifjsldkj", token.GetPayloadValue<string>(Parameters.State));
    }

    [Fact]
    public async Task ApplyAuthorizationResponse_TokenContainsCustomParameters()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            ConfigureJwtResponseServer(options);

            options.AddEventHandler<ApplyAuthorizationResponseContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Response["custom_parameter"] = "custom_value";
                    context.Response["parameter_with_multiple_values"] = new(["custom_value_1", "custom_value_2"]);

                    return ValueTask.CompletedTask;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseMode = ResponseModes.QueryJwt,
            ResponseType = ResponseTypes.Code
        });

        // Assert
        var token = await ValidateAuthorizationResponseTokenAsync(client, (string?) response[Parameters.Response]);
        Assert.Equal("custom_value", token.GetPayloadValue<string>("custom_parameter"));
        Assert.Equal(["custom_value_1", "custom_value_2"], token.GetPayloadValue<JsonElement>("parameter_with_multiple_values")
            .EnumerateArray().Select(static element => element.GetString()!).ToArray());
    }

    [Fact]
    public async Task ApplyAuthorizationResponse_NonJwtResponseModesAreNotAffected()
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureJwtResponseServer);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            State = "af0ifjsldkj"
        });

        // Assert
        Assert.NotNull(response.Code);
        Assert.Equal("af0ifjsldkj", response.State);
        Assert.Null(response[Parameters.Response]);
    }

    [Theory]
    [InlineData(SecurityAlgorithms.Aes256CbcHmacSha512, SecurityAlgorithms.Aes256CbcHmacSha512)]
    [InlineData(null, SecurityAlgorithms.Aes128CbcHmacSha256)]
    public async Task ApplyAuthorizationResponse_TokenIsEncryptedWhenClientOptedIn(string? method, string expected)
    {
        // Arrange
        using var algorithm = RSA.Create(keySizeInBits: 2048);

        var settings = ImmutableDictionary.Create<string, string>(StringComparer.Ordinal)
            .SetItem(Settings.AuthorizationResponse.EncryptionAlgorithm, SecurityAlgorithms.RsaOAEP);

        if (method is not null)
        {
            settings = settings.SetItem(Settings.AuthorizationResponse.EncryptionMethod, method);
        }

        var application = new OpenIddictApplication();

        await using var server = await CreateServerAsync(options =>
        {
            ConfigureNonDegradedJwtResponseServer(options);
            options.Services.AddSingleton(CreateJwtResponseApplicationManager(application, settings, CreateEncryptionKeySet(algorithm)));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseMode = ResponseModes.QueryJwt,
            ResponseType = "code id_token",
            Scope = Scopes.OpenId,
            State = "af0ifjsldkj"
        });

        // Assert
        var value = (string?) response[Parameters.Response];
        Assert.NotNull(value);

        var envelope = new JsonWebToken(value);
        Assert.True(envelope.IsEncrypted);
        Assert.Equal(SecurityAlgorithms.RsaOAEP, envelope.Alg);
        Assert.Equal(expected, envelope.Enc);

        var token = await ValidateAuthorizationResponseTokenAsync(client, value, new RsaSecurityKey(algorithm));
        Assert.Equal("af0ifjsldkj", token.GetPayloadValue<string>(Parameters.State));
        Assert.False(string.IsNullOrEmpty(token.GetPayloadValue<string>(Parameters.Code)));
    }

    [Fact]
    public async Task ApplyAuthorizationResponse_MissingEncryptionKeyCausesAnException()
    {
        // Arrange
        var settings = ImmutableDictionary.Create<string, string>(StringComparer.Ordinal)
            .SetItem(Settings.AuthorizationResponse.EncryptionAlgorithm, SecurityAlgorithms.RsaOAEP);

        var application = new OpenIddictApplication();

        await using var server = await CreateServerAsync(options =>
        {
            ConfigureNonDegradedJwtResponseServer(options);
            options.Services.AddSingleton(CreateJwtResponseApplicationManager(application, settings, CreateRequestObjectJsonWebKeySet()));
        });

        await using var client = await server.CreateClientAsync();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
        {
            return client.PostAsync("/connect/authorize", CreateJwtResponseRequest());
        });

        Assert.Equal(SR.GetResourceString(SR.ID0646), exception.Message);
    }

    [Theory]
    [InlineData(Settings.AuthorizationResponse.EncryptionAlgorithm, SecurityAlgorithms.RsaOaepKeyWrap)]
    [InlineData(Settings.AuthorizationResponse.EncryptionMethod, SecurityAlgorithms.Aes128Gcm)]
    public async Task ApplyAuthorizationResponse_UnsupportedEncryptionSettingCausesAnException(string name, string value)
    {
        // Arrange
        using var algorithm = RSA.Create(keySizeInBits: 2048);

        var settings = ImmutableDictionary.Create<string, string>(StringComparer.Ordinal)
            .SetItem(Settings.AuthorizationResponse.EncryptionAlgorithm, SecurityAlgorithms.RsaOAEP)
            .SetItem(name, value);

        var application = new OpenIddictApplication();

        await using var server = await CreateServerAsync(options =>
        {
            ConfigureNonDegradedJwtResponseServer(options);
            options.Services.AddSingleton(CreateJwtResponseApplicationManager(application, settings, CreateEncryptionKeySet(algorithm)));
        });

        await using var client = await server.CreateClientAsync();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
        {
            return client.PostAsync("/connect/authorize", CreateJwtResponseRequest());
        });

        Assert.Equal(SR.FormatID0645(value, name), exception.Message);
    }

    [Fact]
    public async Task ApplyAuthorizationResponse_UnknownSigningAlgorithmSettingCausesAnException()
    {
        // Arrange
        var settings = ImmutableDictionary.Create<string, string>(StringComparer.Ordinal)
            .SetItem(Settings.AuthorizationResponse.SigningAlgorithm, SecurityAlgorithms.EcdsaSha512);

        var application = new OpenIddictApplication();

        await using var server = await CreateServerAsync(options =>
        {
            ConfigureNonDegradedJwtResponseServer(options);
            options.Services.AddSingleton(CreateJwtResponseApplicationManager(application, settings, set: null));
        });

        await using var client = await server.CreateClientAsync();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
        {
            return client.PostAsync("/connect/authorize", CreateJwtResponseRequest());
        });

        Assert.Equal(SR.FormatID0644(SecurityAlgorithms.EcdsaSha512, Settings.AuthorizationResponse.SigningAlgorithm), exception.Message);
    }

    [Fact]
    public async Task ApplyAuthorizationResponse_MatchingSigningAlgorithmSettingIsUsed()
    {
        // Arrange
        var settings = ImmutableDictionary.Create<string, string>(StringComparer.Ordinal)
            .SetItem(Settings.AuthorizationResponse.SigningAlgorithm, SecurityAlgorithms.RsaSha256);

        var application = new OpenIddictApplication();

        await using var server = await CreateServerAsync(options =>
        {
            ConfigureNonDegradedJwtResponseServer(options);
            options.Services.AddSingleton(CreateJwtResponseApplicationManager(application, settings, set: null));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", CreateJwtResponseRequest());

        // Assert
        var token = await ValidateAuthorizationResponseTokenAsync(client, (string?) response[Parameters.Response]);
        Assert.Equal(SecurityAlgorithms.RsaSha256, token.Alg);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_NonJwtResponseModeIsRejectedWhenRequiredByClientAndJarmIsDisabled()
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateJwtResponseApplicationManager(application, mock =>
            mock.Setup(manager => manager.HasRequirementAsync(application,
                Requirements.Features.JwtSecuredAuthorizationResponses, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true));

        await using var server = await CreateServerAsync(options => options.Services.AddSingleton(manager));
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2320(Parameters.ResponseMode), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2320), response.ErrorUri);

        Mock.Get(manager).Verify(manager => manager.HasRequirementAsync(application,
            Requirements.Features.JwtSecuredAuthorizationResponses, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ValidatePushedAuthorizationRequest_NonJwtResponseModeIsRejectedWhenRequiredByClient(bool enabled)
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateJwtResponseApplicationManager(application, mock =>
        {
            mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.HasRequirementAsync(application,
                Requirements.Features.JwtSecuredAuthorizationResponses, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);
        });

        await using var server = await CreateServerAsync(options =>
        {
            if (enabled)
            {
                options.EnableJwtSecuredAuthorizationResponses();
            }

            options.Services.AddSingleton(manager);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseMode = ResponseModes.Query,
            ResponseType = ResponseTypes.Code
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2320(Parameters.ResponseMode), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2320), response.ErrorUri);

        Mock.Get(manager).Verify(manager => manager.HasRequirementAsync(application,
            Requirements.Features.JwtSecuredAuthorizationResponses, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_QueryJwtWithTokensIsRejectedWhenClientDidNotOptInForEncryption()
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateJwtResponseApplicationManager(application, mock =>
            mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true));

        await using var server = await CreateServerAsync(options =>
        {
            options.EnableJwtSecuredAuthorizationResponses();
            options.Services.AddSingleton(manager);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseMode = ResponseModes.QueryJwt,
            ResponseType = "code id_token",
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2033(Parameters.ResponseType, Parameters.ResponseMode), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2033), response.ErrorUri);
    }

    [Theory]
    [InlineData("code id_token")]
    [InlineData("code token")]
    [InlineData("id_token")]
    [InlineData("token")]
    public async Task ValidatePushedAuthorizationRequest_QueryJwtWithTokensIsRejectedInDegradedMode(string type)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.EnableJwtSecuredAuthorizationResponses();

            options.AddEventHandler<ValidatePushedAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context => ValueTask.CompletedTask));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseMode = ResponseModes.QueryJwt,
            ResponseType = type,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2033(Parameters.ResponseType, Parameters.ResponseMode), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2033), response.ErrorUri);
    }

    [Fact]
    public async Task ApplyAuthorizationResponse_SigningAlgorithmSettingMatchesXmlDSigCredentials()
    {
        // Arrange
        using var algorithm = RSA.Create(keySizeInBits: 2048);
        using var curve = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var settings = ImmutableDictionary.Create<string, string>(StringComparer.Ordinal)
            .SetItem(Settings.AuthorizationResponse.SigningAlgorithm, SecurityAlgorithms.RsaSha256);

        var application = new OpenIddictApplication();

        await using var server = await CreateServerAsync(options =>
        {
            ConfigureNonDegradedJwtResponseServer(options);

            options.Configure(options => options.SigningCredentials.Clear());
            options.AddSigningCredentials(new SigningCredentials(
                new ECDsaSecurityKey(curve) { KeyId = "ec" }, SecurityAlgorithms.EcdsaSha256));
            options.AddSigningCredentials(new SigningCredentials(
                new RsaSecurityKey(algorithm) { KeyId = "rsa" }, SecurityAlgorithms.RsaSha256Signature));

            options.Services.AddSingleton(CreateJwtResponseApplicationManager(application, settings, set: null));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", CreateJwtResponseRequest());

        // Assert
        var value = (string?) response[Parameters.Response];
        Assert.False(string.IsNullOrEmpty(value));
        Assert.Equal("rsa", new JsonWebToken(value).Kid);
    }

    [Fact]
    public async Task ApplyAuthorizationResponse_Rs256CredentialsArePreferredByDefault()
    {
        // Arrange
        using var algorithm = RSA.Create(keySizeInBits: 2048);
        using var curve = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        await using var server = await CreateServerAsync(options =>
        {
            ConfigureJwtResponseServer(options);

            options.Configure(options => options.SigningCredentials.Clear());
            options.AddSigningCredentials(new SigningCredentials(
                new ECDsaSecurityKey(curve) { KeyId = "ec" }, SecurityAlgorithms.EcdsaSha256));
            options.AddSigningCredentials(new SigningCredentials(
                new RsaSecurityKey(algorithm) { KeyId = "rsa" }, SecurityAlgorithms.RsaSha256));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", CreateJwtResponseRequest());

        // Assert
        var token = await ValidateAuthorizationResponseTokenAsync(client, (string?) response[Parameters.Response]);
        Assert.Equal("rsa", token.Kid);
        Assert.Equal(SecurityAlgorithms.RsaSha256, token.Alg);
    }

    private static OpenIddictRequest CreateJwtResponseRequest() => new()
    {
        ClientId = "Fabrikam",
        RedirectUri = "http://www.fabrikam.com/path",
        ResponseMode = ResponseModes.Jwt,
        ResponseType = ResponseTypes.Code,
        State = "af0ifjsldkj"
    };

    private static void ConfigureJwtResponseServer(OpenIddictServerBuilder options)
    {
        options.EnableDegradedMode();
        options.EnableJwtSecuredAuthorizationResponses();

        options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
            builder.UseInlineHandler(context =>
            {
                context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                    .SetClaim(Claims.Subject, "Bob le Magnifique");

                return ValueTask.CompletedTask;
            }));
    }

    private static void ConfigureNonDegradedJwtResponseServer(OpenIddictServerBuilder options)
    {
        options.SetDeviceAuthorizationEndpointUris(Array.Empty<Uri>());
        options.SetRevocationEndpointUris(Array.Empty<Uri>());
        options.Configure(options => options.GrantTypes.Remove(GrantTypes.DeviceCode));
        options.DisableAuthorizationStorage();
        options.DisableTokenStorage();
        options.DisableSlidingRefreshTokenExpiration();
        options.EnableJwtSecuredAuthorizationResponses();

        options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
            builder.UseInlineHandler(context =>
            {
                context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                    .SetClaim(Claims.Subject, "Bob le Magnifique");

                return ValueTask.CompletedTask;
            }));
    }

    private OpenIddictApplicationManager<OpenIddictApplication> CreateJwtResponseApplicationManager(
        OpenIddictApplication application, Action<Mock<OpenIddictApplicationManager<OpenIddictApplication>>>? configuration = null)
        => CreateJwtResponseApplicationManager(application, ImmutableDictionary.Create<string, string>(StringComparer.Ordinal), set: null, configuration);

    private OpenIddictApplicationManager<OpenIddictApplication> CreateJwtResponseApplicationManager(
        OpenIddictApplication application, ImmutableDictionary<string, string> settings, JsonWebKeySet? set,
        Action<Mock<OpenIddictApplicationManager<OpenIddictApplication>>>? configuration = null)
    {
        return CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.GetSettingsAsync(application, It.IsAny<CancellationToken>()))
                .ReturnsAsync(settings);

            mock.Setup(manager => manager.GetJsonWebKeySetAsync(application, It.IsAny<CancellationToken>()))
                .ReturnsAsync(set);

            configuration?.Invoke(mock);
        });
    }

    private static async Task<JsonWebToken> ValidateAuthorizationResponseTokenAsync(
        OpenIddictServerIntegrationTestClient client, string? token, SecurityKey? decryptionKey = null)
    {
        Assert.False(string.IsNullOrEmpty(token));

        var keys = await client.GetAsync("/.well-known/jwks");

        var result = await new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
        {
            IssuerSigningKeys = new JsonWebKeySet(JsonSerializer.Serialize(keys)).GetSigningKeys(),
            RequireExpirationTime = true,
            TokenDecryptionKey = decryptionKey,
            ValidAudience = "Fabrikam",
            ValidIssuer = "http://localhost/"
        });

        Assert.True(result.IsValid, result.Exception?.ToString());

        var jwt = (JsonWebToken) result.SecurityToken;
        return jwt.InnerToken ?? jwt;
    }
}
