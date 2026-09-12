/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Security.Claims;
using System.Security.Cryptography;
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
    private const string RequestObjectIssuer = "https://www.contoso.com/";

    private static readonly RsaSecurityKey RequestObjectSigningKey = new(RSA.Create(keySizeInBits: 2048))
    {
        KeyId = "request_object_signing_key"
    };

    [Fact]
    public async Task ValidateAuthorizationRequest_RequestAndRequestUriParametersCannotBeUsedTogether()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.EnableRequestObjectSupport();
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Request = CreateRequestObject(new(StringComparer.Ordinal) { [Parameters.ResponseType] = ResponseTypes.Code }),
            RequestUri = RequestUris.Prefixes.Generic + "value"
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2074(Parameters.Request), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2074), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_RequestObjectWithoutClientIdParameterIsRejected()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.EnableRequestObjectSupport();
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            Request = CreateRequestObject(new(StringComparer.Ordinal) { [Parameters.ResponseType] = ResponseTypes.Code })
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2177(Parameters.ClientId), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2177), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_MissingRequestObjectIsRejectedWhenGloballyRequired()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.EnableRequestObjectSupport();
            options.RequireSignedRequestObjects();
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
        Assert.Equal(SR.FormatID2029(Parameters.Request), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2029), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_UnsignedRequestObjectIsRejected()
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureRequestObjectServer);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Request = CreateRequestObject(new(StringComparer.Ordinal) { [Parameters.ResponseType] = ResponseTypes.Code }, unsigned: true)
        });

        // Assert
        Assert.Equal(Errors.InvalidRequestObject, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2211), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2211), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_RequestObjectSignedWithUnknownKeyIsRejected()
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureRequestObjectServer);
        await using var client = await server.CreateClientAsync();

        var key = new RsaSecurityKey(RSA.Create(keySizeInBits: 2048)) { KeyId = "unknown_key" };

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Request = CreateRequestObject(new(StringComparer.Ordinal) { [Parameters.ResponseType] = ResponseTypes.Code },
                credentials: new SigningCredentials(key, SecurityAlgorithms.RsaSha256))
        });

        // Assert
        Assert.Equal(Errors.InvalidRequestObject, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2211), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2211), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_RequestObjectWithInvalidTypeIsRejected()
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureRequestObjectServer);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Request = CreateRequestObject(new(StringComparer.Ordinal) { [Parameters.ResponseType] = ResponseTypes.Code },
                type: JsonWebTokenTypes.ClientAuthentication)
        });

        // Assert
        Assert.Equal(Errors.InvalidRequestObject, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2211), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2211), response.ErrorUri);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("https://www.fabrikam.com/")]
    public async Task ValidateAuthorizationRequest_RequestObjectWithInvalidAudienceIsRejected(string? audience)
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureRequestObjectServer);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Request = CreateRequestObject(new(StringComparer.Ordinal) { [Parameters.ResponseType] = ResponseTypes.Code }, audience: audience)
        });

        // Assert
        Assert.Equal(Errors.InvalidRequestObject, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2211), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2211), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_ExpiredRequestObjectIsRejected()
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureRequestObjectServer);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Request = CreateRequestObject(new(StringComparer.Ordinal) { [Parameters.ResponseType] = ResponseTypes.Code },
                expires: DateTime.UtcNow.AddHours(-1))
        });

        // Assert
        Assert.Equal(Errors.InvalidRequestObject, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2211), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2211), response.ErrorUri);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("Contoso")]
    public async Task ValidateAuthorizationRequest_RequestObjectWithInvalidIssuerIsRejected(string? issuer)
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureRequestObjectServer);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Request = CreateRequestObject(new(StringComparer.Ordinal) { [Parameters.ResponseType] = ResponseTypes.Code }, issuer: issuer)
        });

        // Assert
        Assert.Equal(Errors.InvalidRequestObject, response.Error);
        Assert.Equal(SR.FormatID2212(Claims.Issuer), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2212), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_RequestObjectWithMismatchedClientIdIsRejected()
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureRequestObjectServer);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Request = CreateRequestObject(new(StringComparer.Ordinal)
            {
                [Parameters.ClientId] = "Contoso",
                [Parameters.ResponseType] = ResponseTypes.Code
            })
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2178(Parameters.ClientId), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2178), response.ErrorUri);
    }

    [Theory]
    [InlineData(Parameters.Request)]
    [InlineData(Parameters.RequestUri)]
    public async Task ValidateAuthorizationRequest_NestedRequestParameterIsRejected(string parameter)
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureRequestObjectServer);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Request = CreateRequestObject(new(StringComparer.Ordinal)
            {
                [parameter] = "value",
                [Parameters.ResponseType] = ResponseTypes.Code
            })
        });

        // Assert
        Assert.Equal(Errors.InvalidRequestObject, response.Error);
        Assert.Equal(SR.FormatID2074(parameter), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2074), response.ErrorUri);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(JsonWebTokenTypes.AuthorizationRequest)]
    [InlineData(JsonWebTokenTypes.Prefixes.Application + JsonWebTokenTypes.AuthorizationRequest)]
    [InlineData(JsonWebTokenTypes.GenericJsonWebToken)]
    public async Task ValidateAuthorizationRequest_ParametersAreResolvedFromRequestObject(string? type)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            ConfigureRequestObjectServer(options);

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    // Parameters attached outside the request object must be ignored.
                    Assert.Null(context.Request["custom_parameter"]);
                    Assert.Equal("value", (string?) context.Request["object_parameter"]);
                    Assert.Equal(42, (long?) context.Request["numeric_parameter"]);
                    Assert.Equal("Fabrikam", context.Request.ClientId);
                    Assert.Null(context.Request[Claims.Issuer]);
                    Assert.Null(context.Request[Claims.Audience]);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return ValueTask.CompletedTask;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Nonce = "outer_nonce",
            RedirectUri = "http://www.contoso.com/path",
            ResponseType = ResponseTypes.Code,
            State = "outer_state",
            ["custom_parameter"] = "value",
            Request = CreateRequestObject(new(StringComparer.Ordinal)
            {
                [Parameters.Nonce] = "n-0S6_WzA2Mj",
                [Parameters.RedirectUri] = "http://www.fabrikam.com/path",
                [Parameters.ResponseType] = ResponseTypes.Token,
                [Parameters.State] = "af0ifjsldkj",
                ["object_parameter"] = "value",
                ["numeric_parameter"] = 42
            }, type: type)
        });

        // Assert
        Assert.Null(response.Error);
        Assert.Null(response.ErrorDescription);
        Assert.NotNull(response.AccessToken);
        Assert.Null(response.Code);
        Assert.Equal("af0ifjsldkj", response.State);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_RequestObjectIsValidatedUsingClientJsonWebKeySet()
    {
        // Arrange
        var application = new OpenIddictApplication();

        await using var server = await CreateServerAsync(options =>
        {
            options.EnableRequestObjectSupport();
            options.SetIssuer(new Uri(RequestObjectIssuer, UriKind.Absolute));
            options.SetDeviceAuthorizationEndpointUris(Array.Empty<Uri>());
            options.SetRevocationEndpointUris(Array.Empty<Uri>());
            options.Configure(options => options.GrantTypes.Remove(GrantTypes.DeviceCode));
            options.DisableTokenStorage();
            options.DisableSlidingRefreshTokenExpiration();

            options.Services.AddSingleton(CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                mock.Setup(manager => manager.GetJsonWebKeySetAsync(application, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(CreateRequestObjectJsonWebKeySet());

                mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.GetSettingsAsync(application, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(ImmutableDictionary.Create<string, string>(StringComparer.Ordinal));
            }));

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return ValueTask.CompletedTask;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Request = CreateRequestObject(new(StringComparer.Ordinal)
            {
                [Parameters.Nonce] = "n-0S6_WzA2Mj",
                [Parameters.RedirectUri] = "http://www.fabrikam.com/path",
                [Parameters.ResponseType] = ResponseTypes.Token
            })
        });

        // Assert
        Assert.Null(response.Error);
        Assert.Null(response.ErrorDescription);
        Assert.NotNull(response.AccessToken);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_MissingRequestObjectIsRejectedWhenRequiredByClient()
    {
        // Arrange
        var application = new OpenIddictApplication();

        await using var server = await CreateServerAsync(options =>
        {
            options.EnableRequestObjectSupport();

            options.Services.AddSingleton(CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.HasRequirementAsync(application,
                    Requirements.Features.SignedRequestObjects, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);
            }));
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
        Assert.Equal(SR.FormatID2054(Parameters.Request), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2054), response.ErrorUri);
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_RequestObjectIsRejectedWhenSupportIsDisabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Request = CreateRequestObject(new(StringComparer.Ordinal) { [Parameters.ResponseType] = ResponseTypes.Code })
        });

        // Assert
        Assert.Equal(Errors.RequestNotSupported, response.Error);
        Assert.Equal(SR.FormatID2028(Parameters.Request), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2028), response.ErrorUri);
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_MissingRequestObjectIsRejectedWhenGloballyRequired()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.EnableRequestObjectSupport();
            options.RequireSignedRequestObjects();
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2029(Parameters.Request), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2029), response.ErrorUri);
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_InvalidRequestObjectIsRejected()
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureRequestObjectServer);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Request = CreateRequestObject(new(StringComparer.Ordinal) { [Parameters.ResponseType] = ResponseTypes.Code }, audience: "https://www.fabrikam.com/")
        });

        // Assert
        Assert.Equal(Errors.InvalidRequestObject, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2211), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2211), response.ErrorUri);
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_ParametersAreResolvedFromRequestObject()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            ConfigureRequestObjectServer(options);

            options.AddEventHandler<HandlePushedAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("http://www.fabrikam.com/path", context.Request.RedirectUri);
                    Assert.Equal(ResponseTypes.Code, context.Request.ResponseType);
                    Assert.Equal(Scopes.OpenId, context.Request.Scope);
                    Assert.Null(context.Request.Request);

                    return ValueTask.CompletedTask;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.contoso.com/path",
            Request = CreateRequestObject(new(StringComparer.Ordinal)
            {
                [Parameters.Nonce] = "n-0S6_WzA2Mj",
                [Parameters.RedirectUri] = "http://www.fabrikam.com/path",
                [Parameters.ResponseType] = ResponseTypes.Code,
                [Parameters.Scope] = Scopes.OpenId
            })
        });

        // Assert
        Assert.Null(response.Error);
        Assert.Null(response.ErrorDescription);
        Assert.NotNull(response.RequestUri);
    }

    [Fact]
    public async Task HandleConfigurationRequest_RequestObjectMetadataIsReturnedWhenSupportIsEnabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableRequestObjectSupport();
            options.RequireSignedRequestObjects();
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.True((bool) response[Metadata.RequestParameterSupported]);
        Assert.True((bool) response[Metadata.RequireSignedRequestObject]);
        Assert.Contains(SecurityAlgorithms.RsaSha256, (ImmutableArray<string?>?) response[Metadata.RequestObjectSigningAlgValuesSupported] ?? [], StringComparer.Ordinal);
        Assert.Contains(SecurityAlgorithms.EcdsaSha256, (ImmutableArray<string?>?) response[Metadata.RequestObjectSigningAlgValuesSupported] ?? [], StringComparer.Ordinal);
    }

    private static void ConfigureRequestObjectServer(OpenIddictServerBuilder options)
    {
        options.EnableDegradedMode();
        options.EnableRequestObjectSupport();
        options.SetIssuer(new Uri(RequestObjectIssuer, UriKind.Absolute));

        // Note: in degraded mode, the signing keys used to validate request objects must be attached manually.
        options.AddEventHandler<ValidateTokenContext>(builder =>
        {
            builder.UseInlineHandler(context =>
            {
                if (context.ValidTokenTypes.Contains(TokenTypeIdentifiers.Private.RequestObject))
                {
                    context.TokenValidationParameters.IssuerSigningKeys = CreateRequestObjectJsonWebKeySet().GetSigningKeys();
                }

                return ValueTask.CompletedTask;
            });

            builder.SetOrder(ResolveTokenValidationParameters.Descriptor.Order + 500);
        });
    }

    private static JsonWebKeySet CreateRequestObjectJsonWebKeySet()
    {
        var key = JsonWebKeyConverter.ConvertFromRSASecurityKey(new RsaSecurityKey(
            RequestObjectSigningKey.Rsa.ExportParameters(includePrivateParameters: false)));

        key.Kid = RequestObjectSigningKey.KeyId;
        key.Use = JsonWebKeyUseNames.Sig;

        return new JsonWebKeySet { Keys = { key } };
    }

    private static string CreateRequestObject(
        Dictionary<string, object> claims,
        string? issuer = "Fabrikam",
        string? audience = RequestObjectIssuer,
        string? type = JsonWebTokenTypes.AuthorizationRequest,
        DateTime? expires = null,
        SigningCredentials? credentials = null,
        bool unsigned = false)
    {
        credentials ??= new SigningCredentials(RequestObjectSigningKey, SecurityAlgorithms.RsaSha256);

        var descriptor = new SecurityTokenDescriptor
        {
            Audience = audience,
            Claims = claims,
            Expires = expires ?? DateTime.UtcNow.AddMinutes(5),
            IssuedAt = (expires ?? DateTime.UtcNow.AddMinutes(5)).AddMinutes(-10),
            Issuer = issuer,
            NotBefore = (expires ?? DateTime.UtcNow.AddMinutes(5)).AddMinutes(-10),
            SigningCredentials = unsigned ? null : credentials,
            TokenType = type
        };

        return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(descriptor);
    }
}
