using System.Buffers.Text;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using static OpenIddict.Client.OpenIddictClientEvents;
using static OpenIddict.Client.OpenIddictClientHandlers;

namespace OpenIddict.Client.Tests;

public class OpenIddictClientHandlersBackchannelTests
{
    [Fact]
    public async Task EvaluateBackchannelAuthenticationRequest_RequestIsSentForCibaGrant()
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateChallengeContext(provider);
        context.LoginHint = "bob@fabrikam.com";

        // Act
        await new EvaluateBackchannelAuthenticationRequest().HandleAsync(context);

        // Assert
        Assert.True(context.SendBackchannelAuthenticationRequest);
    }

    [Theory]
    [InlineData(null, null, null)]
    [InlineData("bob@fabrikam.com", "token", null)]
    [InlineData("bob@fabrikam.com", null, "id_token")]
    public async Task EvaluateBackchannelAuthenticationRequest_ThrowsAnExceptionForInvalidHints(string? hint, string? token, string? identity)
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateChallengeContext(provider);
        context.LoginHint = hint;
        context.LoginHintToken = token;
        context.IdentityTokenHint = identity;

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await new EvaluateBackchannelAuthenticationRequest().HandleAsync(context));

        Assert.Equal(SR.GetResourceString(SR.ID0541), exception.Message);
    }

    [Fact]
    public async Task AttachBackchannelAuthenticationRequestParameters_ParametersAreAttached()
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateChallengeContext(provider);
        context.BindingMessage = "W4SCT";
        context.LoginHint = "bob@fabrikam.com";
        context.RequestedExpiry = TimeSpan.FromSeconds(119.5);
        context.Scopes.Add(Scopes.Profile);

        // Act
        await new AttachBackchannelAuthenticationRequestParameters().HandleAsync(context);

        // Assert
        Assert.NotNull(context.BackchannelAuthenticationRequest);
        Assert.Equal("openid profile", context.BackchannelAuthenticationRequest.Scope);
        Assert.Equal("bob@fabrikam.com", context.BackchannelAuthenticationRequest.LoginHint);
        Assert.Equal("W4SCT", context.BackchannelAuthenticationRequest.BindingMessage);
        Assert.Equal(120, context.BackchannelAuthenticationRequest.RequestedExpiry);
        Assert.Null(context.BackchannelAuthenticationRequest.IdTokenHint);
    }

    [Fact]
    public async Task ValidateAuthenticationRequestId_MissingIdentifierCausesAnError()
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateResponseContext(provider, new OpenIddictResponse { ExpiresIn = 120 });

        // Act
        await new Backchannel.ValidateAuthenticationRequestId().HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(Errors.ServerError, context.Error);
        Assert.Equal(SR.FormatID2168(Parameters.AuthReqId), context.ErrorDescription);
    }

    [Fact]
    public async Task ValidateExpiration_MissingExpirationCausesAnError()
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateResponseContext(provider, new OpenIddictResponse { AuthReqId = "id" });

        // Act
        await new Backchannel.ValidateExpiration().HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(SR.FormatID2168(Parameters.ExpiresIn), context.ErrorDescription);
    }

    [Theory]
    [InlineData(Errors.UnknownUserId, Errors.UnknownUserId)]
    [InlineData(Errors.ExpiredLoginHintToken, Errors.ExpiredLoginHintToken)]
    [InlineData(Errors.InvalidClient, Errors.InvalidRequest)]
    [InlineData("custom_error", Errors.ServerError)]
    public async Task HandleErrorResponse_ErrorsAreMapped(string error, string expected)
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateResponseContext(provider, new OpenIddictResponse { Error = error });

        // Act
        await new Backchannel.HandleErrorResponse().HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(expected, context.Error);
    }

    [Fact]
    public async Task ValidateWellKnownParameters_InvalidAuthenticationRequestIdTypeCausesAnError()
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateResponseContext(provider, new OpenIddictResponse(
            JsonSerializer.Deserialize<JsonElement>("""{ "auth_req_id": 42, "expires_in": 120 }""")));

        // Act
        await new Backchannel.ValidateWellKnownParameters().HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(SR.FormatID2107(Parameters.AuthReqId), context.ErrorDescription);
    }

    [Fact]
    public async Task ExtractBackchannelAuthenticationEndpoint_MetadataIsExtracted()
    {
        // Arrange
        using var provider = CreateProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>().CurrentValue;

        var context = new HandleConfigurationResponseContext(new OpenIddictClientTransaction
        {
            CancellationToken = CancellationToken.None,
            Configuration = new OpenIddictConfiguration(),
            Options = options,
            Registration = options.Registrations[0],
            ServiceProvider = provider
        })
        {
            Response = new OpenIddictResponse(JsonSerializer.Deserialize<JsonElement>("""
            {
              "backchannel_authentication_endpoint": "https://www.contoso.com/connect/ciba",
              "backchannel_token_delivery_modes_supported": [ "poll" ],
              "backchannel_user_code_parameter_supported": false
            }
            """))
        };

        // Act
        await new OpenIddictClientHandlers.Discovery.ExtractBackchannelAuthenticationEndpoint().HandleAsync(context);

        // Assert
        Assert.False(context.IsRejected);
        Assert.Equal(new Uri("https://www.contoso.com/connect/ciba"), context.Configuration.BackchannelAuthenticationEndpoint);
        Assert.Contains(BackchannelTokenDeliveryModes.Poll, context.Configuration.BackchannelTokenDeliveryModesSupported);
        Assert.False(context.Configuration.BackchannelUserCodeParameterSupported);
    }

    [Theory]
    [InlineData(BackchannelTokenDeliveryModes.Ping)]
    [InlineData(BackchannelTokenDeliveryModes.Push)]
    public async Task AttachBackchannelAuthenticationRequestParameters_ClientNotificationTokenIsGeneratedForPingAndPushModes(string mode)
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateChallengeContext(provider);
        context.BackchannelTokenDeliveryMode = mode;
        context.BackchannelUserCode = "4815";
        context.LoginHint = "bob@fabrikam.com";

        // Act
        await new AttachBackchannelAuthenticationRequestParameters().HandleAsync(context);

        // Assert
        Assert.NotNull(context.BackchannelAuthenticationRequest);
        Assert.False(string.IsNullOrEmpty(context.ClientNotificationToken));
        Assert.Equal(43, context.ClientNotificationToken.Length);
        Assert.Equal(context.ClientNotificationToken, context.BackchannelAuthenticationRequest.ClientNotificationToken);
        Assert.Equal("4815", context.BackchannelAuthenticationRequest.UserCode);
    }

    [Fact]
    public async Task AttachBackchannelAuthenticationRequestParameters_ExplicitClientNotificationTokenIsUsed()
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateChallengeContext(provider);
        context.BackchannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Ping;
        context.ClientNotificationToken = "8C3C7A6D";
        context.LoginHint = "bob@fabrikam.com";

        // Act
        await new AttachBackchannelAuthenticationRequestParameters().HandleAsync(context);

        // Assert
        Assert.Equal("8C3C7A6D", context.BackchannelAuthenticationRequest?.ClientNotificationToken);
    }

    [Fact]
    public async Task AttachBackchannelAuthenticationRequestParameters_NoClientNotificationTokenIsSentForPollMode()
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateChallengeContext(provider);
        context.LoginHint = "bob@fabrikam.com";

        // Act
        await new AttachBackchannelAuthenticationRequestParameters().HandleAsync(context);

        // Assert
        Assert.Null(context.ClientNotificationToken);
        Assert.Null(context.BackchannelAuthenticationRequest?.ClientNotificationToken);
    }

    [Fact]
    public async Task AttachBackchannelAuthenticationRequestParameters_ThrowsAnExceptionForModesNotSupportedByTheServer()
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateChallengeContext(provider);
        context.BackchannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Push;
        context.Configuration.BackchannelTokenDeliveryModesSupported.Add(BackchannelTokenDeliveryModes.Poll);
        context.LoginHint = "bob@fabrikam.com";

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await new AttachBackchannelAuthenticationRequestParameters().HandleAsync(context));

        Assert.Equal(SR.FormatID0606(BackchannelTokenDeliveryModes.Push), exception.Message);
    }

    [Fact]
    public async Task EvaluateBackchannelAuthenticationRequest_ThrowsAnExceptionForUnsupportedMode()
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateChallengeContext(provider);
        context.BackchannelTokenDeliveryMode = "custom";
        context.LoginHint = "bob@fabrikam.com";

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await new EvaluateBackchannelAuthenticationRequest().HandleAsync(context));

        Assert.Equal(SR.FormatID0605("custom"), exception.Message);
    }

    [Fact]
    public async Task EvaluateBackchannelAuthenticationRequest_ThrowsAnExceptionForTooLongClientNotificationToken()
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateChallengeContext(provider);
        context.BackchannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Ping;
        context.ClientNotificationToken = new string('A', 1025);
        context.LoginHint = "bob@fabrikam.com";

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await new EvaluateBackchannelAuthenticationRequest().HandleAsync(context));

        Assert.Equal(SR.GetResourceString(SR.ID0607), exception.Message);
    }

    [Theory]
    [InlineData(null, true)]
    [InlineData(BackchannelTokenDeliveryModes.Ping, true)]
    [InlineData(BackchannelTokenDeliveryModes.Push, false)]
    public async Task EvaluateTokenRequest_NoTokenRequestIsSentForPushMode(string? mode, bool expected)
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateAuthenticationContext(provider);
        context.BackchannelTokenDeliveryMode = mode;

        // Act
        await new EvaluateTokenRequest().HandleAsync(context);

        // Assert
        Assert.Equal(expected, context.SendTokenRequest);
    }

    [Fact]
    public async Task ValidateBackchannelPushedTokens_ValidTokensAreAccepted()
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreatePushedTokensContext(provider, identifier: "F6B3B1E4", hash: true, refresh: true);

        // Act
        await new ValidateBackchannelPushedTokens().HandleAsync(context);

        // Assert
        Assert.False(context.IsRejected);
    }

    [Fact]
    public async Task ValidateBackchannelPushedTokens_IgnoredForPollAndPingModes()
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreatePushedTokensContext(provider, identifier: null, hash: false, refresh: false);
        context.BackchannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Ping;

        // Act
        await new ValidateBackchannelPushedTokens().HandleAsync(context);

        // Assert
        Assert.False(context.IsRejected);
    }

    [Fact]
    public async Task ValidateBackchannelPushedTokens_MissingAuthenticationRequestIdCausesAnError()
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreatePushedTokensContext(provider, identifier: null, hash: true, refresh: false);

        // Act
        await new ValidateBackchannelPushedTokens().HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(SR.FormatID2126(Claims.AuthReqId), context.ErrorDescription);
    }

    [Fact]
    public async Task ValidateBackchannelPushedTokens_MismatchedAuthenticationRequestIdCausesAnError()
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreatePushedTokensContext(provider, identifier: "other", hash: true, refresh: false);

        // Act
        await new ValidateBackchannelPushedTokens().HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(SR.FormatID2128(Claims.AuthReqId), context.ErrorDescription);
    }

    [Fact]
    public async Task ValidateBackchannelPushedTokens_MissingAccessTokenHashCausesAnError()
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreatePushedTokensContext(provider, identifier: "F6B3B1E4", hash: false, refresh: false);

        // Act
        await new ValidateBackchannelPushedTokens().HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(SR.FormatID2126(Claims.AccessTokenHash), context.ErrorDescription);
    }

    [Fact]
    public async Task ValidateBackchannelPushedTokens_MissingOrInvalidRefreshTokenHashCausesAnError()
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreatePushedTokensContext(provider, identifier: "F6B3B1E4", hash: true, refresh: false);
        context.RefreshToken = "refresh_token";

        // Act
        await new ValidateBackchannelPushedTokens().HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(SR.FormatID2126(Claims.RefreshTokenHash), context.ErrorDescription);

        // Arrange
        context = CreatePushedTokensContext(provider, identifier: "F6B3B1E4", hash: true, refresh: true);
        context.RefreshToken = "another_refresh_token";

        // Act
        await new ValidateBackchannelPushedTokens().HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(SR.FormatID2128(Claims.RefreshTokenHash), context.ErrorDescription);
    }

    [Fact]
    public async Task ExtractBackchannelAuthenticationEndpoint_DeliveryModesAndSigningAlgorithmsAreExtracted()
    {
        // Arrange
        using var provider = CreateProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>().CurrentValue;

        var context = new HandleConfigurationResponseContext(new OpenIddictClientTransaction
        {
            CancellationToken = CancellationToken.None,
            Configuration = new OpenIddictConfiguration(),
            Options = options,
            Registration = options.Registrations[0],
            ServiceProvider = provider
        })
        {
            Response = new OpenIddictResponse(JsonSerializer.Deserialize<JsonElement>("""
            {
              "backchannel_authentication_endpoint": "https://www.contoso.com/connect/ciba",
              "backchannel_token_delivery_modes_supported": [ "poll", "ping", "push" ],
              "backchannel_authentication_request_signing_alg_values_supported": [ "RS256", "ES256" ],
              "backchannel_user_code_parameter_supported": true
            }
            """))
        };

        // Act
        await new OpenIddictClientHandlers.Discovery.ExtractBackchannelAuthenticationEndpoint().HandleAsync(context);

        // Assert
        Assert.False(context.IsRejected);
        Assert.Equal(3, context.Configuration.BackchannelTokenDeliveryModesSupported.Count);
        Assert.Contains(BackchannelTokenDeliveryModes.Push, context.Configuration.BackchannelTokenDeliveryModesSupported);
        Assert.Contains("ES256", context.Configuration.BackchannelAuthenticationRequestSigningAlgValuesSupported);
        Assert.True(context.Configuration.BackchannelUserCodeParameterSupported);
    }

    [Fact]
    public async Task CreateBackchannelNotificationAsync_ExtractsBearerTokenAndPayload()
    {
        // Arrange
        using var body = new MemoryStream(Encoding.UTF8.GetBytes("""{ "auth_req_id": "F6B3B1E4" }"""));

        // Act
        var notification = await OpenIddictClientHelpers.CreateBackchannelNotificationAsync(
            "bearer 8C3C7A6D", "application/json; charset=utf-8", body);

        // Assert
        Assert.NotNull(notification);
        Assert.Equal("8C3C7A6D", notification.ClientNotificationToken);
        Assert.Equal("F6B3B1E4", notification.AuthenticationRequestId);
    }

    [Theory]
    [InlineData("application/x-www-form-urlencoded", """{ "auth_req_id": "F6B3B1E4" }""")]
    [InlineData("application/json", "[ 42 ]")]
    [InlineData("application/json", "not json")]
    public async Task CreateBackchannelNotificationAsync_ReturnsNullForInvalidRequests(string type, string payload)
    {
        // Arrange
        using var body = new MemoryStream(Encoding.UTF8.GetBytes(payload));

        // Act and assert
        Assert.Null(await OpenIddictClientHelpers.CreateBackchannelNotificationAsync("Bearer 8C3C7A6D", type, body));
    }

    [Theory]
    [InlineData(null, "F6B3B1E4", null, Errors.InvalidToken)]
    [InlineData("invalid", "F6B3B1E4", null, Errors.InvalidToken)]
    [InlineData("8C3C7A6D", null, null, Errors.InvalidRequest)]
    [InlineData("8C3C7A6D", "other", null, Errors.InvalidRequest)]
    [InlineData("8C3C7A6D", "F6B3B1E4", Errors.AccessDenied, Errors.AccessDenied)]
    public async Task AuthenticateWithBackchannelNotificationAsync_InvalidNotificationsAreRejected(
        string? token, string? identifier, string? error, string expected)
    {
        // Arrange
        using var provider = CreateProvider();
        var service = provider.GetRequiredService<OpenIddictClientService>();

        // Act and assert
        var exception = await Assert.ThrowsAsync<OpenIddictExceptions.ProtocolException>(async () =>
            await service.AuthenticateWithBackchannelNotificationAsync(new()
            {
                AuthenticationRequestId = "F6B3B1E4",
                ClientNotificationToken = "8C3C7A6D",
                Notification = new()
                {
                    ClientNotificationToken = token,
                    Payload = new OpenIddictResponse { AuthReqId = identifier, Error = error }
                },
                TokenDeliveryMode = BackchannelTokenDeliveryModes.Push
            }));

        Assert.Equal(expected, exception.Error);
    }

    [Fact]
    public async Task AuthenticateWithBackchannelNotificationAsync_PushedTokensAreValidated()
    {
        // Arrange
        using var provider = CreateProvider();
        var service = provider.GetRequiredService<OpenIddictClientService>();

        // Act
        var result = await service.AuthenticateWithBackchannelNotificationAsync(new()
        {
            AuthenticationRequestId = "F6B3B1E4",
            ClientNotificationToken = "8C3C7A6D",
            DisableUserInfo = true,
            Notification = new()
            {
                ClientNotificationToken = "8C3C7A6D",
                Payload = CreateTokenPayload("F6B3B1E4", refresh: true)
            },
            TokenDeliveryMode = BackchannelTokenDeliveryModes.Push
        });

        // Assert
        Assert.Equal("access_token", result.AccessToken);
        Assert.Equal("refresh_token", result.RefreshToken);
        Assert.NotNull(result.IdentityToken);
        Assert.Equal("Bob", result.IdentityTokenPrincipal?.GetClaim(Claims.Subject));
        Assert.Equal("Bob", result.Principal.GetClaim(Claims.Subject));
    }

    [Fact]
    public async Task AuthenticateWithBackchannelNotificationAsync_PushedTokensWithInvalidRefreshTokenHashAreRejected()
    {
        // Arrange
        using var provider = CreateProvider();
        var service = provider.GetRequiredService<OpenIddictClientService>();

        var payload = CreateTokenPayload("F6B3B1E4", refresh: true);
        payload.RefreshToken = "tampered_refresh_token";

        // Act and assert
        var exception = await Assert.ThrowsAsync<OpenIddictExceptions.ProtocolException>(async () =>
            await service.AuthenticateWithBackchannelNotificationAsync(new()
            {
                AuthenticationRequestId = "F6B3B1E4",
                ClientNotificationToken = "8C3C7A6D",
                DisableUserInfo = true,
                Notification = new()
                {
                    ClientNotificationToken = "8C3C7A6D",
                    Payload = payload
                },
                TokenDeliveryMode = BackchannelTokenDeliveryModes.Push
            }));

        Assert.Equal(SR.FormatID2128(Claims.RefreshTokenHash), exception.ErrorDescription);
    }

    [Fact]
    public async Task AuthenticateWithBackchannelNotificationAsync_PingNotificationIsRedeemedAtTokenEndpoint()
    {
        // Arrange
        OpenIddictRequest? request = null;

        using var provider = CreateProvider(options => options.AddEventHandler<ExtractTokenResponseContext>(builder =>
            builder.UseInlineHandler(context =>
            {
                request = context.Request;

                // Note: in ping mode, the token response doesn't contain the auth_req_id claim/parameter.
                context.Response = CreateTokenPayload(identifier: null, refresh: false);

                return ValueTask.CompletedTask;
            })));

        var service = provider.GetRequiredService<OpenIddictClientService>();

        // Act
        var result = await service.AuthenticateWithBackchannelNotificationAsync(new()
        {
            AuthenticationRequestId = "F6B3B1E4",
            ClientNotificationToken = "8C3C7A6D",
            DisableUserInfo = true,
            Notification = new()
            {
                ClientNotificationToken = "8C3C7A6D",
                Payload = new OpenIddictResponse { AuthReqId = "F6B3B1E4" }
            },
            TokenDeliveryMode = BackchannelTokenDeliveryModes.Ping
        });

        // Assert
        Assert.NotNull(request);
        Assert.Equal(GrantTypes.Ciba, request.GrantType);
        Assert.Equal("F6B3B1E4", request.AuthReqId);
        Assert.Equal("access_token", result.AccessToken);
        Assert.Equal("Bob", result.IdentityTokenPrincipal?.GetClaim(Claims.Subject));
    }

    [Fact]
    public async Task GenerateBackchannelAuthenticationRequestObject_ParametersAreReplacedBySignedRequest()
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateSignedRequestChallengeContext(provider, SecurityAlgorithms.RsaSha256);

        // Act
        await new GenerateBackchannelAuthenticationRequestObject(
            provider.GetRequiredService<IOpenIddictClientDispatcher>()).HandleAsync(context);

        // Assert
        Assert.False(context.IsRejected);

        var parameter = Assert.Single(context.BackchannelAuthenticationRequest!.GetParameters());
        Assert.Equal(Parameters.Request, parameter.Key);

        var token = new JsonWebToken((string) parameter.Value!);
        Assert.Equal(SecurityAlgorithms.RsaSha256, token.Alg);
        Assert.Equal("Fabrikam", token.Issuer);
        Assert.Equal("https://www.contoso.com/", Assert.Single(token.Audiences));
        Assert.False(string.IsNullOrEmpty(token.Id));
        Assert.True(token.TryGetPayloadValue<long>(Claims.ExpiresAt, out _));
        Assert.True(token.TryGetPayloadValue<long>(Claims.IssuedAt, out _));
        Assert.True(token.TryGetPayloadValue<long>(Claims.NotBefore, out _));
        Assert.Equal("bob@fabrikam.com", token.GetPayloadValue<string>(Parameters.LoginHint));
        Assert.Equal("W4SCT", token.GetPayloadValue<string>(Parameters.BindingMessage));
        Assert.Equal(120, token.GetPayloadValue<long>(Parameters.RequestedExpiry));

        // The signature must be verifiable using the public key of the client.
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
        {
            IssuerSigningKey = ClientSigningKey,
            ValidAudience = "https://www.contoso.com/",
            ValidIssuer = "Fabrikam",
            ValidTypes = [JsonWebTokenTypes.AuthorizationRequest]
        });

        Assert.True(result.IsValid, result.Exception?.Message);
    }

    [Fact]
    public async Task GenerateBackchannelAuthenticationRequestObject_ThrowsAnExceptionForUnsupportedAlgorithm()
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateSignedRequestChallengeContext(provider, SecurityAlgorithms.EcdsaSha256);

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await new GenerateBackchannelAuthenticationRequestObject(
                provider.GetRequiredService<IOpenIddictClientDispatcher>()).HandleAsync(context));

        Assert.Equal(SR.FormatID0610(SecurityAlgorithms.RsaSha256), exception.Message);
    }

    [Fact]
    public async Task GenerateBackchannelAuthenticationRequestObject_RequestIsNotSignedByDefault()
    {
        // Arrange
        using var provider = CreateProvider();
        var context = CreateSignedRequestChallengeContext(provider, SecurityAlgorithms.RsaSha256);
        context.Registration.UseSignedBackchannelAuthenticationRequests = false;

        // Act
        await new GenerateBackchannelAuthenticationRequestObject(
            provider.GetRequiredService<IOpenIddictClientDispatcher>()).HandleAsync(context);

        // Assert
        Assert.Null(context.BackchannelAuthenticationRequest!.Request);
        Assert.Equal("bob@fabrikam.com", context.BackchannelAuthenticationRequest.LoginHint);
    }

    private static readonly RsaSecurityKey ClientSigningKey = new(RSA.Create(keySizeInBits: 2048))
    {
        KeyId = "client_signing_key"
    };

    private static ProcessChallengeContext CreateSignedRequestChallengeContext(IServiceProvider provider, string algorithm)
    {
        var context = CreateChallengeContext(provider);
        context.Configuration.BackchannelAuthenticationRequestSigningAlgValuesSupported.Add(algorithm);

        context.Registration = new OpenIddictClientRegistration
        {
            ClientId = "Fabrikam",
            Issuer = new Uri("https://www.contoso.com/", UriKind.Absolute),
            SigningCredentials = { new SigningCredentials(ClientSigningKey, SecurityAlgorithms.RsaSha256) },
            UseSignedBackchannelAuthenticationRequests = true
        };

        context.BackchannelAuthenticationRequest = new OpenIddictRequest
        {
            BindingMessage = "W4SCT",
            LoginHint = "bob@fabrikam.com",
            RequestedExpiry = 120,
            Scope = Scopes.OpenId
        };

        return context;
    }

    private static OpenIddictResponse CreateTokenPayload(string? identifier, bool refresh)
    {
        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [Claims.AccessTokenHash] = ComputeHash("access_token"),
            [Claims.Subject] = "Bob"
        };

        if (!string.IsNullOrEmpty(identifier))
        {
            claims[Claims.AuthReqId] = identifier;
        }

        if (refresh)
        {
            claims[Claims.RefreshTokenHash] = ComputeHash("refresh_token");
        }

        var token = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Audience = "Fabrikam",
            Claims = claims,
            Expires = DateTime.UtcNow.AddMinutes(5),
            IssuedAt = DateTime.UtcNow,
            Issuer = "https://www.contoso.com/",
            SigningCredentials = new SigningCredentials(ServerSigningKey, SecurityAlgorithms.RsaSha256)
        });

        var response = new OpenIddictResponse
        {
            AccessToken = "access_token",
            AuthReqId = identifier,
            ExpiresIn = 3600,
            IdToken = token,
            TokenType = TokenTypes.Bearer
        };

        if (refresh)
        {
            response.RefreshToken = "refresh_token";
        }

        return response;

        static string ComputeHash(string value)
        {
            using var algorithm = SHA256.Create();
            var digest = algorithm.ComputeHash(Encoding.ASCII.GetBytes(value));
            return Base64Url.EncodeToString(digest.AsSpan(0, digest.Length / 2));
        }
    }

    private static ProcessAuthenticationContext CreateAuthenticationContext(IServiceProvider provider)
    {
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>().CurrentValue;

        return new ProcessAuthenticationContext(new OpenIddictClientTransaction
        {
            CancellationToken = CancellationToken.None,
            Configuration = new OpenIddictConfiguration(),
            Options = options,
            Registration = options.Registrations[0],
            Request = new OpenIddictRequest(),
            ServiceProvider = provider
        })
        {
            AuthenticationRequestId = "F6B3B1E4",
            GrantType = GrantTypes.Ciba
        };
    }

    private static ProcessAuthenticationContext CreatePushedTokensContext(
        IServiceProvider provider, string? identifier, bool hash, bool refresh)
    {
        var context = CreateAuthenticationContext(provider);
        context.BackchannelAccessToken = "access_token";
        context.BackchannelTokenDeliveryMode = BackchannelTokenDeliveryModes.Push;

        var principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
            .SetClaim(Claims.Private.SigningAlgorithm, "RS256");

        if (!string.IsNullOrEmpty(identifier))
        {
            principal.SetClaim(Claims.AuthReqId, identifier);
        }

        if (hash)
        {
            principal.SetClaim(Claims.AccessTokenHash, ComputeHash("access_token"));
        }

        if (refresh)
        {
            context.RefreshToken = "refresh_token";
            principal.SetClaim(Claims.RefreshTokenHash, ComputeHash("refresh_token"));
        }

        context.BackchannelIdentityTokenPrincipal = principal;

        return context;

        static string ComputeHash(string token)
        {
            var digest = SHA256.HashData(Encoding.ASCII.GetBytes(token));
            return Base64Url.EncodeToString(digest.AsSpan(0, digest.Length / 2));
        }
    }

    private static readonly RsaSecurityKey ServerSigningKey = new(RSA.Create(keySizeInBits: 2048))
    {
        KeyId = "server_signing_key"
    };

    private static ServiceProvider CreateProvider(Action<OpenIddictClientBuilder>? configuration = null)
    {
        var services = new ServiceCollection();

        services.AddOpenIddict()
            .AddClient(options =>
            {
                options.AllowClientInitiatedBackchannelAuthenticationFlow();

                options.AddEphemeralEncryptionKey()
                       .AddEphemeralSigningKey();

                options.AddRegistration(new OpenIddictClientRegistration
                {
                    ClientId = "Fabrikam",
                    Configuration = new OpenIddictConfiguration
                    {
                        Issuer = new Uri("https://www.contoso.com/", UriKind.Absolute),
                        GrantTypesSupported = { GrantTypes.Ciba },
                        SigningKeys = { ServerSigningKey },
                        TokenEndpoint = new Uri("https://www.contoso.com/connect/token", UriKind.Absolute)
                    },
                    Issuer = new Uri("https://www.contoso.com/", UriKind.Absolute)
                });

                configuration?.Invoke(options);
            });

        return services.BuildServiceProvider();
    }

    private static ProcessChallengeContext CreateChallengeContext(IServiceProvider provider)
    {
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>().CurrentValue;

        return new ProcessChallengeContext(new OpenIddictClientTransaction
        {
            CancellationToken = CancellationToken.None,
            Configuration = new OpenIddictConfiguration(),
            Options = options,
            Registration = options.Registrations[0],
            Request = new OpenIddictRequest(),
            ServiceProvider = provider
        })
        {
            ClientId = "Fabrikam",
            GrantType = GrantTypes.Ciba,
            Principal = new ClaimsPrincipal(new ClaimsIdentity())
        };
    }

    private static HandleBackchannelAuthenticationResponseContext CreateResponseContext(
        IServiceProvider provider, OpenIddictResponse response)
    {
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>().CurrentValue;

        return new HandleBackchannelAuthenticationResponseContext(new OpenIddictClientTransaction
        {
            CancellationToken = CancellationToken.None,
            Configuration = new OpenIddictConfiguration(),
            Options = options,
            Registration = options.Registrations[0],
            ServiceProvider = provider
        })
        {
            Request = new OpenIddictRequest(),
            Response = response
        };
    }
}
