using System.Buffers.Text;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
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

    private static ServiceProvider CreateProvider()
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
                        Issuer = new Uri("https://www.contoso.com/", UriKind.Absolute)
                    },
                    Issuer = new Uri("https://www.contoso.com/", UriKind.Absolute)
                });
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
