using System.Collections.Immutable;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictExceptions;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Server.Tests;

public class OpenIddictServerServiceTests
{
    private const string Identifier = "3E228451-1555-46F7-A471-951EFBA23A56";

    [Fact]
    public async Task ListPendingBackchannelAuthenticationRequestsAsync_ReturnsPendingRequests()
    {
        // Arrange
        var token = new object();
        var (provider, _) = await CreateProviderAsync(token, Statuses.Inactive);
        var service = provider.GetRequiredService<OpenIddictServerService>();

        // Act
        var requests = new List<OpenIddictServerBackchannelAuthenticationRequest>();
        await foreach (var request in service.ListPendingBackchannelAuthenticationRequestsAsync("Bob"))
        {
            requests.Add(request);
        }

        // Assert
        var result = Assert.Single(requests);
        Assert.Equal(Identifier, result.Identifier);
        Assert.Equal("Fabrikam", result.ClientId);
        Assert.Equal("W4SCT", result.BindingMessage);
        Assert.Equal("Bob", result.Subject);
        Assert.Equal([Scopes.OpenId, Scopes.Profile], result.Scopes.ToArray());
    }

    [Theory]
    [InlineData(Statuses.Valid)]
    [InlineData(Statuses.Rejected)]
    [InlineData(Statuses.Redeemed)]
    public async Task GetPendingBackchannelAuthenticationRequestAsync_ReturnsNullForNonPendingRequests(string status)
    {
        // Arrange
        var token = new object();
        var (provider, _) = await CreateProviderAsync(token, status);
        var service = provider.GetRequiredService<OpenIddictServerService>();

        // Act and assert
        Assert.Null(await service.GetPendingBackchannelAuthenticationRequestAsync(Identifier));
    }

    [Fact]
    public async Task ApproveBackchannelAuthenticationRequestAsync_UpdatesTokenEntry()
    {
        // Arrange
        var token = new object();
        var (provider, manager) = await CreateProviderAsync(token, Statuses.Inactive);
        var service = provider.GetRequiredService<OpenIddictServerService>();

        OpenIddictTokenDescriptor? descriptor = null;
        manager.Setup(manager => manager.UpdateAsync(token, It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
            .Callback((object _, OpenIddictTokenDescriptor value, CancellationToken _) => descriptor = value)
            .Returns(ValueTask.CompletedTask);

        var principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
            .SetClaim(Claims.Subject, "Bob")
            .SetClaim(Claims.Name, "Bob le Bricoleur");

        // Act
        var result = await service.ApproveBackchannelAuthenticationRequestAsync(Identifier, principal);

        // Assert
        Assert.True(result);
        Assert.NotNull(descriptor);
        Assert.Equal(Statuses.Valid, descriptor.Status);
        Assert.Equal("Bob", descriptor.Subject);
        Assert.NotNull(descriptor.Payload);

        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;
        var parameters = options.TokenValidationParameters.Clone();
        parameters.ValidIssuer = "https://www.contoso.com/";

        var validation = await options.JsonWebTokenHandler.ValidateTokenAsync(descriptor.Payload, parameters);
        Assert.True(validation.IsValid, validation.Exception?.Message);

        var approved = new ClaimsPrincipal(validation.ClaimsIdentity);
        Assert.Equal("Bob le Bricoleur", approved.GetClaim(Claims.Name));
        Assert.Equal(Identifier, approved.GetTokenId());
        Assert.Equal("W4SCT", approved.GetClaim(Claims.Private.BindingMessage));
        Assert.True(approved.HasPresenter("Fabrikam"));
    }

    [Fact]
    public async Task ApproveBackchannelAuthenticationRequestAsync_ThrowsAnExceptionForDifferentSubject()
    {
        // Arrange
        var token = new object();
        var (provider, _) = await CreateProviderAsync(token, Statuses.Inactive);
        var service = provider.GetRequiredService<OpenIddictServerService>();

        var principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer")).SetClaim(Claims.Subject, "Alice");

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await service.ApproveBackchannelAuthenticationRequestAsync(Identifier, principal));

        Assert.Equal(SR.GetResourceString(SR.ID0534), exception.Message);
    }

    [Fact]
    public async Task ApproveBackchannelAuthenticationRequestAsync_ReturnsFalseForConcurrentUpdates()
    {
        // Arrange
        var token = new object();
        var (provider, manager) = await CreateProviderAsync(token, Statuses.Inactive);
        var service = provider.GetRequiredService<OpenIddictServerService>();

        manager.Setup(manager => manager.UpdateAsync(token, It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
            .Returns(new ValueTask(Task.FromException(new ConcurrencyException("concurrency"))));

        // Act and assert
        Assert.False(await service.ApproveBackchannelAuthenticationRequestAsync(Identifier));
    }

    [Fact]
    public async Task ApproveBackchannelAuthenticationRequestAsync_ReturnsFalseForNonPendingRequests()
    {
        // Arrange
        var token = new object();
        var (provider, manager) = await CreateProviderAsync(token, Statuses.Valid);
        var service = provider.GetRequiredService<OpenIddictServerService>();

        // Act and assert
        Assert.False(await service.ApproveBackchannelAuthenticationRequestAsync(Identifier));

        manager.Verify(manager => manager.UpdateAsync(token, It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task RejectBackchannelAuthenticationRequestAsync_RejectsTokenEntry()
    {
        // Arrange
        var token = new object();
        var (provider, manager) = await CreateProviderAsync(token, Statuses.Inactive);
        var service = provider.GetRequiredService<OpenIddictServerService>();

        manager.Setup(manager => manager.TryRejectAsync(token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        // Act and assert
        Assert.True(await service.RejectBackchannelAuthenticationRequestAsync(Identifier));

        manager.Verify(manager => manager.TryRejectAsync(token, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ApproveOrRejectBackchannelAuthenticationRequestAsync_SendsPingNotification(bool approve)
    {
        // Arrange
        var token = new object();
        var notifications = new List<SendBackchannelNotificationContext>();

        var (provider, manager) = await CreateProviderAsync(token, Statuses.Inactive, BackchannelTokenDeliveryModes.Ping, notifications);
        var service = provider.GetRequiredService<OpenIddictServerService>();

        manager.Setup(manager => manager.TryRejectAsync(token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        // Act
        var result = approve
            ? await service.ApproveBackchannelAuthenticationRequestAsync(Identifier)
            : await service.RejectBackchannelAuthenticationRequestAsync(Identifier);

        // Assert
        Assert.True(result);

        var notification = Assert.Single(notifications);
        Assert.Equal("Fabrikam", notification.ClientId);
        Assert.Equal(new Uri("https://fabrikam.com/ciba/notify"), notification.ClientNotificationEndpoint);
        Assert.Equal("8C3C7A6D-notification-token", notification.ClientNotificationToken);
        Assert.Equal(BackchannelTokenDeliveryModes.Ping, notification.TokenDeliveryMode);
        Assert.Equal("F6B3B1E4-auth-req-id", notification.Notification.AuthReqId);
        Assert.Single(notification.Notification.GetParameters());
    }

    [Fact]
    public async Task RejectBackchannelAuthenticationRequestAsync_SendsPushErrorNotification()
    {
        // Arrange
        var token = new object();
        var notifications = new List<SendBackchannelNotificationContext>();

        var (provider, manager) = await CreateProviderAsync(token, Statuses.Inactive, BackchannelTokenDeliveryModes.Push, notifications);
        var service = provider.GetRequiredService<OpenIddictServerService>();

        manager.Setup(manager => manager.TryRejectAsync(token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        // Act
        Assert.True(await service.RejectBackchannelAuthenticationRequestAsync(Identifier));

        // Assert
        var notification = Assert.Single(notifications);
        Assert.Equal(BackchannelTokenDeliveryModes.Push, notification.TokenDeliveryMode);
        Assert.Equal("F6B3B1E4-auth-req-id", notification.Notification.AuthReqId);
        Assert.Equal(Errors.AccessDenied, notification.Notification.Error);
        Assert.Null(notification.Notification.AccessToken);
    }

    [Fact]
    public async Task ApproveBackchannelAuthenticationRequestAsync_SendsPushNotificationWithTokens()
    {
        // Arrange
        var token = new object();
        var notifications = new List<SendBackchannelNotificationContext>();

        var (provider, manager) = await CreateProviderAsync(token, Statuses.Inactive, BackchannelTokenDeliveryModes.Push, notifications);
        var service = provider.GetRequiredService<OpenIddictServerService>();

        manager.Setup(manager => manager.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new object());

        manager.Setup(manager => manager.GetIdAsync(It.Is<object>(value => value != token), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Guid.NewGuid().ToString());

        manager.Setup(manager => manager.TryRedeemAsync(token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        // Act
        Assert.True(await service.ApproveBackchannelAuthenticationRequestAsync(Identifier));

        // Assert
        var notification = Assert.Single(notifications);
        Assert.Equal(BackchannelTokenDeliveryModes.Push, notification.TokenDeliveryMode);
        Assert.Null(notification.Notification.Error);
        Assert.Equal("F6B3B1E4-auth-req-id", notification.Notification.AuthReqId);
        Assert.NotNull(notification.Notification.AccessToken);
        Assert.Equal(TokenTypes.Bearer, notification.Notification.TokenType);
        Assert.NotNull(notification.Notification.IdToken);

        // The identity token MUST contain the authentication request identifier and the at_hash claim.
        var identity = new JsonWebToken(notification.Notification.IdToken);
        Assert.Equal("F6B3B1E4-auth-req-id", identity.GetPayloadValue<string>(Claims.AuthReqId));
        Assert.False(string.IsNullOrEmpty(identity.GetPayloadValue<string>(Claims.AccessTokenHash)));
        Assert.Equal("Bob", identity.Subject);

        // The authentication request identifier MUST be marked as redeemed.
        manager.Verify(manager => manager.TryRedeemAsync(token, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ApproveBackchannelAuthenticationRequestAsync_RetriesFailedNotifications()
    {
        // Arrange
        var token = new object();
        var notifications = new List<SendBackchannelNotificationContext>();

        var (provider, _) = await CreateProviderAsync(token, Statuses.Inactive, BackchannelTokenDeliveryModes.Ping, notifications,
            configuration: options => options.SetBackchannelNotificationRetryPolicy(2, TimeSpan.Zero),
            succeed: false);

        var service = provider.GetRequiredService<OpenIddictServerService>();

        // Act
        Assert.True(await service.ApproveBackchannelAuthenticationRequestAsync(Identifier));

        // Assert
        Assert.Equal([1, 2, 3], notifications.Select(notification => notification.Attempt));
    }

    [Fact]
    public async Task ApproveBackchannelAuthenticationRequestAsync_SendsRefreshTokenHashInPushedIdentityToken()
    {
        // Arrange
        var token = new object();
        var notifications = new List<SendBackchannelNotificationContext>();

        var (provider, manager) = await CreateProviderAsync(token, Statuses.Inactive, BackchannelTokenDeliveryModes.Push, notifications,
            configuration: options => options.AllowRefreshTokenFlow(), scopes: [Scopes.OpenId, Scopes.OfflineAccess]);
        var service = provider.GetRequiredService<OpenIddictServerService>();

        manager.Setup(manager => manager.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new object());

        manager.Setup(manager => manager.GetIdAsync(It.Is<object>(value => value != token), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Guid.NewGuid().ToString());

        manager.Setup(manager => manager.TryRedeemAsync(token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        // Act
        Assert.True(await service.ApproveBackchannelAuthenticationRequestAsync(Identifier));

        // Assert
        var notification = Assert.Single(notifications);
        Assert.NotNull(notification.Notification.RefreshToken);

        // When a refresh token is pushed, the identity token MUST contain its hash (left-most half of its SHA-256 digest).
        var identity = new JsonWebToken(notification.Notification.IdToken);
        using var algorithm = SHA256.Create();
        var digest = algorithm.ComputeHash(Encoding.ASCII.GetBytes(notification.Notification.RefreshToken));
        Assert.Equal(Base64UrlEncoder.Encode(digest.AsSpan(0, digest.Length / 2).ToArray()),
            identity.GetPayloadValue<string>(Claims.RefreshTokenHash));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ApproveOrRejectBackchannelAuthenticationRequestAsync_DoesNotThrowWhenNotificationTransportFails(bool approve)
    {
        // Arrange
        var token = new object();

        var (provider, manager) = await CreateProviderAsync(token, Statuses.Inactive, BackchannelTokenDeliveryModes.Ping, notifications: null,
            configuration: options => options.AddEventHandler<SendBackchannelNotificationContext>(builder =>
                builder.UseInlineHandler(context => throw new HttpRequestException("The endpoint is unavailable."))));

        var service = provider.GetRequiredService<OpenIddictServerService>();

        manager.Setup(manager => manager.TryRejectAsync(token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        // Act
        var result = approve
            ? await service.ApproveBackchannelAuthenticationRequestAsync(Identifier)
            : await service.RejectBackchannelAuthenticationRequestAsync(Identifier);

        // Assert: the status change was persisted, so the operation must be reported as successful.
        Assert.True(result);

        if (approve)
        {
            manager.Verify(manager => manager.UpdateAsync(token, It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()), Times.Once());
        }

        else
        {
            manager.Verify(manager => manager.TryRejectAsync(token, It.IsAny<CancellationToken>()), Times.Once());
        }
    }

    [Fact]
    public async Task ApproveBackchannelAuthenticationRequestAsync_DoesNotThrowWhenCancelledDuringRetryDelay()
    {
        // Arrange
        var token = new object();
        var notifications = new List<SendBackchannelNotificationContext>();
        using var source = new CancellationTokenSource();

        var (provider, _) = await CreateProviderAsync(token, Statuses.Inactive, BackchannelTokenDeliveryModes.Ping, notifications,
            configuration: options => options.SetBackchannelNotificationRetryPolicy(2, TimeSpan.FromMinutes(5))
                .AddEventHandler<SendBackchannelNotificationContext>(builder => builder.UseInlineHandler(context =>
                {
                    source.Cancel();
                    return ValueTask.CompletedTask;
                })),
            succeed: false);

        var service = provider.GetRequiredService<OpenIddictServerService>();

        // Act and assert
        Assert.True(await service.ApproveBackchannelAuthenticationRequestAsync(Identifier, cancellationToken: source.Token));
    }

    private static async Task<(ServiceProvider Provider, Mock<IOpenIddictTokenManager> Manager)> CreateProviderAsync(object token, string status)
        => await CreateProviderAsync(token, status, mode: null, notifications: null);

    private static async Task<(ServiceProvider Provider, Mock<IOpenIddictTokenManager> Manager)> CreateProviderAsync(
        object token, string status, string? mode, List<SendBackchannelNotificationContext>? notifications,
        Action<OpenIddictServerBuilder>? configuration = null, bool succeed = true, string[]? scopes = null)
    {
        var manager = new Mock<IOpenIddictTokenManager>();

        var services = new ServiceCollection();
        services.AddSingleton(manager.Object);

        var application = new object();
        var applications = new Mock<IOpenIddictApplicationManager>();

        applications.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
            .ReturnsAsync(application);

        applications.Setup(manager => manager.GetSettingsAsync(application, It.IsAny<CancellationToken>()))
            .ReturnsAsync(ImmutableDictionary.CreateRange(StringComparer.Ordinal, new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [Settings.BackchannelAuthentication.ClientNotificationEndpoint] = "https://fabrikam.com/ciba/notify",
                [Settings.BackchannelAuthentication.TokenDeliveryMode] = mode ?? BackchannelTokenDeliveryModes.Poll
            }));

        services.AddSingleton(applications.Object);

        services.AddOpenIddict()
            .AddServer(options =>
            {
                options.SetTokenEndpointUris("connect/token")
                       .SetBackchannelAuthenticationEndpointUris("connect/ciba")
                       .AllowClientInitiatedBackchannelAuthenticationFlow()
                       .SetIssuer(new Uri("https://www.contoso.com/", UriKind.Absolute));

                options.AddEphemeralEncryptionKey()
                       .AddEphemeralSigningKey();

                options.DisableAuthorizationStorage();

                if (mode is BackchannelTokenDeliveryModes.Ping or BackchannelTokenDeliveryModes.Push)
                {
                    options.AllowBackchannelPingTokenDeliveryMode()
                           .AllowBackchannelPushTokenDeliveryMode();
                }

                if (notifications is not null)
                {
                    options.AddEventHandler<SendBackchannelNotificationContext>(builder => builder.UseInlineHandler(context =>
                    {
                        notifications.Add(context);

                        if (succeed)
                        {
                            context.HandleRequest();
                        }

                        else
                        {
                            context.Reject(Errors.ServerError, "The endpoint is unavailable.");
                        }

                        return ValueTask.CompletedTask;
                    }));
                }

                configuration?.Invoke(options);
            });

        var provider = services.BuildServiceProvider();

        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;

        // Generate the payload of the pending authentication request using the server token generation pipeline.
        var context = new GenerateTokenContext(new OpenIddictServerTransaction
        {
            CancellationToken = CancellationToken.None,
            Options = options,
            ServiceProvider = provider
        })
        {
            ClientId = "Fabrikam",
            CreateTokenEntry = false,
            IsReferenceToken = false,
            PersistTokenPayload = false,
            Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                .SetClaim(Claims.Subject, "Bob")
                .SetClaim(Claims.Private.BindingMessage, "W4SCT")
                .SetClaim(Claims.Private.Issuer, "https://www.contoso.com/")
                .SetPresenters("Fabrikam")
                .SetScopes(scopes ?? [Scopes.OpenId, Scopes.Profile])
                .SetTokenId(Identifier),
            TokenFormat = TokenFormats.Private.JsonWebToken,
            TokenType = TokenTypeIdentifiers.Private.AuthenticationRequestId
        };

        await provider.GetRequiredService<IOpenIddictServerDispatcher>().DispatchAsync(context);
        Assert.False(string.IsNullOrEmpty(context.Token));
        Assert.True(new JsonWebTokenHandler().CanReadToken(context.Token));

        manager.Setup(manager => manager.FindByIdAsync(Identifier, It.IsAny<CancellationToken>()))
            .ReturnsAsync(token);

        manager.Setup(manager => manager.FindBySubjectAsync("Bob", It.IsAny<CancellationToken>()))
            .Returns(ListAsync());

        manager.Setup(manager => manager.GetIdAsync(token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Identifier);

        manager.Setup(manager => manager.HasTypeAsync(token, TokenTypeIdentifiers.Private.AuthenticationRequestId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        manager.Setup(manager => manager.HasStatusAsync(token, It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((object _, string value, CancellationToken _) => string.Equals(value, status, StringComparison.Ordinal));

        manager.Setup(manager => manager.GetExpirationDateAsync(token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(DateTimeOffset.UtcNow + TimeSpan.FromMinutes(5));

        manager.Setup(manager => manager.GetCreationDateAsync(token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(DateTimeOffset.UtcNow);

        manager.Setup(manager => manager.GetPayloadAsync(token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(context.Token);

        var properties = ImmutableDictionary.CreateBuilder<string, JsonElement>(StringComparer.Ordinal);

        if (mode is BackchannelTokenDeliveryModes.Ping or BackchannelTokenDeliveryModes.Push)
        {
            // Note: the notification details are stored as an encrypted token only readable by the server.
            var payload = options.JsonWebTokenHandler.CreateToken(new SecurityTokenDescriptor
            {
                Claims = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    [Claims.AuthReqId] = "F6B3B1E4-auth-req-id",
                    [Claims.Private.ClientNotificationToken] = "8C3C7A6D-notification-token",
                    [Claims.Private.TokenDeliveryMode] = mode
                },
                EncryptingCredentials = options.EncryptionCredentials[0],
                SigningCredentials = options.SigningCredentials[0],
                TokenType = JsonWebTokenTypes.Private.BackchannelNotification
            });

            properties.Add(Properties.BackchannelNotification, JsonSerializer.SerializeToElement(payload));
        }

        manager.Setup(manager => manager.GetPropertiesAsync(token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(properties.ToImmutable());

        return (provider, manager);

        async IAsyncEnumerable<object> ListAsync()
        {
            await Task.Yield();
            yield return token;
        }
    }
}
