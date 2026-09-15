using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using static OpenIddict.Client.AspNetCore.Bff.OpenIddictClientAspNetCoreBffModels;

namespace OpenIddict.Client.AspNetCore.Bff.Tests;

public class OpenIddictClientAspNetCoreBffDistributedCacheTests
{
    [Fact]
    public async Task ValidatePrincipal_RefreshResultIsSharedWithOtherInstances()
    {
        // Arrange
        var (cache, protection) = CreateSharedServices();

        await using var first = await CreateHostAsync(cache, protection);
        await using var second = await CreateHostAsync(cache, protection);

        var cookie = await first.SignInAsync(expiration: DateTimeOffset.UtcNow.AddSeconds(-1));

        // Act
        using var refreshed = await first.SendAsync(HttpMethod.Get, "/test/token", cookie);
        using var shared = await second.SendAsync(HttpMethod.Get, "/test/token", cookie);

        // Assert
        Assert.Equal("new_access_token", await refreshed.Content.ReadAsStringAsync());
        Assert.Equal("new_access_token", await shared.Content.ReadAsStringAsync());
        Assert.Single(first.Endpoint.Requests);
        Assert.Empty(second.Endpoint.Requests);
    }

    [Fact]
    public async Task ValidatePrincipal_PendingRefreshOnAnotherInstanceIsAwaited()
    {
        // Arrange
        var (cache, protection) = CreateSharedServices();
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        await using var first = await CreateHostAsync(cache, protection);
        await using var second = await CreateHostAsync(cache, protection);

        first.Endpoint.Handler = async request =>
        {
            await release.Task;

            return new OpenIddictResponse
            {
                AccessToken = "first_access_token",
                ExpiresIn = 3600,
                RefreshToken = "first_refresh_token",
                TokenType = TokenTypes.Bearer
            };
        };

        var cookie = await first.SignInAsync(expiration: DateTimeOffset.UtcNow.AddSeconds(-1));

        // Act
        var pending = first.SendAsync(HttpMethod.Get, "/test/token", cookie);
        await WaitUntilAsync(() => !first.Endpoint.Requests.IsEmpty);

        var waiting = second.SendAsync(HttpMethod.Get, "/test/token", cookie);
        await Task.Delay(300);

        Assert.False(waiting.IsCompleted);
        release.SetResult();

        using var response = await pending;
        using var other = await waiting;

        // Assert
        Assert.Equal("first_access_token", await response.Content.ReadAsStringAsync());
        Assert.Equal("first_access_token", await other.Content.ReadAsStringAsync());
        Assert.Single(first.Endpoint.Requests);
        Assert.Empty(second.Endpoint.Requests);
    }

    [Fact]
    public async Task ValidatePrincipal_RefreshResultIsNotSharedWhenDistributedCachingIsDisabled()
    {
        // Arrange
        var (cache, protection) = CreateSharedServices();

        await using var first = await CreateHostAsync(cache, protection, distributed: false);
        await using var second = await CreateHostAsync(cache, protection, distributed: false);

        var cookie = await first.SignInAsync(expiration: DateTimeOffset.UtcNow.AddSeconds(-1));

        // Act
        using var refreshed = await first.SendAsync(HttpMethod.Get, "/test/token", cookie);
        using var other = await second.SendAsync(HttpMethod.Get, "/test/token", cookie);

        // Assert
        Assert.Single(first.Endpoint.Requests);
        Assert.Single(second.Endpoint.Requests);
    }

    [Fact]
    public async Task ValidatePrincipal_TicketIsKeptWhenNoDistributedCacheIsRegistered()
    {
        // Arrange
        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync(
            bff: options => options.EnableDistributedCaching());

        var cookie = await host.SignInAsync(expiration: DateTimeOffset.UtcNow.AddSeconds(-1));

        // Act
        using var response = await host.SendAsync(HttpMethod.Get, "/test/token", cookie);

        // Assert
        Assert.Equal("old_access_token", await response.Content.ReadAsStringAsync());
        Assert.Empty(host.Endpoint.Requests);
    }

    [Fact]
    public async Task ValidatePrincipal_RefreshResultIsProtectedInTheDistributedCache()
    {
        // Arrange
        var (cache, protection) = CreateSharedServices();

        await using var host = await CreateHostAsync(cache, protection);
        var cookie = await host.SignInAsync(expiration: DateTimeOffset.UtcNow.AddSeconds(-1), refreshToken: "refresh_token");

        // Act
        using var response = await host.SendAsync(HttpMethod.Get, "/test/token", cookie);

        // Assert
        var key = OpenIddictClientAspNetCoreBffConstants.CacheKeys.RefreshResult +
            Base64UrlEncoder.Encode(SHA256.HashData("refresh_token"u8.ToArray()));

        var payload = await cache.GetAsync(key);
        Assert.NotNull(payload);
        Assert.DoesNotContain("new_access_token", System.Text.Encoding.UTF8.GetString(payload), StringComparison.Ordinal);

        var protector = protection.CreateProtector(OpenIddictClientAspNetCoreBffConstants.Purposes.RefreshResult);
        using var document = JsonDocument.Parse(protector.Unprotect(payload));
        Assert.Equal("new_access_token", document.RootElement.GetProperty("AccessToken").GetString());
    }

    [Fact]
    public async Task BackchannelLogoutEndpoint_TokenReceivedByAnotherInstanceIsRejected()
    {
        // Arrange
        var (cache, protection) = CreateSharedServices();

        await using var first = await CreateHostAsync(cache, protection);
        await using var second = await CreateHostAsync(cache, protection, key: first.SigningKey);

        var token = CreateLogoutToken(first.SigningKey);

        // Act
        using var accepted = await SendLogoutTokenAsync(first, token);
        using var replayed = await SendLogoutTokenAsync(second, token);

        // Assert
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, replayed.StatusCode);
    }

    [Fact]
    public async Task BackchannelLogoutEndpoint_TokenReceivedByAnotherInstanceIsRejectedByTheClientStackWhenDistributedCachingIsDisabled()
    {
        // Arrange
        var (cache, protection) = CreateSharedServices();

        await using var first = await CreateHostAsync(cache, protection, distributed: false);
        await using var second = await CreateHostAsync(cache, protection, distributed: false, key: first.SigningKey);

        var token = CreateLogoutToken(first.SigningKey);

        // Act
        using var accepted = await SendLogoutTokenAsync(first, token);
        using var other = await SendLogoutTokenAsync(second, token);

        // Assert
        // Note: the client stack uses the registered distributed cache independently of the BFF options.
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, other.StatusCode);
    }

    [Fact]
    public async Task BackchannelLogoutEndpoint_EncryptedLogoutTokenIsAcceptedOnce()
    {
        // Arrange
        var handler = new RecordingLogoutHandler();

        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync(services: services =>
            services.AddSingleton<IOpenIddictClientAspNetCoreBffBackchannelLogoutHandler>(handler));

        var options = host.Services.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>().CurrentValue;
        var credentials = options.EncryptionCredentials[0];

        var token = CreateLogoutToken(host.SigningKey, new EncryptingCredentials(
            credentials.Key, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes256CbcHmacSha512));

        Assert.Equal(5, token.Split('.').Length);

        // Act
        using var first = await SendLogoutTokenAsync(host, token);
        using var second = await SendLogoutTokenAsync(host, token);

        // Assert
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, second.StatusCode);

        var notification = Assert.Single(handler.Notifications);
        Assert.Equal("session", notification.SessionId);
        Assert.Equal("Contoso", notification.Registration.RegistrationId);
    }

    [Theory]
    [InlineData(SecurityAlgorithms.RsaSsaPssSha256, true)]
    [InlineData(SecurityAlgorithms.RsaSha256, false)]
    public async Task BackchannelLogoutEndpoint_EncryptedLogoutTokenIsValidatedForFapi2Registration(string algorithm, bool valid)
    {
        // Arrange
        var handler = new RecordingLogoutHandler();

        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync(
            client: options => options.EnableDPoPTokenBinding().Configure(options =>
            {
                var registration = options.Registrations[0];
                registration.ClientSecret = null;
                registration.EnableFapi2SecurityProfile = true;
                registration.SigningCredentials.Add(new SigningCredentials(
                    new ECDsaSecurityKey(ECDsa.Create(ECCurve.NamedCurves.nistP256)), SecurityAlgorithms.EcdsaSha256));
            }),
            services: services => services.AddSingleton<IOpenIddictClientAspNetCoreBffBackchannelLogoutHandler>(handler));

        var options = host.Services.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>().CurrentValue;
        Assert.True(options.Registrations[0].EnableFapi2SecurityProfile);

        // Note: the key management and content encryption algorithms must not be
        // restricted by the signing algorithms allowed by the FAPI 2.0 profile.
        var token = CreateLogoutToken(host.SigningKey, new EncryptingCredentials(
            options.EncryptionCredentials[0].Key, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes256CbcHmacSha512), algorithm);

        // Act
        using var response = await SendLogoutTokenAsync(host, token);

        // Assert
        Assert.Equal(valid ? HttpStatusCode.OK : HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(valid ? 1 : 0, handler.Notifications.Count);
    }

    [Fact]
    public async Task BackchannelLogoutEndpoint_EncryptedLogoutTokenUsingUnknownKeyIsRejected()
    {
        // Arrange
        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync();

        var token = CreateLogoutToken(host.SigningKey, new EncryptingCredentials(
            new RsaSecurityKey(RSA.Create(2048)), SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes256CbcHmacSha512));

        // Act
        using var response = await SendLogoutTokenAsync(host, token);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task BackchannelLogoutEndpoint_EncryptedUnsignedLogoutTokenIsRejected()
    {
        // Arrange
        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync();

        var options = host.Services.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>().CurrentValue;
        var token = CreateLogoutToken(signingKey: null, new EncryptingCredentials(
            options.EncryptionCredentials[0].Key, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes256CbcHmacSha512));

        // Act
        using var response = await SendLogoutTokenAsync(host, token);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public void Validate_NonPositiveDistributedTokenRefreshLockTimeoutIsRejected()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddOptions();
        services.AddOpenIddict().AddClient().UseBff().EnableDistributedCaching(TimeSpan.Zero);

        using var provider = services.BuildServiceProvider();

        // Act and assert
        var exception = Assert.Throws<OptionsValidationException>(() =>
            provider.GetRequiredService<IOptions<OpenIddictClientAspNetCoreBffOptions>>().Value);

        Assert.Contains(SR.GetResourceString(SR.ID0987), exception.Failures, StringComparer.Ordinal);
    }

    private static (IDistributedCache Cache, IDataProtectionProvider Protection) CreateSharedServices()
        => (new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions())), new EphemeralDataProtectionProvider());

    private static async Task<OpenIddictClientAspNetCoreBffTestHost> CreateHostAsync(
        IDistributedCache cache, IDataProtectionProvider protection, bool distributed = true, SecurityKey? key = null)
    {
        return await OpenIddictClientAspNetCoreBffTestHost.CreateAsync(
            bff: options =>
            {
                if (distributed)
                {
                    options.EnableDistributedCaching();
                }
            },
            services: services =>
            {
                services.AddSingleton(cache);
                services.AddSingleton(protection);
            },
            signingKey: key);
    }

    private static string CreateLogoutToken(SecurityKey? signingKey,
        EncryptingCredentials? encryptingCredentials = null, string algorithm = SecurityAlgorithms.RsaSha256)
    {
        var now = DateTime.UtcNow;

        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Audience = "Fabrikam",
            Claims = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [Claims.JwtId] = Guid.NewGuid().ToString(),
                [Claims.SessionId] = "session",
                [Claims.Events] = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    [OpenIddictClientAspNetCoreBffConstants.Events.BackchannelLogout] = new Dictionary<string, object>(StringComparer.Ordinal)
                }
            },
            EncryptingCredentials = encryptingCredentials,
            Expires = now.AddMinutes(2),
            IssuedAt = now,
            NotBefore = now,
            Issuer = OpenIddictClientAspNetCoreBffTestHost.Issuer.AbsoluteUri,
            SigningCredentials = signingKey is null ? null : new SigningCredentials(signingKey, algorithm),
            TokenType = JsonWebTokenTypes.LogoutToken
        });
    }

    private static Task<HttpResponseMessage> SendLogoutTokenAsync(OpenIddictClientAspNetCoreBffTestHost host, string token)
        => host.Client.PostAsync("/bff/backchannel-logout", new FormUrlEncodedContent(
            [new KeyValuePair<string, string>(Parameters.LogoutToken, token)]));

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        for (var attempt = 0; attempt < 500 && !condition(); attempt++)
        {
            await Task.Delay(10);
        }

        Assert.True(condition());
    }

    private sealed class RecordingLogoutHandler : IOpenIddictClientAspNetCoreBffBackchannelLogoutHandler
    {
        public List<BackchannelLogoutNotification> Notifications { get; } = [];

        public ValueTask HandleAsync(BackchannelLogoutNotification notification, CancellationToken cancellationToken)
        {
            Notifications.Add(notification);
            return ValueTask.CompletedTask;
        }
    }
}
