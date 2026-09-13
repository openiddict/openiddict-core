using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using static OpenIddict.Client.AspNetCore.Bff.OpenIddictClientAspNetCoreBffModels;

namespace OpenIddict.Client.AspNetCore.Bff.Tests;

public class OpenIddictClientAspNetCoreBffTokenRefreshTests
{
    [Fact]
    public async Task ValidatePrincipal_ExpiringAccessTokenIsRefreshedAndTicketIsRenewed()
    {
        // Arrange
        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync();
        var cookie = await host.SignInAsync(expiration: DateTimeOffset.UtcNow.AddSeconds(30));

        // Act
        using var response = await host.SendAsync(HttpMethod.Get, "/test/token", cookie);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("new_access_token", await response.Content.ReadAsStringAsync());

        var request = Assert.Single(host.Endpoint.Requests);
        Assert.Equal(GrantTypes.RefreshToken, request.GrantType);
        Assert.Equal("old_refresh_token", request.RefreshToken);

        // The renewed cookie must contain the new access and refresh tokens and must not trigger another refresh.
        var renewed = OpenIddictClientAspNetCoreBffTestHost.GetCookie(response);
        Assert.NotNull(renewed);

        using var token = await host.SendAsync(HttpMethod.Get, "/test/token", renewed);
        using var refresh = await host.SendAsync(HttpMethod.Get, "/test/refresh_token", renewed);

        Assert.Equal("new_access_token", await token.Content.ReadAsStringAsync());
        Assert.Equal("new_refresh_token", await refresh.Content.ReadAsStringAsync());
        Assert.Single(host.Endpoint.Requests);
    }

    [Fact]
    public async Task ValidatePrincipal_MissingAccessTokenIsRefreshed()
    {
        // Arrange
        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync();
        var cookie = await host.SignInAsync(accessToken: null);

        // Act
        using var response = await host.SendAsync(HttpMethod.Get, "/test/token", cookie);

        // Assert
        Assert.Equal("new_access_token", await response.Content.ReadAsStringAsync());
        Assert.Single(host.Endpoint.Requests);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ValidatePrincipal_ValidAccessTokenIsNotRefreshed(bool expiration)
    {
        // Arrange
        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync();
        var cookie = await host.SignInAsync(expiration: expiration ? DateTimeOffset.UtcNow.AddHours(1) : null);

        // Act
        using var response = await host.SendAsync(HttpMethod.Get, "/test/token", cookie);

        // Assert
        Assert.Equal("old_access_token", await response.Content.ReadAsStringAsync());
        Assert.Null(OpenIddictClientAspNetCoreBffTestHost.GetCookie(response));
        Assert.Empty(host.Endpoint.Requests);
    }

    [Fact]
    public async Task ValidatePrincipal_AccessTokenIsNotRefreshedWithoutRefreshToken()
    {
        // Arrange
        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync();
        var cookie = await host.SignInAsync(expiration: DateTimeOffset.UtcNow.AddMinutes(-5), refreshToken: null);

        // Act
        using var response = await host.SendAsync(HttpMethod.Get, "/test/token", cookie);

        // Assert
        Assert.Equal("old_access_token", await response.Content.ReadAsStringAsync());
        Assert.Empty(host.Endpoint.Requests);
    }

    [Fact]
    public async Task ValidatePrincipal_AccessTokenIsNotRefreshedWhenAutomaticRefreshIsDisabled()
    {
        // Arrange
        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync(
            bff: options => options.DisableAutomaticTokenRefresh());

        var cookie = await host.SignInAsync(expiration: DateTimeOffset.UtcNow.AddMinutes(-5));

        // Act
        using var response = await host.SendAsync(HttpMethod.Get, "/test/token", cookie);

        // Assert
        Assert.Equal("old_access_token", await response.Content.ReadAsStringAsync());
        Assert.Empty(host.Endpoint.Requests);
    }

    [Fact]
    public async Task ValidatePrincipal_RefreshMarginIsHonored()
    {
        // Arrange
        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync(
            bff: options => options.SetAccessTokenRefreshMargin(TimeSpan.FromMinutes(10)));

        var cookie = await host.SignInAsync(expiration: DateTimeOffset.UtcNow.AddMinutes(5));

        // Act
        using var response = await host.SendAsync(HttpMethod.Get, "/test/token", cookie);

        // Assert
        Assert.Equal("new_access_token", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task ValidatePrincipal_ConcurrentRequestsShareASingleRefreshTokenRequest()
    {
        // Arrange
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync();
        host.Endpoint.Handler = async request =>
        {
            await release.Task;

            return new OpenIddictResponse
            {
                AccessToken = "new_access_token",
                ExpiresIn = 3600,
                RefreshToken = "new_refresh_token",
                TokenType = TokenTypes.Bearer
            };
        };

        var cookie = await host.SignInAsync(expiration: DateTimeOffset.UtcNow.AddSeconds(-1));

        // Act
        var tasks = Enumerable.Range(0, 8).Select(_ => host.SendAsync(HttpMethod.Get, "/test/token", cookie)).ToList();

        await WaitUntilAsync(() => !host.Endpoint.Requests.IsEmpty);
        await Task.Delay(100);
        release.SetResult();

        var responses = await Task.WhenAll(tasks);

        // Assert
        Assert.Single(host.Endpoint.Requests);

        foreach (var response in responses)
        {
            Assert.Equal("new_access_token", await response.Content.ReadAsStringAsync());
            response.Dispose();
        }

        // Requests still carrying the old cookie shortly after the refresh reuse the retained result.
        using var late = await host.SendAsync(HttpMethod.Get, "/test/token", cookie);
        Assert.Equal("new_access_token", await late.Content.ReadAsStringAsync());
        Assert.Single(host.Endpoint.Requests);
    }

    [Fact]
    public async Task ValidatePrincipal_RejectedRefreshTokenSignsOutTheUser()
    {
        // Arrange
        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync();
        host.Endpoint.Handler = static request => Task.FromResult(new OpenIddictResponse
        {
            Error = Errors.InvalidGrant,
            ErrorDescription = "The refresh token is no longer valid."
        });

        var cookie = await host.SignInAsync(expiration: DateTimeOffset.UtcNow.AddSeconds(-1));

        // Act
        using var response = await host.SendAsync(HttpMethod.Get, "/test/token", cookie);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains(response.Headers.GetValues("Set-Cookie"), static value =>
            value.StartsWith(".AspNetCore.Cookies=;", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ValidatePrincipal_TransientRefreshErrorKeepsThePrincipal()
    {
        // Arrange
        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync();
        host.Endpoint.Handler = static request => Task.FromResult(new OpenIddictResponse
        {
            Error = Errors.ServerError
        });

        var cookie = await host.SignInAsync(expiration: DateTimeOffset.UtcNow.AddSeconds(-1));

        // Act
        using var response = await host.SendAsync(HttpMethod.Get, "/test/token", cookie);
        using var retry = await host.SendAsync(HttpMethod.Get, "/test/token", cookie);

        // Assert
        Assert.Equal("old_access_token", await response.Content.ReadAsStringAsync());
        Assert.Equal("old_access_token", await retry.Content.ReadAsStringAsync());

        // Failed refresh operations are never retained.
        Assert.Equal(2, host.Endpoint.Requests.Count);
    }

    [Fact]
    public async Task ValidatePrincipal_DPoPTokenTypeIsStored()
    {
        // Arrange
        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync();
        host.Endpoint.Handler = static request => Task.FromResult(new OpenIddictResponse
        {
            AccessToken = "dpop_access_token",
            ExpiresIn = 3600,
            TokenType = TokenTypes.DPoP
        });

        var cookie = await host.SignInAsync(expiration: DateTimeOffset.UtcNow.AddSeconds(-1));

        // Act
        using var response = await host.SendAsync(HttpMethod.Get, "/test/token", cookie);
        var renewed = OpenIddictClientAspNetCoreBffTestHost.GetCookie(response);

        using var refresh = await host.SendAsync(HttpMethod.Get, "/test/refresh_token", renewed);

        // Assert
        Assert.Equal("dpop_access_token", await response.Content.ReadAsStringAsync());

        // The refresh token is preserved when no new refresh token is returned.
        Assert.Equal("old_refresh_token", await refresh.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task GetClientAccessTokenAsync_TokensAreCachedUntilTheyExpire()
    {
        // Arrange
        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync();
        var manager = host.Services.GetRequiredService<OpenIddictClientAspNetCoreBffTokenManager>();

        // Act
        var first = await manager.GetClientAccessTokenAsync(new ClientAccessTokenRequest { Scopes = ["api"] });
        var second = await manager.GetClientAccessTokenAsync(new ClientAccessTokenRequest { Scopes = ["api"] });
        var other = await manager.GetClientAccessTokenAsync(new ClientAccessTokenRequest { Scopes = ["other"] });

        // Assert
        Assert.Equal("new_access_token", first.Value);
        Assert.Same(first, second);
        Assert.NotSame(first, other);
        Assert.Equal(2, host.Endpoint.Requests.Count);
        Assert.All(host.Endpoint.Requests, static request => Assert.Equal(GrantTypes.ClientCredentials, request.GrantType));
    }

    [Fact]
    public async Task AttachAccessTokenAsync_BearerTokenIsAttached()
    {
        // Arrange
        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync();
        var manager = host.Services.GetRequiredService<OpenIddictClientAspNetCoreBffTokenManager>();

        using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.contoso.com/resource");

        // Act
        await manager.AttachAccessTokenAsync(request, new AccessToken { Value = "access_token", TokenType = TokenTypes.Bearer });

        // Assert
        Assert.Equal(Schemes.Bearer, request.Headers.Authorization?.Scheme);
        Assert.Equal("access_token", request.Headers.Authorization?.Parameter);
        Assert.False(request.Headers.Contains("DPoP"));
    }

    [Fact]
    public async Task AttachAccessTokenAsync_DPoPProofIsAttachedToDPoPBoundTokens()
    {
        // Arrange
        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync(
            client: options => options.EnableDPoPTokenBinding());

        var manager = host.Services.GetRequiredService<OpenIddictClientAspNetCoreBffTokenManager>();

        using var request = new HttpRequestMessage(HttpMethod.Post, "https://api.contoso.com/resource?query=value");

        // Act
        await manager.AttachAccessTokenAsync(request, new AccessToken
        {
            RegistrationId = "Contoso",
            TokenType = TokenTypes.DPoP,
            Value = "access_token"
        });

        // Assert
        Assert.Equal(Schemes.DPoP, request.Headers.Authorization?.Scheme);
        Assert.Equal("access_token", request.Headers.Authorization?.Parameter);

        var proof = new Microsoft.IdentityModel.JsonWebTokens.JsonWebToken(Assert.Single(request.Headers.GetValues("DPoP")));
        Assert.Equal(JsonWebTokenTypes.DPoPProof, proof.Typ);
        Assert.Equal("POST", proof.GetPayloadValue<string>(Claims.HttpMethod));
        Assert.Equal("https://api.contoso.com/resource", proof.GetPayloadValue<string>(Claims.HttpUri));
        Assert.Equal(Base64UrlEncoder.Encode(System.Security.Cryptography.SHA256.HashData("access_token"u8)),
            proof.GetPayloadValue<string>(Claims.DPoPAccessTokenHash));
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        for (var attempt = 0; attempt < 500 && !condition(); attempt++)
        {
            await Task.Delay(10);
        }

        Assert.True(condition());
    }
}
