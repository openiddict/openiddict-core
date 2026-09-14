/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Net;
using System.Net.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using OpenIddict.Server.SystemNetHttp;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Server.Tests;

public class OpenIddictServerLogoutTests
{
    [Fact]
    public void Builder_LogoutAndSessionOptionsAreApplied()
    {
        // Arrange
        var services = new ServiceCollection().AddOptions();
        var builder = new OpenIddictServerBuilder(services);

        // Act
        builder.EnableBackchannelLogout()
               .EnableFrontchannelLogout()
               .EnableSessionManagement()
               .EnableSessionRevocationOnSignOut()
               .RevokeAuthorizationsOnSessionTermination()
               .IncludeSessionIdInAccessTokens()
               .SetCheckSessionIframeEndpointUris("/connect/checksession")
               .SetBackchannelLogoutTimeout(TimeSpan.FromSeconds(3))
               .SetLogoutTokenLifetime(TimeSpan.FromMinutes(1))
               .SetBrowserStateCookieName("custom")
               .SetSessionIdleTimeout(TimeSpan.FromMinutes(20))
               .SetSessionLifetime(TimeSpan.FromHours(10));

        var options = services.BuildServiceProvider().GetRequiredService<IOptions<OpenIddictServerOptions>>().Value;

        // Assert
        Assert.True(options.EnableBackchannelLogout);
        Assert.True(options.EnableFrontchannelLogout);
        Assert.True(options.EnableSessionManagement);
        Assert.True(options.EnableSessionRevocationOnSignOut);
        Assert.True(options.RevokeAuthorizationsOnSessionTermination);
        Assert.True(options.IncludeSessionIdInAccessTokens);
        Assert.Equal(new Uri("/connect/checksession", UriKind.Relative), Assert.Single(options.CheckSessionIframeEndpointUris));
        Assert.Equal(TimeSpan.FromSeconds(3), options.BackchannelLogoutTimeout);
        Assert.Equal(TimeSpan.FromMinutes(1), options.LogoutTokenLifetime);
        Assert.Equal("custom", options.BrowserStateCookieName);
        Assert.Equal(TimeSpan.FromMinutes(20), options.SessionIdleTimeout);
        Assert.Equal(TimeSpan.FromHours(10), options.SessionLifetime);
    }

    [Fact]
    public void Builder_LogoutFeaturesAreDisabledByDefault()
    {
        // Arrange
        var options = new OpenIddictServerOptions();

        // Act and assert
        Assert.False(options.EnableBackchannelLogout);
        Assert.False(options.EnableFrontchannelLogout);
        Assert.False(options.EnableSessionManagement);
        Assert.False(options.EnableSessionRevocationOnSignOut);
        Assert.False(options.RevokeAuthorizationsOnSessionTermination);
        Assert.Null(options.SessionIdleTimeout);
        Assert.Null(options.SessionLifetime);
    }

    [Theory]
    [InlineData("~/path")]
    [InlineData("C:\\path")]
    public void Builder_SetCheckSessionIframeEndpointUris_ThrowsAnExceptionForInvalidUri(string uri)
    {
        // Arrange
        var builder = new OpenIddictServerBuilder(new ServiceCollection().AddOptions());

        // Act and assert
        Assert.Throws<ArgumentException>(() => builder.SetCheckSessionIframeEndpointUris(uri));
    }

    [Theory]
    [InlineData(true, false, false, false)]
    [InlineData(false, true, false, false)]
    [InlineData(false, false, true, false)]
    [InlineData(false, false, false, true)]
    public void Configuration_ReturnsAnErrorWhenLogoutFeaturesAreUsedWithDegradedMode(
        bool backchannel, bool frontchannel, bool revocation, bool expiration)
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = new OpenIddictServerOptions
        {
            EnableBackchannelLogout = backchannel,
            EnableDegradedMode = true,
            EnableFrontchannelLogout = frontchannel,
            EnableSessionRevocationOnSignOut = revocation,
            SessionIdleTimeout = expiration ? TimeSpan.FromMinutes(5) : null,
            TimeProvider = TimeProvider.System
        };

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0721), result.Failures!, StringComparer.Ordinal);
    }

    [Fact]
    public void Configuration_ReturnsAnErrorWhenCheckSessionIframeIsUsedWithoutSessionManagement()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = new OpenIddictServerOptions { TimeProvider = TimeProvider.System };
        options.CheckSessionIframeEndpointUris.Add(new Uri("/connect/checksession", UriKind.Relative));

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0722), result.Failures!, StringComparer.Ordinal);
    }

    [Fact]
    public void Configuration_ReturnsAnErrorWhenSessionManagementIsUsedWithoutCheckSessionIframe()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = new OpenIddictServerOptions { EnableSessionManagement = true, TimeProvider = TimeProvider.System };

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0723), result.Failures!, StringComparer.Ordinal);
    }

    [Fact]
    public void Configuration_ReturnsAnErrorWhenLogoutLifetimesAreNotPositive()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = new OpenIddictServerOptions { LogoutTokenLifetime = TimeSpan.Zero, TimeProvider = TimeProvider.System };

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0724), result.Failures!, StringComparer.Ordinal);
    }

    [Fact]
    public void ComputeSessionState_ReturnsExpectedValue()
    {
        // The expected value is hex(SHA-256("client_id origin browser_state salt")) + "." + salt
        // (OpenID Connect Session Management 1.0, section 3).
        var value = OpenIddictServerHelpers.ComputeSessionState("client", "https://rp.example.com", "state", "salt");

        Assert.Equal("salt", value[(value.IndexOf('.') + 1)..]);
        Assert.Equal(64, value.IndexOf('.'));
        Assert.Equal(value, OpenIddictServerHelpers.ComputeSessionState("client", "https://rp.example.com", "state", "salt"));
        Assert.False(string.Equals(value, OpenIddictServerHelpers.ComputeSessionState("client", "https://rp.example.com", "other", "salt"), StringComparison.Ordinal));
        Assert.False(string.Equals(value, OpenIddictServerHelpers.ComputeSessionState("client", "https://other.example.com", "state", "salt"), StringComparison.Ordinal));

        using var algorithm = System.Security.Cryptography.SHA256.Create();
        var hash = algorithm.ComputeHash(System.Text.Encoding.UTF8.GetBytes("client https://rp.example.com state salt"));
        Assert.Equal(string.Concat(hash.Select(static value => value.ToString("x2", System.Globalization.CultureInfo.InvariantCulture))) + ".salt", value);
    }

    [Fact]
    public void BrowserState_IsBoundToSubject()
    {
        // Arrange
        var state = OpenIddictServerHelpers.CreateBrowserState("Bob");

        // Act and assert
        Assert.True(OpenIddictServerHelpers.ValidateBrowserState(state, "Bob"));
        Assert.False(OpenIddictServerHelpers.ValidateBrowserState(state, "Alice"));
        Assert.False(OpenIddictServerHelpers.ValidateBrowserState(null, "Bob"));
        Assert.False(OpenIddictServerHelpers.ValidateBrowserState("invalid", "Bob"));
        Assert.False(string.Equals(state, OpenIddictServerHelpers.CreateBrowserState("Bob"), StringComparison.Ordinal));
    }

    [Fact]
    public void ComputeSessionExpirationDate_AppliesIdleTimeoutAndAbsoluteLifetime()
    {
        // Arrange
        var date = new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);
        var options = new OpenIddictServerOptions
        {
            SessionIdleTimeout = TimeSpan.FromMinutes(30),
            SessionLifetime = TimeSpan.FromHours(1)
        };

        // Act and assert
        Assert.Equal(date.AddMinutes(30), OpenIddictServerHelpers.ComputeSessionExpirationDate(options, date, date.AddMinutes(-10)));
        Assert.Equal(date.AddMinutes(10), OpenIddictServerHelpers.ComputeSessionExpirationDate(options, date, date.AddMinutes(-50)));
        Assert.Null(OpenIddictServerHelpers.ComputeSessionExpirationDate(new OpenIddictServerOptions(), date, date));
    }

    [Fact]
    public void CreateFrontchannelLogoutPage_EncodesUrisAndRedirection()
    {
        // Act
        var page = OpenIddictServerHelpers.CreateFrontchannelLogoutPage(
            [new Uri("https://rp.example.com/logout?a=1&b=\"2\"")], "https://rp.example.com/\"</script>", "nonce");

        // Assert
        Assert.Contains("<iframe", page, StringComparison.Ordinal);
        Assert.DoesNotContain("\"</script>", page, StringComparison.Ordinal);
        Assert.Contains("nonce=\"nonce\"", page, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SystemNetHttp_LogoutTokenIsPostedToBackchannelLogoutUri()
    {
        // Arrange
        HttpRequestMessage? request = null;
        string? body = null;

        var handler = new CallbackHttpMessageHandler(async message =>
        {
            request = message;
            body = await message.Content!.ReadAsStringAsync();

            return new HttpResponseMessage(HttpStatusCode.OK);
        });

        var context = CreateSendContext(handler);

        // Act
        await new OpenIddictServerSystemNetHttpHandlers.SendHttpBackchannelLogoutRequest(CreateFactory(handler)).HandleAsync(context);

        // Assert
        Assert.True(context.IsSent);
        Assert.False(context.IsRejected);
        Assert.Equal(HttpMethod.Post, request!.Method);
        Assert.Equal("https://rp.example.com/logout", request.RequestUri!.AbsoluteUri);
        Assert.Equal("logout_token=eyJ.token", body);
    }

    [Fact]
    public async Task SystemNetHttp_UnsuccessfulResponseRejectsContext()
    {
        // Arrange
        var handler = new CallbackHttpMessageHandler(static _ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.BadRequest)));
        var context = CreateSendContext(handler);

        // Act
        await new OpenIddictServerSystemNetHttpHandlers.SendHttpBackchannelLogoutRequest(CreateFactory(handler)).HandleAsync(context);

        // Assert
        Assert.False(context.IsSent);
        Assert.True(context.IsRejected);
    }

    [Fact]
    public async Task TerminateSessionAsync_RevokesSessionAndSendsBackchannelLogoutRequests()
    {
        // Arrange
        var session = new object();
        var application = new object();
        var tokens = new List<string>();

        var sessions = new Mock<IOpenIddictSessionManager>();
        sessions.Setup(manager => manager.FindByIdAsync("s1", It.IsAny<CancellationToken>())).ReturnsAsync(session);
        sessions.Setup(manager => manager.GetIdAsync(session, It.IsAny<CancellationToken>())).ReturnsAsync("s1");
        sessions.Setup(manager => manager.GetSubjectAsync(session, It.IsAny<CancellationToken>())).ReturnsAsync("Bob");
        sessions.Setup(manager => manager.GetApplicationIdAsync(session, It.IsAny<CancellationToken>())).ReturnsAsync("a1");
        sessions.Setup(manager => manager.GetAuthorizationIdAsync(session, It.IsAny<CancellationToken>())).ReturnsAsync("z1");
        sessions.Setup(manager => manager.TryRevokeAsync(session, It.IsAny<CancellationToken>())).ReturnsAsync(true);

        var applications = new Mock<IOpenIddictApplicationManager>();
        applications.Setup(manager => manager.FindByIdAsync("a1", It.IsAny<CancellationToken>())).ReturnsAsync(application);
        applications.Setup(manager => manager.GetClientIdAsync(application, It.IsAny<CancellationToken>())).ReturnsAsync("Fabrikam");
        applications.Setup(manager => manager.GetSettingsAsync(application, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [Settings.Logout.BackchannelLogoutUri] = "https://rp.example.com/logout",
                [Settings.Logout.FrontchannelLogoutUri] = "https://rp.example.com/frontchannel"
            }.ToImmutableDictionary(StringComparer.Ordinal));

        var manager = new Mock<IOpenIddictTokenManager>();
        var authorizations = new Mock<IOpenIddictAuthorizationManager>();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(sessions.Object);
        services.AddSingleton(applications.Object);
        services.AddSingleton(manager.Object);
        services.AddSingleton(authorizations.Object);

        services.AddOpenIddict()
            .AddServer(options =>
            {
                options.SetTokenEndpointUris("connect/token")
                       .AllowClientCredentialsFlow()
                       .SetIssuer(new Uri("https://www.contoso.com/", UriKind.Absolute))
                       .EnableBackchannelLogout()
                       .EnableFrontchannelLogout();

                options.AddEphemeralEncryptionKey()
                       .AddEphemeralSigningKey();

                options.AddEventHandler<SendBackchannelLogoutRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        lock (tokens)
                        {
                            tokens.Add(context.LogoutToken);
                        }

                        context.IsSent = true;

                        return ValueTask.CompletedTask;
                    }));
            });

        await using var provider = services.BuildServiceProvider();
        var service = provider.GetRequiredService<OpenIddictServerService>();

        // Act
        var result = await service.TerminateSessionAsync("s1");

        // Assert
        Assert.NotNull(result);
        Assert.Equal("s1", Assert.Single(result.SessionIds));
        Assert.Equal("Fabrikam", Assert.Single(result.NotifiedParticipants).ClientId);
        Assert.Empty(result.FailedParticipants);
        Assert.Contains("sid=s1", Assert.Single(result.FrontchannelLogoutUris).Query, StringComparison.Ordinal);
        Assert.Single(tokens);

        sessions.Verify(mock => mock.TryRevokeAsync(session, It.IsAny<CancellationToken>()), Times.Once());
        manager.Verify(mock => mock.RevokeBySessionIdAsync("s1", It.IsAny<CancellationToken>()), Times.Once());

        // Authorizations are only revoked when RevokeAuthorizationsOnSessionTermination() is used.
        authorizations.Verify(mock => mock.FindByIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task TerminateSessionAsync_ReturnsNullForUnknownSession()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(Mock.Of<IOpenIddictSessionManager>());

        services.AddOpenIddict()
            .AddServer(options =>
            {
                options.SetTokenEndpointUris("connect/token")
                       .AllowClientCredentialsFlow()
                       .SetIssuer(new Uri("https://www.contoso.com/", UriKind.Absolute));

                options.AddEphemeralEncryptionKey()
                       .AddEphemeralSigningKey();
            });

        await using var provider = services.BuildServiceProvider();
        var service = provider.GetRequiredService<OpenIddictServerService>();

        // Act and assert
        Assert.Null(await service.TerminateSessionAsync("unknown"));
    }

    [Fact]
    public async Task TerminateSessionAsync_ThrowsAnExceptionWhenIssuerIsNotSet()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddLogging();

        services.AddOpenIddict()
            .AddServer(options =>
            {
                options.SetTokenEndpointUris("connect/token")
                       .AllowClientCredentialsFlow();

                options.AddEphemeralEncryptionKey()
                       .AddEphemeralSigningKey();
            });

        await using var provider = services.BuildServiceProvider();
        var service = provider.GetRequiredService<OpenIddictServerService>();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () => await service.TerminateSessionAsync("s1"));
        Assert.Equal(SR.GetResourceString(SR.ID0726), exception.Message);
    }

    private static SendBackchannelLogoutRequestContext CreateSendContext(HttpMessageHandler handler)
    {
        var provider = new ServiceCollection()
            .AddSingleton<ILoggerFactory>(NullLoggerFactory.Instance)
            .AddSingleton(typeof(ILogger<>), typeof(Logger<>))
            .BuildServiceProvider();

        var transaction = new OpenIddictServerTransaction
        {
            CancellationToken = CancellationToken.None,
            Options = new OpenIddictServerOptions(),
            ServiceProvider = provider
        };

        return new SendBackchannelLogoutRequestContext(transaction)
        {
            LogoutToken = "eyJ.token",
            Participant = new OpenIddictServerLogoutParticipant
            {
                ApplicationId = "1",
                ClientId = "client",
                SessionId = "session"
            },
            Uri = new Uri("https://rp.example.com/logout", UriKind.Absolute)
        };
    }

    private static IHttpClientFactory CreateFactory(HttpMessageHandler handler)
    {
        var factory = new Mock<IHttpClientFactory>();
        factory.Setup(factory => factory.CreateClient(OpenIddictServerSystemNetHttpConstants.HttpClientName))
            .Returns(() => new HttpClient(handler, disposeHandler: false));

        return factory.Object;
    }

    private sealed class CallbackHttpMessageHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> callback) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => callback(request);
    }
}
