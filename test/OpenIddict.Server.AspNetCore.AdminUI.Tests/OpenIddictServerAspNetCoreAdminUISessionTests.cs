/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Net;
using System.Security.Claims;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Moq;
using OpenIddict.Server;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Server.AspNetCore.AdminUI.Tests;

public partial class OpenIddictServerAspNetCoreAdminUITests
{
    [Theory]
    [InlineData("/openiddict/admin/sessions")]
    [InlineData("/openiddict/admin/sessions/s1")]
    public async Task Sessions_RejectUnauthenticatedAndForbiddenRequests(string path)
    {
        // Arrange
        var manager = new Mock<IOpenIddictSessionManager>();
        using var host = await CreateHostAsync(services => services.AddSingleton(manager.Object));
        using var anonymous = CreateClient(host, role: null);
        using var user = CreateClient(host, role: "user");

        // Act
        var unauthenticated = await anonymous.GetAsync(path);
        var forbidden = await user.GetAsync(path);
        var terminate = await user.PostAsync("/openiddict/admin/sessions/s1/terminate", new FormUrlEncodedContent([]));

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, unauthenticated.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, terminate.StatusCode);
        manager.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task ListSessions_ListsSessionsWithoutPrincipals()
    {
        // Arrange
        var session = new object();
        var application = new object();

        var applications = new Mock<IOpenIddictApplicationManager>();
        applications.Setup(mock => mock.FindByIdAsync("app-1", It.IsAny<CancellationToken>())).ReturnsAsync(application);
        applications.Setup(mock => mock.GetClientIdAsync(application, It.IsAny<CancellationToken>())).ReturnsAsync("fabrikam");

        var manager = new Mock<IOpenIddictSessionManager>();
        manager.Setup(mock => mock.ListAsync(26, 0, It.IsAny<CancellationToken>())).Returns(EnumerateAsync(session));
        SetupSession(manager, session, "session-1", Statuses.Valid);

        using var host = await CreateHostAsync(services => services
            .AddSingleton(applications.Object)
            .AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        // Act
        var html = await client.GetStringAsync("/openiddict/admin/sessions");

        // Assert
        Assert.Contains("href=\"/openiddict/admin/sessions/session-1\"", html, StringComparison.Ordinal);
        Assert.Contains("<td>fabrikam</td>", html, StringComparison.Ordinal);
        Assert.Contains("<td>login-1</td>", html, StringComparison.Ordinal);
        Assert.Contains("action=\"/openiddict/admin/sessions/session-1/terminate\"", html, StringComparison.Ordinal);
        Assert.Contains("href=\"/openiddict/admin/sessions\" aria-current=\"page\"", html, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-claim-value", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ListSessions_FiltersSessionsAndHidesTheTerminateActionForRevokedSessions()
    {
        // Arrange
        var session = new object();
        var application = new object();

        var applications = new Mock<IOpenIddictApplicationManager>();
        applications.Setup(mock => mock.FindByClientIdAsync("fabrikam", It.IsAny<CancellationToken>())).ReturnsAsync(application);
        applications.Setup(mock => mock.GetIdAsync(application, It.IsAny<CancellationToken>())).ReturnsAsync("app-1");

        var manager = new Mock<IOpenIddictSessionManager>();
        manager.Setup(mock => mock.FindAsync(It.Is<(string?, string?, string?, string?, string?)>(query =>
                query.Item1 == "alice" && query.Item2 == "login-1" && query.Item3 == "app-1" &&
                query.Item4 == null && query.Item5 == Statuses.Revoked), It.IsAny<CancellationToken>()))
            .Returns(EnumerateAsync(session));
        SetupSession(manager, session, "session-1", Statuses.Revoked);

        using var host = await CreateHostAsync(services => services
            .AddSingleton(applications.Object)
            .AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        // Act
        var html = await client.GetStringAsync("/openiddict/admin/sessions?subject=alice&client=fabrikam&status=revoked&login_id=login-1");
        var unknown = await client.GetStringAsync("/openiddict/admin/sessions?client=unknown");

        // Assert
        Assert.Contains("<code>session-1</code>", html, StringComparison.Ordinal);
        Assert.Contains("value=\"login-1\"", html, StringComparison.Ordinal);
        Assert.DoesNotContain("/terminate\"", html, StringComparison.Ordinal);
        Assert.Contains("No session was found.", unknown, StringComparison.Ordinal);
        manager.Verify(mock => mock.ListAsync(It.IsAny<int?>(), It.IsAny<int?>(), It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task ShowSession_RendersTheSessionAndItsTokensWithoutPrincipalOrPayloads()
    {
        // Arrange
        var session = new object();
        var token = new object();

        var applications = new Mock<IOpenIddictApplicationManager>();

        var manager = new Mock<IOpenIddictSessionManager>();
        manager.Setup(mock => mock.FindByIdAsync("session-1", It.IsAny<CancellationToken>())).ReturnsAsync(session);
        SetupSession(manager, session, "session-1", Statuses.Valid);

        var tokens = new Mock<IOpenIddictTokenManager>();
        tokens.Setup(mock => mock.FindBySessionIdAsync("session-1", It.IsAny<CancellationToken>())).Returns(EnumerateAsync(token));
        tokens.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>())).ReturnsAsync("token-1");
        tokens.Setup(mock => mock.PopulateAsync(It.IsAny<OpenIddictTokenDescriptor>(), token, It.IsAny<CancellationToken>()))
            .Callback((OpenIddictTokenDescriptor descriptor, object _, CancellationToken _) =>
            {
                descriptor.Payload = "secret-token-payload";
                descriptor.Type = TokenTypeIdentifiers.RefreshToken;
            })
            .Returns(ValueTask.CompletedTask);

        using var host = await CreateHostAsync(services => services
            .AddSingleton(applications.Object)
            .AddSingleton(manager.Object)
            .AddSingleton(tokens.Object));
        using var client = CreateClient(host, role: "admin");

        // Act
        var html = await client.GetStringAsync("/openiddict/admin/sessions/session-1");
        var unknown = await client.GetAsync("/openiddict/admin/sessions/unknown");

        // Assert
        Assert.Contains("href=\"/openiddict/admin/sessions?login_id=login-1\"", html, StringComparison.Ordinal);
        Assert.Contains("href=\"/openiddict/admin/authorizations/authz-1\"", html, StringComparison.Ordinal);
        Assert.Contains("href=\"/openiddict/admin/tokens/token-1\"", html, StringComparison.Ordinal);
        Assert.Contains("action=\"/openiddict/admin/sessions/session-1/terminate\"", html, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-claim-value", html, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-token-payload", html, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
    }

    [Fact]
    public async Task TerminateSession_RejectsRequestsWithoutAntiforgeryToken()
    {
        // Arrange
        var service = new Mock<OpenIddictServerService>(Mock.Of<IServiceProvider>());
        var manager = new Mock<IOpenIddictSessionManager>();

        using var host = await CreateHostAsync(services => services
            .AddSingleton(manager.Object)
            .AddSingleton(service.Object));
        using var client = CreateClient(host, role: "admin");

        // Act
        var response = await client.PostAsync("/openiddict/admin/sessions/session-1/terminate", new FormUrlEncodedContent([]));

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains(WebUtility.HtmlEncode(SR.GetResourceString(SR.ID2340)), await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        service.Verify(mock => mock.TerminateSessionAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task TerminateSession_UsesTheServerServiceAndRendersTheResult()
    {
        // Arrange
        var session = new object();

        var applications = new Mock<IOpenIddictApplicationManager>();

        var manager = new Mock<IOpenIddictSessionManager>();
        manager.Setup(mock => mock.FindByIdAsync("session-1", It.IsAny<CancellationToken>())).ReturnsAsync(session);
        SetupSession(manager, session, "session-1", Statuses.Valid);

        var tokens = new Mock<IOpenIddictTokenManager>();
        tokens.Setup(mock => mock.FindBySessionIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>())).Returns(EnumerateAsync());

        var service = new Mock<OpenIddictServerService>(Mock.Of<IServiceProvider>());
        service.Setup(mock => mock.TerminateSessionAsync("session-1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new OpenIddictServerSessionTerminationResult
            {
                SessionIds = ["session-1", "session-2"],
                NotifiedParticipants = [new OpenIddictServerLogoutParticipant { ApplicationId = "app-1", ClientId = "fabrikam", SessionId = "session-1" }],
                FailedParticipants = [new OpenIddictServerLogoutParticipant { ApplicationId = "app-2", ClientId = "contoso", SessionId = "session-2" }],
                FrontchannelLogoutUris = [new Uri("https://fabrikam.com/frontchannel?iss=https%3A%2F%2Fcontoso.com%2F&sid=session-1")]
            });

        using var host = await CreateHostAsync(services => services
            .AddSingleton(applications.Object)
            .AddSingleton(manager.Object)
            .AddSingleton(tokens.Object)
            .AddSingleton(service.Object));
        using var client = CreateClient(host, role: "admin");

        var antiforgery = await GetAntiforgeryAsync(client, "/openiddict/admin/sessions/session-1");

        // Act
        var response = await PostAsync(client, antiforgery, "/openiddict/admin/sessions/session-1/terminate", []);
        var html = await response.Content.ReadAsStringAsync();

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("The session was terminated.", html, StringComparison.Ordinal);
        Assert.Contains("href=\"/openiddict/admin/sessions/session-2\"", html, StringComparison.Ordinal);
        Assert.Contains("<dd>fabrikam</dd>", html, StringComparison.Ordinal);
        Assert.Contains("<dd>contoso</dd>", html, StringComparison.Ordinal);
        Assert.Contains("<code>https://fabrikam.com/frontchannel?iss=https%3A%2F%2Fcontoso.com%2F&amp;sid=session-1</code>", html, StringComparison.Ordinal);
        Assert.DoesNotContain("<iframe", html, StringComparison.OrdinalIgnoreCase);
        service.Verify(mock => mock.TerminateSessionAsync("session-1", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task TerminateSession_ReturnsNotFoundForUnknownSessions()
    {
        // Arrange
        var service = new Mock<OpenIddictServerService>(Mock.Of<IServiceProvider>());
        var manager = new Mock<IOpenIddictSessionManager>();

        var session = new object();
        manager.Setup(mock => mock.ListAsync(26, 0, It.IsAny<CancellationToken>())).Returns(EnumerateAsync(session));
        SetupSession(manager, session, "session-1", Statuses.Valid);

        using var host = await CreateHostAsync(services => services
            .AddSingleton(new Mock<IOpenIddictApplicationManager>().Object)
            .AddSingleton(manager.Object)
            .AddSingleton(service.Object));
        using var client = CreateClient(host, role: "admin");

        var antiforgery = await GetAntiforgeryAsync(client, "/openiddict/admin/sessions");

        // Act
        var response = await PostAsync(client, antiforgery, "/openiddict/admin/sessions/unknown/terminate", []);

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        service.Verify(mock => mock.TerminateSessionAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task TerminateSession_ThrowsAnExceptionWhenServerServicesAreMissing()
    {
        // Arrange
        var session = new object();

        var manager = new Mock<IOpenIddictSessionManager>();
        manager.Setup(mock => mock.ListAsync(26, 0, It.IsAny<CancellationToken>())).Returns(EnumerateAsync(session));
        manager.Setup(mock => mock.FindByIdAsync("session-1", It.IsAny<CancellationToken>())).ReturnsAsync(session);
        SetupSession(manager, session, "session-1", Statuses.Valid);

        using var host = await CreateHostAsync(services => services
            .AddSingleton(new Mock<IOpenIddictApplicationManager>().Object)
            .AddSingleton(manager.Object));
        using var client = CreateClient(host, role: "admin");

        var antiforgery = await GetAntiforgeryAsync(client, "/openiddict/admin/sessions");

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => PostAsync(client, antiforgery, "/openiddict/admin/sessions/session-1/terminate", []));
        Assert.Equal(SR.GetResourceString(SR.ID01040), exception.Message);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TerminateSession_SendsLogoutNotificationsAndReportsConfigurationErrors(bool issuer)
    {
        // Arrange
        var sessions = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["session-1"] = new object(),
            ["session-2"] = new object()
        };

        var applications = new Mock<IOpenIddictApplicationManager>();
        var manager = new Mock<IOpenIddictSessionManager>();

        foreach (var (identifier, index) in new[] { ("session-1", "1"), ("session-2", "2") })
        {
            var session = sessions[identifier];
            var application = new object();

            manager.Setup(mock => mock.FindByIdAsync(identifier, It.IsAny<CancellationToken>())).ReturnsAsync(session);
            manager.Setup(mock => mock.HasStatusAsync(session, Statuses.Valid, It.IsAny<CancellationToken>())).ReturnsAsync(true);
            manager.Setup(mock => mock.GetApplicationIdAsync(session, It.IsAny<CancellationToken>())).ReturnsAsync($"app-{index}");
            manager.Setup(mock => mock.TryRevokeAsync(session, It.IsAny<CancellationToken>())).ReturnsAsync(true);
            SetupSession(manager, session, identifier, Statuses.Valid, $"app-{index}");

            applications.Setup(mock => mock.FindByIdAsync($"app-{index}", It.IsAny<CancellationToken>())).ReturnsAsync(application);
            applications.Setup(mock => mock.GetClientIdAsync(application, It.IsAny<CancellationToken>())).ReturnsAsync($"client-{index}");
            applications.Setup(mock => mock.GetSettingsAsync(application, It.IsAny<CancellationToken>()))
                .ReturnsAsync(ImmutableDictionary.CreateRange(StringComparer.Ordinal,
                [
                    KeyValuePair.Create(Settings.Logout.BackchannelLogoutUri, $"https://client-{index}.com/backchannel"),
                    KeyValuePair.Create(Settings.Logout.FrontchannelLogoutUri, $"https://client-{index}.com/frontchannel")
                ]));
        }

        manager.Setup(mock => mock.FindByLoginIdAsync("login-1", It.IsAny<CancellationToken>()))
            .Returns(() => EnumerateAsync(sessions["session-1"], sessions["session-2"]));

        var tokens = new Mock<IOpenIddictTokenManager>();
        tokens.Setup(mock => mock.FindBySessionIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>())).Returns(() => EnumerateAsync());

        List<(Uri Uri, string Token)> requests = [];

        using var host = await CreateHostAsync(services =>
        {
            services.AddSingleton(applications.Object);
            services.AddSingleton(manager.Object);
            services.AddSingleton(tokens.Object);

            services.AddOpenIddict()
                .AddServer(options =>
                {
                    options.SetTokenEndpointUris("connect/token")
                           .AllowClientCredentialsFlow()
                           .EnableBackchannelLogout()
                           .EnableFrontchannelLogout();

                    if (issuer)
                    {
                        options.SetIssuer(new Uri("https://www.contoso.com/", UriKind.Absolute));
                    }

                    options.AddEphemeralEncryptionKey()
                           .AddEphemeralSigningKey();

                    // Note: the notification sent to the second client application is marked as failed.
                    options.AddEventHandler<SendBackchannelLogoutRequestContext>(builder =>
                        builder.UseInlineHandler(context =>
                        {
                            lock (requests)
                            {
                                requests.Add((context.Uri, context.LogoutToken));
                            }

                            context.IsSent = context.Participant.ClientId is "client-1";

                            return ValueTask.CompletedTask;
                        }));
                });
        });

        using var client = CreateClient(host, role: "admin");

        var antiforgery = await GetAntiforgeryAsync(client, "/openiddict/admin/sessions/session-1");

        // Act
        var response = await PostAsync(client, antiforgery, "/openiddict/admin/sessions/session-1/terminate", []);
        var html = await response.Content.ReadAsStringAsync();

        // Assert
        if (!issuer)
        {
            Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
            Assert.Contains("SetIssuer", html, StringComparison.Ordinal);
            Assert.Empty(requests);

            return;
        }

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("The session was terminated.", html, StringComparison.Ordinal);
        Assert.Contains("<dd>client-1</dd>", html, StringComparison.Ordinal);
        Assert.Contains("<dd>client-2</dd>", html, StringComparison.Ordinal);
        Assert.Contains("<code>https://client-1.com/frontchannel?", html, StringComparison.Ordinal);
        Assert.Contains("<code>https://client-2.com/frontchannel?", html, StringComparison.Ordinal);

        Assert.Equal("https://client-1.com/backchannel https://client-2.com/backchannel",
            string.Join(' ', requests.Select(static request => request.Uri.AbsoluteUri).Order(StringComparer.Ordinal)));
        Assert.All(requests, static request => Assert.False(string.IsNullOrEmpty(request.Token)));

        manager.Verify(mock => mock.TryRevokeAsync(sessions["session-1"], It.IsAny<CancellationToken>()), Times.Once());
        manager.Verify(mock => mock.TryRevokeAsync(sessions["session-2"], It.IsAny<CancellationToken>()), Times.Once());
        tokens.Verify(mock => mock.RevokeBySessionIdAsync("session-1", It.IsAny<CancellationToken>()), Times.Once());
        tokens.Verify(mock => mock.RevokeBySessionIdAsync("session-2", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task EntityFrameworkCore_SessionsCanBeListedAndTerminated()
    {
        // Arrange
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();

        List<string> notifications = [];

        using var host = await CreateEntityFrameworkCoreHostAsync(connection, services => services.AddOpenIddict()
            .AddServer(options =>
            {
                options.SetTokenEndpointUris("connect/token")
                       .AllowClientCredentialsFlow()
                       .SetIssuer(new Uri("https://www.contoso.com/", UriKind.Absolute))
                       .EnableBackchannelLogout();

                options.AddEphemeralEncryptionKey()
                       .AddEphemeralSigningKey();

                options.AddEventHandler<SendBackchannelLogoutRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        lock (notifications)
                        {
                            notifications.Add(context.Participant.ClientId);
                        }

                        context.IsSent = true;

                        return ValueTask.CompletedTask;
                    }));
            }));

        string first, second, other;

        await using (var scope = host.Services.CreateAsyncScope())
        {
            var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictSessionManager>();

            var application = await applications.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "fabrikam",
                ClientType = ClientTypes.Public,
                Settings = { [Settings.Logout.BackchannelLogoutUri] = "https://fabrikam.com/backchannel" }
            });

            var identifier = await applications.GetIdAsync(application);

            first = await CreateSessionAsync(manager, identifier, "login-1");
            second = await CreateSessionAsync(manager, identifier, "login-1");
            other = await CreateSessionAsync(manager, identifier, "login-2");
        }

        using var client = CreateClient(host, role: "admin");

        // Act
        var list = await client.GetStringAsync("/openiddict/admin/sessions?login_id=login-1");
        var invalid = await client.GetAsync("/openiddict/admin/sessions/fabrikam");

        var antiforgery = await GetAntiforgeryAsync(client, $"/openiddict/admin/sessions/{first}");
        var response = await PostAsync(client, antiforgery, $"/openiddict/admin/sessions/{first}/terminate", []);
        var html = await response.Content.ReadAsStringAsync();

        // Assert
        Assert.Contains($"<code>{first}</code>", list, StringComparison.Ordinal);
        Assert.Contains($"<code>{second}</code>", list, StringComparison.Ordinal);
        Assert.DoesNotContain($"<code>{other}</code>", list, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.NotFound, invalid.StatusCode);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("The session was terminated.", html, StringComparison.Ordinal);
        Assert.DoesNotContain($"action=\"/openiddict/admin/sessions/{first}/terminate\"", html, StringComparison.Ordinal);
        Assert.Equal("fabrikam fabrikam", string.Join(' ', notifications));

        await using (var scope = host.Services.CreateAsyncScope())
        {
            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictSessionManager>();

            Assert.True(await manager.HasStatusAsync((await manager.FindByIdAsync(first))!, Statuses.Revoked));
            Assert.True(await manager.HasStatusAsync((await manager.FindByIdAsync(second))!, Statuses.Revoked));
            Assert.True(await manager.HasStatusAsync((await manager.FindByIdAsync(other))!, Statuses.Valid));
        }

        // Terminating an already terminated session doesn't notify the client applications again.
        var again = await PostAsync(client, antiforgery, $"/openiddict/admin/sessions/{first}/terminate", []);

        Assert.Equal(HttpStatusCode.OK, again.StatusCode);
        Assert.Contains("No valid session was terminated", await again.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        Assert.Equal(2, notifications.Count);

        static async Task<string> CreateSessionAsync(IOpenIddictSessionManager manager, string? application, string login)
        {
            var session = await manager.CreateAsync(new OpenIddictSessionDescriptor
            {
                ApplicationId = application,
                CreationDate = DateTimeOffset.UtcNow,
                ExpirationDate = DateTimeOffset.UtcNow.AddHours(1),
                LoginId = login,
                Status = Statuses.Valid,
                Subject = "alice"
            });

            return (await manager.GetIdAsync(session))!;
        }
    }

    private static void SetupSession(Mock<IOpenIddictSessionManager> manager, object session,
        string identifier, string status, string application = "app-1")
    {
        manager.Setup(mock => mock.GetIdAsync(session, It.IsAny<CancellationToken>())).ReturnsAsync(identifier);
        manager.Setup(mock => mock.GetLoginIdAsync(session, It.IsAny<CancellationToken>())).ReturnsAsync("login-1");
        manager.Setup(mock => mock.GetSubjectAsync(session, It.IsAny<CancellationToken>())).ReturnsAsync("alice");
        manager.Setup(mock => mock.PopulateAsync(It.IsAny<OpenIddictSessionDescriptor>(), session, It.IsAny<CancellationToken>()))
            .Callback((OpenIddictSessionDescriptor descriptor, object _, CancellationToken _) =>
            {
                descriptor.ApplicationId = application;
                descriptor.AuthorizationId = "authz-1";
                descriptor.CreationDate = new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero);
                descriptor.ExpirationDate = new DateTimeOffset(2030, 1, 2, 0, 0, 0, TimeSpan.Zero);
                descriptor.LoginId = "login-1";
                descriptor.Principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("secret", "secret-claim-value")], "Test"));
                descriptor.Status = status;
                descriptor.Subject = "alice";
            })
            .Returns(ValueTask.CompletedTask);
    }
}
