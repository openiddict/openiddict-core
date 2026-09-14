/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Moq;
using OpenIddict.Core;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers;
using static OpenIddict.Server.OpenIddictServerHandlers.Protection;

namespace OpenIddict.Server.IntegrationTests;

public abstract partial class OpenIddictServerIntegrationTests
{
    private const string LogoutSessionId = "3E228451-1555-46F7-A471-951EFBA23A56";

    [Fact]
    public async Task HandleConfigurationRequest_LogoutMetadataAreNotReturnedByDefault()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.Null((bool?) response[Metadata.BackchannelLogoutSupported]);
        Assert.Null((bool?) response[Metadata.FrontchannelLogoutSupported]);
        Assert.Null((string?) response[Metadata.CheckSessionIframe]);
    }

    [Fact]
    public async Task HandleConfigurationRequest_LogoutMetadataAreReturnedWhenEnabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableBackchannelLogout()
                   .EnableFrontchannelLogout()
                   .EnableSessionManagement()
                   .SetCheckSessionIframeEndpointUris("/connect/checksession");
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.True((bool) response[Metadata.BackchannelLogoutSupported]);
        Assert.True((bool) response[Metadata.BackchannelLogoutSessionSupported]);
        Assert.True((bool) response[Metadata.FrontchannelLogoutSupported]);
        Assert.True((bool) response[Metadata.FrontchannelLogoutSessionSupported]);
        Assert.EndsWith("/connect/checksession", (string?) response[Metadata.CheckSessionIframe], StringComparison.Ordinal);
    }

    [Fact]
    public async Task ProcessSignOut_SessionIsNotRevokedByDefault()
    {
        // Arrange
        var manager = CreateSessionManager();

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(manager);
            ConfigureSignOut(options);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/connect/endsession");

        // Assert
        Assert.Null(response.Error);
        Mock.Get(manager).Verify(manager => manager.FindByIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task ProcessSignOut_SessionAndTokensAreRevokedWhenEnabled()
    {
        // Arrange
        var session = new OpenIddictSession();
        var sessions = CreateLogoutSessionManager(session, login: null);
        var tokens = CreateTokenManager(mock =>
        {
            mock.Setup(manager => manager.RevokeBySessionIdAsync(LogoutSessionId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(2);
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(sessions);
            options.Services.AddSingleton(tokens);
            options.EnableSessionRevocationOnSignOut();
            ConfigureSignOut(options, LogoutSessionId);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/connect/endsession");

        // Assert
        Assert.Null(response.Error);
        Mock.Get(sessions).Verify(manager => manager.TryRevokeAsync(session, It.IsAny<CancellationToken>()), Times.Once());
        Mock.Get(tokens).Verify(manager => manager.RevokeBySessionIdAsync(LogoutSessionId, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ProcessSignOut_SessionIsResolvedFromIdentityTokenHint()
    {
        // Arrange
        var session = new OpenIddictSession();
        var sessions = CreateLogoutSessionManager(session, login: null);

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(sessions);
            options.EnableSessionRevocationOnSignOut();

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeIdentifiers.IdentityToken)
                        .SetClaim(Claims.Subject, "Bob le Bricoleur")
                        .SetClaim(Claims.SessionId, LogoutSessionId);

                    return ValueTask.CompletedTask;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });

            ConfigureSignOut(options);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/connect/endsession", new OpenIddictRequest
        {
            IdTokenHint = "id_token"
        });

        // Assert
        Assert.Null(response.Error);
        Mock.Get(sessions).Verify(manager => manager.TryRevokeAsync(session, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ProcessSignOut_SessionsSharingLoginIdentifierAreRevoked()
    {
        // Arrange
        var session = new OpenIddictSession();
        var other = new OpenIddictSession();
        var foreign = new OpenIddictSession();

        var sessions = CreateLogoutSessionManager(session, login: "login", mock =>
        {
            mock.Setup(manager => manager.FindByLoginIdAsync("login", It.IsAny<CancellationToken>()))
                .Returns(new[] { session, other, foreign }.ToAsyncEnumerable());

            mock.Setup(manager => manager.GetIdAsync(other, It.IsAny<CancellationToken>()))
                .ReturnsAsync("other");
            mock.Setup(manager => manager.GetSubjectAsync(other, It.IsAny<CancellationToken>()))
                .ReturnsAsync("Bob le Bricoleur");
            mock.Setup(manager => manager.HasStatusAsync(other, Statuses.Valid, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            // Sessions attached to a different subject are never terminated.
            mock.Setup(manager => manager.GetIdAsync(foreign, It.IsAny<CancellationToken>()))
                .ReturnsAsync("foreign");
            mock.Setup(manager => manager.GetSubjectAsync(foreign, It.IsAny<CancellationToken>()))
                .ReturnsAsync("Bob l'Eponge");
            mock.Setup(manager => manager.HasStatusAsync(foreign, Statuses.Valid, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(sessions);
            options.EnableSessionRevocationOnSignOut();
            ConfigureSignOut(options, LogoutSessionId);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/connect/endsession");

        // Assert
        Assert.Null(response.Error);
        Mock.Get(sessions).Verify(manager => manager.TryRevokeAsync(session, It.IsAny<CancellationToken>()), Times.Once());
        Mock.Get(sessions).Verify(manager => manager.TryRevokeAsync(other, It.IsAny<CancellationToken>()), Times.Once());
        Mock.Get(sessions).Verify(manager => manager.TryRevokeAsync(foreign, It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task ProcessSignOut_BackchannelLogoutTokenIsSentToParticipants()
    {
        // Arrange
        var session = new OpenIddictSession();
        var sessions = CreateLogoutSessionManager(session, login: null);
        var applications = CreateLogoutApplicationManager(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [Settings.Logout.BackchannelLogoutUri] = "https://www.fabrikam.com/logout/backchannel"
        });

        SendBackchannelLogoutRequestContext? notification = null;

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(sessions);
            options.Services.AddSingleton(applications);
            options.SetIssuer("https://www.contoso.com/");
            options.EnableBackchannelLogout();

            options.AddEventHandler<SendBackchannelLogoutRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    notification = context;
                    context.IsSent = true;

                    return ValueTask.CompletedTask;
                }));

            ConfigureSignOut(options, LogoutSessionId);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/connect/endsession");

        // Assert
        Assert.Null(response.Error);
        Assert.NotNull(notification);
        Assert.Equal("https://www.fabrikam.com/logout/backchannel", notification.Uri.AbsoluteUri);
        Assert.Equal("Fabrikam", notification.Participant.ClientId);

        var token = new JsonWebToken(notification.LogoutToken);
        Assert.Equal(JsonWebTokenTypes.LogoutToken, token.Typ);
        Assert.Equal("https://www.contoso.com/", token.Issuer);
        Assert.Equal("Fabrikam", Assert.Single(token.Audiences));
        Assert.Equal("Bob le Bricoleur", token.Subject);
        Assert.Equal(LogoutSessionId, token.GetPayloadValue<string>(Claims.SessionId));
        Assert.False(string.IsNullOrEmpty(token.Id));
        Assert.True(token.TryGetPayloadValue(Claims.IssuedAt, out long _));
        Assert.True(token.TryGetPayloadValue(Claims.ExpiresAt, out long _));
        Assert.False(token.TryGetPayloadValue(Claims.Nonce, out string _));
        Assert.True(token.TryGetPayloadValue(Claims.Events, out JsonElement events));
        Assert.Equal(JsonValueKind.Object, events.GetProperty(SecurityEventTypes.BackchannelLogout).ValueKind);
    }

    [Fact]
    public async Task ProcessSignOut_BackchannelLogoutFailureDoesNotPreventSignOut()
    {
        // Arrange
        var session = new OpenIddictSession();
        var sessions = CreateLogoutSessionManager(session, login: null);
        var applications = CreateLogoutApplicationManager(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [Settings.Logout.BackchannelLogoutUri] = "https://www.fabrikam.com/logout/backchannel"
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(sessions);
            options.Services.AddSingleton(applications);
            options.EnableBackchannelLogout();

            options.AddEventHandler<SendBackchannelLogoutRequestContext>(builder =>
                builder.UseInlineHandler(context => throw new HttpRequestException("The request timed out.")));

            ConfigureSignOut(options, LogoutSessionId);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/connect/endsession");

        // Assert
        Assert.Null(response.Error);
    }

    [Fact]
    public async Task ProcessSignOut_FrontchannelLogoutIframesAreRendered()
    {
        // Arrange
        var session = new OpenIddictSession();
        var sessions = CreateLogoutSessionManager(session, login: null);
        var applications = CreateLogoutApplicationManager(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [Settings.Logout.FrontchannelLogoutUri] = "https://www.fabrikam.com/logout/frontchannel?tenant=1"
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(sessions);
            options.Services.AddSingleton(applications);
            options.SetIssuer("https://www.contoso.com/");
            options.EnableFrontchannelLogout();
            ConfigureSignOut(options, LogoutSessionId);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        using var response = await client.HttpClient.GetAsync("/connect/endsession");
        var content = await response.Content.ReadAsStringAsync();

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);
        Assert.Contains("<iframe", content, StringComparison.Ordinal);

        var start = content.IndexOf("src=\"", content.IndexOf("<iframe", StringComparison.Ordinal), StringComparison.Ordinal) + 5;
        var uri = new Uri(WebUtility.HtmlDecode(content[start..content.IndexOf('"', start)]), UriKind.Absolute);
        Assert.Equal("https://www.fabrikam.com/logout/frontchannel", uri.GetLeftPart(UriPartial.Path));

        var parameters = uri.Query.TrimStart('?').Split('&')
            .Select(static parameter => parameter.Split('='))
            .ToDictionary(static parts => parts[0], static parts => Uri.UnescapeDataString(parts[1]), StringComparer.Ordinal);

        Assert.Equal("1", parameters["tenant"]);
        Assert.Equal("https://www.contoso.com/", parameters[Parameters.Iss]);
        Assert.Equal(LogoutSessionId, parameters[Parameters.Sid]);
        Assert.Contains("frame-src https://www.fabrikam.com", string.Join(';', response.Headers.GetValues("Content-Security-Policy")), StringComparison.Ordinal);

        // Front-channel logout doesn't revoke the session unless session revocation is enabled.
        Mock.Get(sessions).Verify(manager => manager.TryRevokeAsync(session, It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task ProcessSignOut_FrontchannelLogoutPageRedirectsToPostLogoutRedirectUri()
    {
        // Arrange
        var session = new OpenIddictSession();
        var sessions = CreateLogoutSessionManager(session, login: null);
        var applications = CreateLogoutApplicationManager(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [Settings.Logout.FrontchannelLogoutUri] = "https://www.fabrikam.com/logout/frontchannel"
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(sessions);
            options.Services.AddSingleton(applications);
            options.EnableFrontchannelLogout();

            ConfigureSignOut(options, LogoutSessionId);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        using var response = await client.HttpClient.GetAsync("/connect/endsession?post_logout_redirect_uri=http%3A%2F%2Fwww.fabrikam.com%2Fpath&state=af0ifjsldkj");
        var content = await response.Content.ReadAsStringAsync();

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("www.fabrikam.com", content, StringComparison.Ordinal);
        Assert.Contains("state=af0ifjsldkj", content, StringComparison.Ordinal);
        Assert.Contains("window.location.replace", content, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ProcessSignOut_NoFrontchannelLogoutPageIsRenderedWithoutParticipants()
    {
        // Arrange
        var session = new OpenIddictSession();
        var sessions = CreateLogoutSessionManager(session, login: null);
        var applications = CreateLogoutApplicationManager(new Dictionary<string, string>(StringComparer.Ordinal));

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(sessions);
            options.Services.AddSingleton(applications);
            options.EnableFrontchannelLogout();

            ConfigureSignOut(options, LogoutSessionId);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/connect/endsession", new OpenIddictRequest
        {
            PostLogoutRedirectUri = "http://www.fabrikam.com/path",
            State = "af0ifjsldkj"
        });

        // Assert
        Assert.Equal("af0ifjsldkj", response.State);
    }

    [Fact]
    public async Task CheckSessionIframe_PageIsReturnedWhenSessionManagementIsEnabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.EnableSessionManagement()
                   .SetCheckSessionIframeEndpointUris("/connect/checksession")
                   .SetBrowserStateCookieName("custom.browser_state");
        });

        await using var client = await server.CreateClientAsync();

        // Act
        using var response = await client.HttpClient.GetAsync("/connect/checksession");
        var content = await response.Content.ReadAsStringAsync();

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);
        Assert.Contains("custom.browser_state", content, StringComparison.Ordinal);
        Assert.Contains("postMessage", content, StringComparison.Ordinal);
        Assert.Contains("script-src 'nonce-", string.Join(';', response.Headers.GetValues("Content-Security-Policy")), StringComparison.Ordinal);
    }

    [Fact]
    public async Task CheckSessionIframe_PostRequestIsRejected()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.EnableSessionManagement()
                   .SetCheckSessionIframeEndpointUris("/connect/checksession");
        });

        await using var client = await server.CreateClientAsync();

        // Act
        using var response = await client.HttpClient.PostAsync("/connect/checksession", new StringContent(string.Empty));

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task ApplyAuthorizationResponse_SessionStateIsReturnedWhenSessionManagementIsEnabled()
    {
        // Arrange
        string? state = null;

        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.EnableSessionManagement()
                   .SetCheckSessionIframeEndpointUris("/connect/checksession");

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return ValueTask.CompletedTask;
                }));

            options.AddEventHandler<ApplyAuthorizationResponseContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    state = context.Transaction.BrowserState;

                    return ValueTask.CompletedTask;
                });

                builder.SetOrder(Logout.AttachSessionState.Descriptor.Order + 1);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Null(response.Error);
        Assert.NotNull(state);
        Assert.True(OpenIddictServerHelpers.ValidateBrowserState(state, "Bob le Magnifique"));

        var value = (string?) response[Parameters.SessionState];
        Assert.NotNull(value);

        var salt = value[(value.LastIndexOf('.') + 1)..];
        Assert.Equal(OpenIddictServerHelpers.ComputeSessionState("Fabrikam", "http://www.fabrikam.com", state, salt), value);
    }

    [Fact]
    public async Task ApplyAuthorizationResponse_SessionStateIsNotReturnedByDefault()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

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
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Null((string?) response[Parameters.SessionState]);
    }

    [Fact]
    public async Task ProcessSignIn_SessionExpirationIsExtendedWhenIdleTimeoutIsConfigured()
    {
        // Arrange
        var session = new OpenIddictSession();
        var sessions = CreateSessionManager(mock =>
        {
            mock.Setup(manager => manager.FindByIdAsync(LogoutSessionId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(session);
            mock.Setup(manager => manager.HasStatusAsync(session, Statuses.Valid, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);
            mock.Setup(manager => manager.GetCreationDateAsync(session, It.IsAny<CancellationToken>()))
                .ReturnsAsync(DateTimeOffset.UtcNow.AddHours(-1));
            mock.Setup(manager => manager.TryExtendAsync(session, It.IsAny<DateTimeOffset>(),
                It.IsAny<DateTimeOffset?>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(sessions);
            options.SetDeviceAuthorizationEndpointUris(Array.Empty<Uri>());
            options.SetRevocationEndpointUris(Array.Empty<Uri>());
            options.Configure(options => options.GrantTypes.Remove(GrantTypes.DeviceCode));
            options.DisableTokenStorage();
            options.DisableAuthorizationStorage();
            options.DisableSlidingRefreshTokenExpiration();
            options.SetSessionIdleTimeout(TimeSpan.FromMinutes(30));
            options.SetSessionLifetime(TimeSpan.FromHours(8));

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique")
                        .SetSessionId(LogoutSessionId);

                    return ValueTask.CompletedTask;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            GrantType = GrantTypes.Password,
            Username = "johndoe",
            Password = "A3ddj3w"
        });

        // Assert
        Assert.Null(response.Error);
        Mock.Get(sessions).Verify(manager => manager.TryExtendAsync(session, It.IsAny<DateTimeOffset>(),
            It.Is<DateTimeOffset?>(date => date > DateTimeOffset.UtcNow.AddMinutes(25) && date < DateTimeOffset.UtcNow.AddMinutes(35)),
            It.IsAny<CancellationToken>()), Times.Once());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ProcessSignIn_SessionIdIsAddedToAccessTokensWhenEnabled(bool enabled)
    {
        // Arrange
        ClaimsPrincipal? principal = null;

        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            if (enabled)
            {
                options.IncludeSessionIdInAccessTokens();
            }

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique")
                        .SetSessionId(LogoutSessionId);

                    return ValueTask.CompletedTask;
                }));

            options.AddEventHandler<ProcessSignInContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    principal = context.AccessTokenPrincipal;

                    return ValueTask.CompletedTask;
                });

                builder.SetOrder(Logout.AttachAccessTokenSessionId.Descriptor.Order + 1);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            GrantType = GrantTypes.Password,
            Username = "johndoe",
            Password = "A3ddj3w"
        });

        // Assert
        Assert.Null(response.Error);
        Assert.NotNull(principal);
        Assert.Equal(enabled ? LogoutSessionId : null, principal.GetClaim(Claims.SessionId));
    }

    [Fact]
    public async Task ValidateToken_RequestIsRejectedWhenSessionAssociatedWithTokenIsExpired()
    {
        // Arrange
        var session = new OpenIddictSession();

        var manager = CreateSessionManager(mock =>
        {
            mock.Setup(manager => manager.FindByIdAsync("DE7F0AF0-9595-4546-BE3D-F6BB43FB5FA5", It.IsAny<CancellationToken>()))
                .ReturnsAsync(session);

            mock.Setup(manager => manager.HasStatusAsync(session, Statuses.Valid, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.HasExpiredAsync(session, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeIdentifiers.RefreshToken)
                        .SetTokenId("60FFF7EA-F98E-437B-937E-5073CC313103")
                        .SetClaim(Claims.Subject, "Bob le Bricoleur");

                    return ValueTask.CompletedTask;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });

            options.Services.AddSingleton(CreateTokenManager(mock =>
            {
                var token = new OpenIddictToken();

                mock.Setup(manager => manager.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                mock.Setup(manager => manager.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("60FFF7EA-F98E-437B-937E-5073CC313103");

                mock.Setup(manager => manager.GetTypeAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(TokenTypeIdentifiers.RefreshToken);

                mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Redeemed, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);

                mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Valid, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.GetSessionIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("DE7F0AF0-9595-4546-BE3D-F6BB43FB5FA5");
            }));

            options.Services.AddSingleton(manager);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            GrantType = GrantTypes.RefreshToken,
            RefreshToken = "8xLOxBtZp8"
        });

        // Assert
        Assert.Equal(SR.GetResourceString(SR.ID2210), response.ErrorDescription);

        Mock.Get(manager).Verify(manager => manager.HasExpiredAsync(session, It.IsAny<CancellationToken>()), Times.Once());
    }

    private static void ConfigureSignOut(OpenIddictServerBuilder options, string? session = null)
    {
        options.AddEventHandler<HandleEndSessionRequestContext>(builder =>
            builder.UseInlineHandler(context =>
            {
                context.SignOut();

                return ValueTask.CompletedTask;
            }));

        if (session is not null)
        {
            options.AddEventHandler<ProcessSignOutContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    context.Properties[Properties.SessionId] = session;

                    return ValueTask.CompletedTask;
                });

                builder.SetOrder(Logout.TerminateSignOutSession.Descriptor.Order - 100);
            });
        }
    }

    private OpenIddictSessionManager<OpenIddictSession> CreateLogoutSessionManager(
        OpenIddictSession session, string? login,
        Action<Mock<OpenIddictSessionManager<OpenIddictSession>>>? configuration = null)
        => CreateSessionManager(mock =>
        {
            mock.Setup(manager => manager.FindByIdAsync(LogoutSessionId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(session);
            mock.Setup(manager => manager.GetIdAsync(session, It.IsAny<CancellationToken>()))
                .ReturnsAsync(LogoutSessionId);
            mock.Setup(manager => manager.GetLoginIdAsync(session, It.IsAny<CancellationToken>()))
                .ReturnsAsync(login);
            mock.Setup(manager => manager.GetSubjectAsync(session, It.IsAny<CancellationToken>()))
                .ReturnsAsync("Bob le Bricoleur");
            mock.Setup(manager => manager.GetApplicationIdAsync(session, It.IsAny<CancellationToken>()))
                .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A57");
            mock.Setup(manager => manager.HasStatusAsync(session, Statuses.Valid, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);
            mock.Setup(manager => manager.TryRevokeAsync(It.IsAny<OpenIddictSession>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            configuration?.Invoke(mock);
        });

    private OpenIddictApplicationManager<OpenIddictApplication> CreateLogoutApplicationManager(
        Dictionary<string, string> settings)
        => CreateApplicationManager(mock =>
        {
            var application = new OpenIddictApplication();

            mock.Setup(manager => manager.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A57", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);
            mock.Setup(manager => manager.GetClientIdAsync(application, It.IsAny<CancellationToken>()))
                .ReturnsAsync("Fabrikam");
            mock.Setup(manager => manager.GetSettingsAsync(application, It.IsAny<CancellationToken>()))
                .ReturnsAsync(settings.ToImmutableDictionary(StringComparer.Ordinal));
            mock.Setup(manager => manager.FindByPostLogoutRedirectUriAsync("http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                .Returns(new[] { application }.ToAsyncEnumerable());
            mock.Setup(manager => manager.ValidatePostLogoutRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);
        });
}
