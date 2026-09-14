using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;

namespace OpenIddict.Client.AspNetCore.Bff.Tests;

public class OpenIddictClientAspNetCoreBffEndpointTests
{
    [Fact]
    public async Task UserEndpoint_MissingAntiforgeryHeaderIsRejected()
    {
        // Arrange
        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync();
        var cookie = await host.SignInAsync(expiration: DateTimeOffset.UtcNow.AddHours(1));

        // Act
        using var response = await host.SendAsync(HttpMethod.Get, "/bff/user", cookie);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
    }

    [Fact]
    public async Task UserEndpoint_InvalidAntiforgeryHeaderValueIsRejected()
    {
        // Arrange
        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync();
        var cookie = await host.SignInAsync(expiration: DateTimeOffset.UtcNow.AddHours(1));

        using var request = new HttpRequestMessage(HttpMethod.Get, "/bff/user");
        request.Headers.Add("Cookie", cookie);
        request.Headers.Add("X-CSRF", "0");

        // Act
        using var response = await host.Client.SendAsync(request);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task UserEndpoint_CustomAntiforgeryHeaderIsHonored()
    {
        // Arrange
        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync(
            bff: options => options.SetAntiforgeryHeader("X-Requested-With", "fetch"));

        var cookie = await host.SignInAsync(expiration: DateTimeOffset.UtcNow.AddHours(1));

        using var request = new HttpRequestMessage(HttpMethod.Get, "/bff/user");
        request.Headers.Add("Cookie", cookie);
        request.Headers.Add("X-Requested-With", "fetch");

        // Act
        using var response = await host.Client.SendAsync(request);
        using var legacy = await host.SendAsync(HttpMethod.Get, "/bff/user", cookie, antiforgery: true);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, legacy.StatusCode);
    }

    [Fact]
    public async Task UserEndpoint_AnonymousRequestIsRejected()
    {
        // Arrange
        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync();

        // Act
        using var response = await host.SendAsync(HttpMethod.Get, "/bff/user", cookie: null, antiforgery: true);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task UserEndpoint_ClaimsAndLogoutUrlAreReturned()
    {
        // Arrange
        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync();
        var cookie = await host.SignInAsync(expiration: DateTimeOffset.UtcNow.AddHours(1));

        // Act
        using var response = await host.SendAsync(HttpMethod.Get, "/bff/user", cookie, antiforgery: true);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var claims = document.RootElement.EnumerateArray().ToDictionary(
            static claim => claim.GetProperty("type").GetString()!,
            static claim => claim.GetProperty("value").GetString(), StringComparer.Ordinal);

        Assert.Equal("Bob", claims[Claims.Subject]);
        Assert.Equal("/bff/logout?sid=session", claims[OpenIddictClientAspNetCoreBffConstants.Claims.LogoutUrl]);

        // Tokens must never be returned to the browser.
        Assert.DoesNotContain(claims.Values, static value => value is "old_access_token" or "old_refresh_token");
    }

    [Fact]
    public async Task ApiEndpoint_AntiforgeryHeaderIsRequired()
    {
        // Arrange
        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync(endpoints: routes =>
        {
            routes.MapGet("/api/data", static () => "data").AsOpenIddictBffApiEndpoint();
            routes.MapGet("/api/unprotected", static () => "data").AsOpenIddictBffApiEndpoint(disableAntiforgeryCheck: true);
        });

        // Act
        using var missing = await host.SendAsync(HttpMethod.Get, "/api/data", cookie: null);
        using var valid = await host.SendAsync(HttpMethod.Get, "/api/data", cookie: null, antiforgery: true);
        using var unprotected = await host.SendAsync(HttpMethod.Get, "/api/unprotected", cookie: null);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, missing.StatusCode);
        Assert.Equal(HttpStatusCode.OK, valid.StatusCode);
        Assert.Equal(HttpStatusCode.OK, unprotected.StatusCode);
    }

    [Fact]
    public async Task ApiEndpoint_AntiforgeryHeaderIsRequiredWhenTheMiddlewareIsNotRegistered()
    {
        // Arrange
        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync(endpoints: routes =>
        {
            routes.MapGet("/api/data", static () => "data").AsOpenIddictBffApiEndpoint();
            routes.MapGet("/api/unprotected", static () => "data").AsOpenIddictBffApiEndpoint(disableAntiforgeryCheck: true);
        }, middleware: false);

        // Act
        using var missing = await host.SendAsync(HttpMethod.Get, "/api/data", cookie: null);
        using var valid = await host.SendAsync(HttpMethod.Get, "/api/data", cookie: null, antiforgery: true);
        using var unprotected = await host.SendAsync(HttpMethod.Get, "/api/unprotected", cookie: null);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, missing.StatusCode);
        Assert.Equal(HttpStatusCode.OK, valid.StatusCode);
        Assert.Equal(HttpStatusCode.OK, unprotected.StatusCode);
    }

    [Fact]
    public async Task ApiEndpoint_UnauthenticatedRequestReturns401InsteadOfRedirecting()
    {
        // Arrange
        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync(endpoints: routes =>
        {
            routes.MapGet("/api/secure", static () => "data").RequireAuthorization().AsOpenIddictBffApiEndpoint();
            routes.MapGet("/page", static () => "data").RequireAuthorization();
        });

        // Act
        using var api = await host.SendAsync(HttpMethod.Get, "/api/secure", cookie: null, antiforgery: true);
        using var page = await host.SendAsync(HttpMethod.Get, "/page", cookie: null);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, api.StatusCode);
        Assert.Equal(HttpStatusCode.Redirect, page.StatusCode);
    }

    [Fact]
    public async Task LoginEndpoint_UserAgentIsRedirectedToTheAuthorizationEndpoint()
    {
        // Arrange
        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync();

        // Act
        using var response = await host.SendAsync(HttpMethod.Get, "/bff/login?provider=Contoso&returnUrl=%2Fapp", cookie: null);

        // Assert
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);

        var location = response.Headers.Location!;
        Assert.Equal("https://contoso.com/connect/authorize", location.GetLeftPart(UriPartial.Path));

        var parameters = QueryHelpers.ParseQuery(location.Query);
        Assert.Equal("Fabrikam", parameters[Parameters.ClientId]);
        Assert.Equal("http://localhost/bff/callback/login", parameters[Parameters.RedirectUri]);
    }

    [Fact]
    public async Task LoginCallbackEndpoint_UserIsSignedInWithTheReturnedTokens()
    {
        // Arrange
        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync(endpoints: routes =>
            routes.MapGet("/test/token_type", static async (HttpContext context, OpenIddictClientAspNetCoreBffTokenManager manager) =>
                (await manager.GetUserAccessTokenAsync(context))?.TokenType));

        using var challenge = await host.SendAsync(HttpMethod.Get, "/bff/login?returnUrl=%2Fapp", cookie: null);
        Assert.Equal(HttpStatusCode.Redirect, challenge.StatusCode);

        var parameters = QueryHelpers.ParseQuery(challenge.Headers.Location!.Query);

        host.Endpoint.Handler = request =>
        {
            Assert.Equal(GrantTypes.AuthorizationCode, request.GrantType);
            Assert.Equal("authorization_code", request.Code);

            var now = DateTime.UtcNow;

            return Task.FromResult(new OpenIddictResponse
            {
                AccessToken = "access_token",
                ExpiresIn = 3600,
                IdToken = parameters.TryGetValue(Parameters.Nonce, out var nonce) ? new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
                {
                    Audience = "Fabrikam",
                    Claims = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        [Claims.Nonce] = nonce.ToString(),
                        [Claims.SessionId] = "session",
                        [Claims.Subject] = "Bob"
                    },
                    Expires = now.AddMinutes(5),
                    IssuedAt = now,
                    Issuer = OpenIddictClientAspNetCoreBffTestHost.Issuer.AbsoluteUri,
                    SigningCredentials = new SigningCredentials(host.SigningKey, SecurityAlgorithms.RsaSha256)
                }) : null,
                RefreshToken = "refresh_token",
                TokenType = TokenTypes.Bearer
            });
        };

        using var callback = new HttpRequestMessage(HttpMethod.Get, "/bff/callback/login?code=authorization_code&state=" +
            Uri.EscapeDataString(parameters[Parameters.State]!));

        foreach (var value in challenge.Headers.GetValues("Set-Cookie"))
        {
            callback.Headers.Add("Cookie", value.Split(';')[0]);
        }

        // Act
        using var response = await host.Client.SendAsync(callback);

        // Assert
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/app", response.Headers.Location?.OriginalString);

        var cookie = OpenIddictClientAspNetCoreBffTestHost.GetCookie(response);
        Assert.NotNull(cookie);

        using var token = await host.SendAsync(HttpMethod.Get, "/test/token", cookie);
        using var type = await host.SendAsync(HttpMethod.Get, "/test/token_type", cookie);
        using var refresh = await host.SendAsync(HttpMethod.Get, "/test/refresh_token", cookie);
        using var user = await host.SendAsync(HttpMethod.Get, "/bff/user", cookie, antiforgery: true);

        Assert.Equal("access_token", await token.Content.ReadAsStringAsync());
        Assert.Equal(TokenTypes.Bearer, await type.Content.ReadAsStringAsync());
        Assert.Equal("refresh_token", await refresh.Content.ReadAsStringAsync());

        using var document = JsonDocument.Parse(await user.Content.ReadAsStringAsync());
        var claims = document.RootElement.EnumerateArray().ToDictionary(
            static claim => claim.GetProperty("type").GetString()!,
            static claim => claim.GetProperty("value").GetString(), StringComparer.Ordinal);

        Assert.Equal("Bob", claims[Claims.Subject]);
        Assert.Equal("Contoso", claims[Claims.Private.RegistrationId]);
    }

    [Theory]
    [InlineData("/bff/login?returnUrl=https%3A%2F%2Fevil.com")]
    [InlineData("/bff/login?returnUrl=%2F%2Fevil.com")]
    [InlineData("/bff/login?returnUrl=%2F%5Cevil.com")]
    [InlineData("/bff/login?provider=Unknown")]
    [InlineData("/bff/logout?returnUrl=https%3A%2F%2Fevil.com")]
    public async Task Endpoints_InvalidParametersAreRejected(string uri)
    {
        // Arrange
        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync();

        // Act
        using var response = await host.SendAsync(HttpMethod.Get, uri, cookie: null);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task LogoutEndpoint_SessionIdentifierIsRequired()
    {
        // Arrange
        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync();
        var cookie = await host.SignInAsync(expiration: DateTimeOffset.UtcNow.AddHours(1));

        // Act
        using var missing = await host.SendAsync(HttpMethod.Get, "/bff/logout", cookie);
        using var invalid = await host.SendAsync(HttpMethod.Get, "/bff/logout?sid=other", cookie);
        using var valid = await host.SendAsync(HttpMethod.Get, "/bff/logout?sid=session&returnUrl=%2Fbye", cookie);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, missing.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);

        Assert.Equal(HttpStatusCode.Redirect, valid.StatusCode);
        Assert.Equal("/bye", valid.Headers.Location?.OriginalString);
        Assert.Contains(valid.Headers.GetValues("Set-Cookie"), static value =>
            value.StartsWith(".AspNetCore.Cookies=;", StringComparison.Ordinal));
    }

    [Fact]
    public async Task BackchannelLogoutEndpoint_MatchingSessionsAreRemovedFromTheSessionStore()
    {
        // Arrange
        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync(
            bff: options => options.UseInMemorySessionStore());

        var store = host.Services.GetRequiredService<OpenIddictClientAspNetCoreBffMemorySessionStore>();
        var cookie = await host.SignInAsync(expiration: DateTimeOffset.UtcNow.AddHours(1));

        Assert.Equal(1, store.Count);

        // Act
        using var response = await SendLogoutTokenAsync(host, CreateLogoutToken(host, sid: "session"));
        using var token = await host.SendAsync(HttpMethod.Get, "/test/token", cookie);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(0, store.Count);
        Assert.Equal(HttpStatusCode.Unauthorized, token.StatusCode);
    }

    [Fact]
    public async Task BackchannelLogoutEndpoint_NonMatchingSessionsAreKept()
    {
        // Arrange
        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync(
            bff: options => options.UseInMemorySessionStore());

        var store = host.Services.GetRequiredService<OpenIddictClientAspNetCoreBffMemorySessionStore>();
        await host.SignInAsync(expiration: DateTimeOffset.UtcNow.AddHours(1));

        // Act
        using var response = await SendLogoutTokenAsync(host, CreateLogoutToken(host, sub: "Alice"));

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, store.Count);
    }

    [Fact]
    public async Task BackchannelLogoutEndpoint_CustomHandlersAreInvoked()
    {
        // Arrange
        var handler = new RecordingLogoutHandler();

        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync(services: services =>
            services.AddSingleton<IOpenIddictClientAspNetCoreBffBackchannelLogoutHandler>(handler));

        // Act
        using var response = await SendLogoutTokenAsync(host, CreateLogoutToken(host, sub: "Bob", sid: "session"));

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var notification = Assert.Single(handler.Notifications);
        Assert.Equal("Bob", notification.Subject);
        Assert.Equal("session", notification.SessionId);
        Assert.Equal("Contoso", notification.Registration.RegistrationId);
    }

    public static IEnumerable<object[]> InvalidLogoutTokens =>
    [
        ["missing_events"],
        ["nonce"],
        ["no_subject"],
        ["wrong_audience"],
        ["wrong_key"],
        ["expired"],
        ["replayed"],
        ["not_a_jwt"],
        ["malformed"],
        ["unsigned"],
        ["stale_iat_without_exp"],
        ["future_iat"],
        ["future_nbf"]
    ];

    [Theory]
    [MemberData(nameof(InvalidLogoutTokens))]
    public async Task BackchannelLogoutEndpoint_InvalidLogoutTokensAreRejected(string scenario)
    {
        // Arrange
        var handler = new RecordingLogoutHandler();

        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync(services: services =>
            services.AddSingleton<IOpenIddictClientAspNetCoreBffBackchannelLogoutHandler>(handler));

        var token = scenario switch
        {
            "missing_events" => CreateLogoutToken(host, sid: "session", events: false),
            "nonce" => CreateLogoutToken(host, sid: "session", nonce: true),
            "no_subject" => CreateLogoutToken(host),
            "wrong_audience" => CreateLogoutToken(host, sid: "session", audience: "Other"),
            "wrong_key" => CreateLogoutToken(host, sid: "session", key: new RsaSecurityKey(System.Security.Cryptography.RSA.Create(2048))),
            "expired" => CreateLogoutToken(host, sid: "session", expiration: DateTime.UtcNow.AddMinutes(-5)),
            "replayed" => CreateLogoutToken(host, sid: "session", identifier: "replayed"),
            "malformed" => "abc.def.ghi",
            "unsigned" => CreateLogoutToken(host, sid: "session", unsigned: true),
            "stale_iat_without_exp" => CreateLogoutToken(host, sid: "session", expires: false, issuedAt: DateTime.UtcNow.AddHours(-1)),
            "future_iat" => CreateLogoutToken(host, sid: "session", expires: false, issuedAt: DateTime.UtcNow.AddHours(1)),
            "future_nbf" => CreateLogoutToken(host, sid: "session", expiration: DateTime.UtcNow.AddHours(1), issuedAt: DateTime.UtcNow, notBefore: DateTime.UtcNow.AddMinutes(30)),
            _ => "not_a_jwt"
        };

        if (scenario is "replayed")
        {
            using var first = await SendLogoutTokenAsync(host, token);
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
            handler.Notifications.Clear();
        }

        // Act
        using var response = await SendLogoutTokenAsync(host, token);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(Errors.InvalidRequest, document.RootElement.GetProperty(Parameters.Error).GetString());
        Assert.Empty(handler.Notifications);
    }

    [Fact]
    public async Task BackchannelLogoutEndpoint_RecentLogoutTokenWithoutExpirationIsAcceptedOnce()
    {
        // Arrange
        var handler = new RecordingLogoutHandler();

        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync(services: services =>
            services.AddSingleton<IOpenIddictClientAspNetCoreBffBackchannelLogoutHandler>(handler));

        var token = CreateLogoutToken(host, sid: "session", expires: false, issuedAt: DateTime.UtcNow.AddMinutes(-1));

        // Act
        using var first = await SendLogoutTokenAsync(host, token);
        using var second = await SendLogoutTokenAsync(host, token);

        // Assert
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, second.StatusCode);
        Assert.Single(handler.Notifications);
    }

    [Fact]
    public async Task BackchannelLogoutEndpoint_MissingLogoutTokenIsRejected()
    {
        // Arrange
        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync();

        // Act
        using var response = await host.Client.PostAsync("/bff/backchannel-logout", new FormUrlEncodedContent([]));

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(SR.GetResourceString(SR.ID2239), document.RootElement.GetProperty(Parameters.ErrorDescription).GetString());
    }

    [Fact]
    public async Task AccessTokenHandler_UserAccessTokenIsAttached()
    {
        // Arrange
        var backend = new RecordingHandler();

        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync(
            services: services => services.AddHttpClient("api")
                .AddOpenIddictBffUserAccessTokenHandler()
                .ConfigurePrimaryHttpMessageHandler(() => backend),
            endpoints: routes => routes.MapGet("/test/call", static async (HttpContext context, IHttpClientFactory factory) =>
            {
                using var client = factory.CreateClient("api");
                using var response = await client.GetAsync(new Uri("https://api.contoso.com/resource"));
                return (int) response.StatusCode;
            }));

        var cookie = await host.SignInAsync(expiration: DateTimeOffset.UtcNow.AddSeconds(10));

        // Act
        using var response = await host.SendAsync(HttpMethod.Get, "/test/call", cookie);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // The access token was about to expire and must have been refreshed before being attached.
        var request = Assert.Single(backend.Requests);
        Assert.Equal(new AuthenticationHeaderValue(Schemes.Bearer, "new_access_token"), request.Authorization);
    }

    [Fact]
    public async Task AccessTokenHandler_ClientAccessTokenIsAttachedAndCached()
    {
        // Arrange
        var backend = new RecordingHandler();

        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync(
            services: services => services.AddHttpClient("api")
                .AddOpenIddictBffClientAccessTokenHandler(new() { Scopes = ["api"] })
                .ConfigurePrimaryHttpMessageHandler(() => backend));

        var factory = host.Services.GetRequiredService<IHttpClientFactory>();

        // Act
        for (var index = 0; index < 3; index++)
        {
            using var client = factory.CreateClient("api");
            using var response = await client.GetAsync(new Uri("https://api.contoso.com/resource"));
        }

        // Assert
        Assert.Equal(3, backend.Requests.Count);
        Assert.All(backend.Requests, static request =>
            Assert.Equal(new AuthenticationHeaderValue(Schemes.Bearer, "new_access_token"), request.Authorization));

        var token = Assert.Single(host.Endpoint.Requests);
        Assert.Equal(GrantTypes.ClientCredentials, token.GrantType);
        Assert.Equal("api", token.Scope);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ReverseProxy_UserAccessTokenIsAttachedAndCookiesAreRemoved(bool middleware)
    {
        // Arrange
        var backend = new RecordingHandler();

        await using var host = await OpenIddictClientAspNetCoreBffTestHost.CreateAsync(
            services: services =>
            {
                services.AddSingleton<IForwarderHttpClientFactory>(new RecordingForwarderFactory(backend));
                services.AddReverseProxy()
                    .LoadFromMemory(
                        [
                            new RouteConfig
                            {
                                RouteId = "user",
                                ClusterId = "api",
                                Match = new RouteMatch { Path = "/proxy/user/{**catch-all}" },
                                Metadata = new Dictionary<string, string>(StringComparer.Ordinal)
                                {
                                    [OpenIddictClientAspNetCoreBffConstants.Metadata.AccessToken] = nameof(OpenIddictClientAspNetCoreBffTokenType.User)
                                }
                            },
                            new RouteConfig
                            {
                                RouteId = "anonymous",
                                ClusterId = "api",
                                Match = new RouteMatch { Path = "/proxy/anonymous/{**catch-all}" }
                            }
                        ],
                        [
                            new ClusterConfig
                            {
                                ClusterId = "api",
                                Destinations = new Dictionary<string, DestinationConfig>(StringComparer.Ordinal)
                                {
                                    ["api"] = new DestinationConfig { Address = "https://api.contoso.com/" }
                                }
                            }
                        ])
                    .AddOpenIddictBffTransforms();
            },
            endpoints: routes => routes.MapReverseProxy(),
            middleware: middleware);

        var cookie = await host.SignInAsync(expiration: DateTimeOffset.UtcNow.AddHours(1));
        var tokenless = await host.SignInAsync(accessToken: null, refreshToken: null);

        // Act
        using var missing = await host.SendAsync(HttpMethod.Get, "/proxy/user/resource", cookie);
        using var anonymous = await host.SendAsync(HttpMethod.Get, "/proxy/user/resource", cookie: null, antiforgery: true);
        using var unavailable = await host.SendAsync(HttpMethod.Get, "/proxy/user/resource", tokenless, antiforgery: true);
        using var response = await host.SendAsync(HttpMethod.Get, "/proxy/user/resource?value=1", cookie, antiforgery: true);
        using var other = await host.SendAsync(HttpMethod.Get, "/proxy/anonymous/resource", cookie);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, missing.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, unavailable.StatusCode);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(HttpStatusCode.OK, other.StatusCode);

        Assert.Equal(2, backend.Requests.Count);

        var proxied = backend.Requests[0];
        Assert.Equal("https://api.contoso.com/proxy/user/resource?value=1", proxied.Uri);
        Assert.Equal(new AuthenticationHeaderValue(Schemes.Bearer, "old_access_token"), proxied.Authorization);
        Assert.False(proxied.HasCookies);

        // Routes without the BFF metadata are not affected by the BFF transforms.
        Assert.Null(backend.Requests[1].Authorization);
        Assert.True(backend.Requests[1].HasCookies);
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/path?query=value")]
    [InlineData("~/path")]
    public void IsLocalUrl_LocalUrlsAreAccepted(string url)
        => Assert.True(IsLocalUrl(url));

    [Theory]
    [InlineData("")]
    [InlineData("//evil.com")]
    [InlineData("/\\evil.com")]
    [InlineData("~//evil.com")]
    [InlineData("https://evil.com/")]
    [InlineData("/path\r\nLocation: https://evil.com")]
    public void IsLocalUrl_NonLocalUrlsAreRejected(string url)
        => Assert.False(IsLocalUrl(url));

    private static bool IsLocalUrl(string url)
        => (bool) typeof(OpenIddictClientAspNetCoreBffHelpers)
            .GetMethod("IsLocalUrl", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!
            .Invoke(obj: null, [url])!;

    private static string CreateLogoutToken(OpenIddictClientAspNetCoreBffTestHost host, string? sub = null, string? sid = null,
        bool events = true, bool nonce = false, string audience = "Fabrikam", SecurityKey? key = null,
        DateTime? expiration = null, string? identifier = null, bool unsigned = false, bool expires = true, DateTime? issuedAt = null, DateTime? notBefore = null)
    {
        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [Claims.JwtId] = identifier ?? Guid.NewGuid().ToString()
        };

        if (sub is not null)
        {
            claims[Claims.Subject] = sub;
        }

        if (sid is not null)
        {
            claims[Claims.SessionId] = sid;
        }

        if (events)
        {
            claims[Claims.Events] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [OpenIddictClientAspNetCoreBffConstants.Events.BackchannelLogout] = new Dictionary<string, object>(StringComparer.Ordinal)
            };
        }

        if (nonce)
        {
            claims[Claims.Nonce] = "nonce";
        }

        var now = DateTime.UtcNow;

        return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = expires }.CreateToken(new SecurityTokenDescriptor
        {
            Audience = audience,
            Claims = claims,
            Expires = expires ? expiration ?? now.AddMinutes(2) : null,
            IssuedAt = issuedAt ?? (expiration ?? now.AddMinutes(2)).AddMinutes(-2),
            NotBefore = notBefore ?? (expires ? (expiration ?? now.AddMinutes(2)).AddMinutes(-2) : null),
            Issuer = OpenIddictClientAspNetCoreBffTestHost.Issuer.AbsoluteUri,
            SigningCredentials = unsigned ? null : new SigningCredentials(key ?? host.SigningKey, SecurityAlgorithms.RsaSha256),
            TokenType = JsonWebTokenTypes.LogoutToken
        });
    }

    private static Task<HttpResponseMessage> SendLogoutTokenAsync(OpenIddictClientAspNetCoreBffTestHost host, string token)
        => host.Client.PostAsync("/bff/backchannel-logout", new FormUrlEncodedContent(
            [new KeyValuePair<string, string>(Parameters.LogoutToken, token)]));

    private sealed class RecordingLogoutHandler : IOpenIddictClientAspNetCoreBffBackchannelLogoutHandler
    {
        public List<OpenIddictClientAspNetCoreBffModels.BackchannelLogoutNotification> Notifications { get; } = [];

        public ValueTask HandleAsync(OpenIddictClientAspNetCoreBffModels.BackchannelLogoutNotification notification, CancellationToken cancellationToken)
        {
            Notifications.Add(notification);
            return ValueTask.CompletedTask;
        }
    }

    private sealed record class RecordedRequest(string Uri, AuthenticationHeaderValue? Authorization, bool HasCookies);

    private sealed class RecordingHandler : HttpMessageHandler
    {
        public List<RecordedRequest> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            lock (Requests)
            {
                Requests.Add(new RecordedRequest(request.RequestUri!.AbsoluteUri, request.Headers.Authorization,
                    request.Headers.Contains("Cookie")));
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("ok") });
        }
    }

    private sealed class RecordingForwarderFactory(HttpMessageHandler handler) : IForwarderHttpClientFactory
    {
        public HttpMessageInvoker CreateClient(ForwarderHttpClientContext context) => new(handler, disposeHandler: false);
    }
}
