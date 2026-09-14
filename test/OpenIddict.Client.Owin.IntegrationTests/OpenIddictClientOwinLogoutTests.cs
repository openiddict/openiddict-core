/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Testing;
using Owin;
using Xunit;
using static OpenIddict.Client.OpenIddictClientEvents;
using Properties = OpenIddict.Client.Owin.OpenIddictClientOwinConstants.Properties;

namespace OpenIddict.Client.Owin.IntegrationTests;

public class OpenIddictClientOwinLogoutTests
{
    private static readonly Uri Issuer = new("https://contoso.com/", UriKind.Absolute);
    private static readonly RsaSecurityKey SigningKey = new(RSA.Create()) { KeyId = "key" };

    [Fact]
    public async Task BackchannelLogout_ValidLogoutTokenRemovesMatchingSessions()
    {
        // Arrange
        var store = new TestSessionStore();
        using var server = CreateServer(services => services.AddOpenIddict().AddClient().AddSessionStore(store));
        using var client = server.HttpClient;

        // Act
        using var response = await client.PostAsync("/backchannel-logout", new FormUrlEncodedContent(
            [new KeyValuePair<string, string>(Parameters.LogoutToken, CreateLogoutToken(sub: "Bob", sid: "session"))]));

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.CacheControl is { NoStore: true });
        Assert.Equal(("Contoso", "Bob", "session"), Assert.Single(store.Calls));
    }

    [Theory]
    [InlineData("nonce")]
    [InlineData("missing")]
    [InlineData("get")]
    public async Task BackchannelLogout_InvalidRequestsAreRejected(string scenario)
    {
        // Arrange
        var store = new TestSessionStore();
        using var server = CreateServer(services => services.AddOpenIddict().AddClient().AddSessionStore(store));
        using var client = server.HttpClient;

        var token = CreateLogoutToken(sid: "session", nonce: scenario is "nonce" ? "nonce" : null);

        // Act
        using var response = scenario is "get"
            ? await client.GetAsync("/backchannel-logout?logout_token=" + token)
            : await client.PostAsync("/backchannel-logout", new FormUrlEncodedContent(scenario is "missing" ?
                [] : [new KeyValuePair<string, string>(Parameters.LogoutToken, token)]));

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(Errors.InvalidRequest, document.RootElement.GetProperty(Parameters.Error).GetString());
        Assert.Empty(store.Calls);
    }

    [Fact]
    public async Task BackchannelLogout_FailedSessionRemovalReturnsBadRequestAndAllowsRetries()
    {
        // Arrange
        var store = new TestSessionStore { Failures = 1 };
        using var server = CreateServer(services => services.AddOpenIddict().AddClient().AddSessionStore(store));
        using var client = server.HttpClient;

        var token = CreateLogoutToken(sub: "Bob", sid: "session");

        // Act
        using var failure = await client.PostAsync("/backchannel-logout", new FormUrlEncodedContent(
            [new KeyValuePair<string, string>(Parameters.LogoutToken, token)]));

        using var response = await client.PostAsync("/backchannel-logout", new FormUrlEncodedContent(
            [new KeyValuePair<string, string>(Parameters.LogoutToken, token)]));

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, failure.StatusCode);

        using (var document = JsonDocument.Parse(await failure.Content.ReadAsStringAsync()))
        {
            Assert.Equal(Errors.ServerError, document.RootElement.GetProperty(Parameters.Error).GetString());
        }

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(2, store.Calls.Count);
    }

    [Fact]
    public async Task BackchannelLogout_MissingSessionStoreIsRejectedWhenOptionsAreValidated()
    {
        // Act and assert
        var exception = await Assert.ThrowsAsync<OptionsValidationException>(async () =>
        {
            using var server = CreateServer(
                configuration: options => options.SetFrontchannelLogoutSignOutAuthenticationType(CookieAuthenticationDefaults.AuthenticationType),
                defaults: false);

            using var client = server.HttpClient;
            using var response = await client.PostAsync("/backchannel-logout", new FormUrlEncodedContent(
                [new KeyValuePair<string, string>(Parameters.LogoutToken, CreateLogoutToken(sid: "session"))]));
        });

        Assert.Contains(SR.GetResourceString(SR.ID0760), exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task FrontchannelLogout_EndpointThatCannotTerminateSessionsIsRejectedWhenOptionsAreValidated()
    {
        // Act and assert
        var exception = await Assert.ThrowsAsync<OptionsValidationException>(async () =>
        {
            using var server = CreateServer(
                services => services.AddOpenIddict().AddClient().AddSessionStore(new TestSessionStore()),
                defaults: false);

            using var client = server.HttpClient;
            using var response = await client.GetAsync($"/frontchannel-logout?iss={Uri.EscapeDataString(Issuer.AbsoluteUri)}&sid=session");
        });

        Assert.Contains(SR.GetResourceString(SR.ID0766), exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task BackchannelLogout_PassthroughModeExposesTheMergedPrincipal()
    {
        // Arrange
        using var server = CreateServer(configuration: options => options.EnableBackchannelLogoutEndpointPassthrough());
        using var client = server.HttpClient;

        // Act
        using var response = await client.PostAsync("/backchannel-logout", new FormUrlEncodedContent(
            [new KeyValuePair<string, string>(Parameters.LogoutToken, CreateLogoutToken(sub: "Bob", sid: "session"))]));

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("passthrough|Bob|session|Contoso", await response.Content.ReadAsStringAsync());
    }

    [Theory]
    [InlineData("session", true)]
    [InlineData("other_session", false)]
    public async Task FrontchannelLogout_OnlyMatchingSessionIsSignedOut(string session, bool expected)
    {
        // Arrange
        var store = new TestSessionStore();
        using var server = CreateServer(
            services => services.AddOpenIddict().AddClient().AddSessionStore(store),
            options => options.SetFrontchannelLogoutSignOutAuthenticationType(CookieAuthenticationDefaults.AuthenticationType));

        using var client = server.HttpClient;

        using var signin = await client.GetAsync("/signin?sid=" + session);
        var cookie = signin.Headers.GetValues("Set-Cookie").First().Split(';')[0];

        using var request = new HttpRequestMessage(HttpMethod.Get,
            $"/frontchannel-logout?iss={Uri.EscapeDataString(Issuer.AbsoluteUri)}&sid=session");
        request.Headers.Add("Cookie", cookie);

        // Act
        using var response = await client.SendAsync(request);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.CacheControl is { NoCache: true, NoStore: true });
        Assert.Equal(expected, response.Headers.TryGetValues("Set-Cookie", out var values) &&
            values.Any(static value => value.Contains("1970", StringComparison.Ordinal)));
        Assert.Equal(expected ? 1 : 0, store.Calls.Count);
    }

    [Fact]
    public async Task FrontchannelLogout_ForgedRequestWithoutSessionDoesNotReachSessionStores()
    {
        // Arrange
        var store = new TestSessionStore();
        using var server = CreateServer(
            services => services.AddOpenIddict().AddClient().AddSessionStore(store),
            options => options.SetFrontchannelLogoutSignOutAuthenticationType(CookieAuthenticationDefaults.AuthenticationType));

        using var client = server.HttpClient;

        // Act
        using var response = await client.GetAsync($"/frontchannel-logout?iss={Uri.EscapeDataString(Issuer.AbsoluteUri)}&sid=session");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.CacheControl is { NoCache: true, NoStore: true });
        Assert.Empty(store.Calls);
    }

    [Theory]
    [InlineData("?sid=session")]
    [InlineData("?iss=https%3A%2F%2Ffabrikam.com%2F&sid=session")]
    [InlineData("")]
    public async Task FrontchannelLogout_InvalidRequestsAreRejected(string query)
    {
        // Arrange
        using var server = CreateServer();
        using var client = server.HttpClient;

        // Act
        using var response = await client.GetAsync("/frontchannel-logout" + query);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Redirection_SessionStateIsExposedInAuthenticationProperties()
    {
        // Arrange
        using var server = CreateServer();
        using var client = server.HttpClient;

        using var challenge = await client.GetAsync("/challenge");
        Assert.Equal(HttpStatusCode.Redirect, challenge.StatusCode);

        var state = challenge.Headers.Location!.Query.TrimStart('?').Split('&')
            .Select(static parameter => parameter.Split('='))
            .Single(static parts => parts[0] is Parameters.State)[1];

        using var request = new HttpRequestMessage(HttpMethod.Get,
            "/callback?code=authorization_code&session_state=state_value&state=" + state);

        foreach (var cookie in challenge.Headers.GetValues("Set-Cookie"))
        {
            request.Headers.Add("Cookie", cookie.Split(';')[0]);
        }

        // Act
        using var callback = await client.SendAsync(request);

        // Assert
        Assert.Equal("state_value", await callback.Content.ReadAsStringAsync());
    }

    private static string CreateLogoutToken(string? sub = null, string? sid = null, string? nonce = null)
    {
        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [Claims.Events] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["http://schemas.openid.net/event/backchannel-logout"] = new Dictionary<string, object>(StringComparer.Ordinal)
            },
            [Claims.JwtId] = Guid.NewGuid().ToString()
        };

        if (sub is not null)
        {
            claims[Claims.Subject] = sub;
        }

        if (sid is not null)
        {
            claims[Claims.SessionId] = sid;
        }

        if (nonce is not null)
        {
            claims[Claims.Nonce] = nonce;
        }

        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Audience = "Fabrikam",
            Claims = claims,
            Expires = DateTime.UtcNow.AddMinutes(2),
            IssuedAt = DateTime.UtcNow,
            Issuer = Issuer.AbsoluteUri,
            SigningCredentials = new SigningCredentials(SigningKey, SecurityAlgorithms.RsaSha256),
            TokenType = JsonWebTokenTypes.LogoutToken
        });
    }

    private static TestServer CreateServer(
        Action<IServiceCollection>? configure = null,
        Action<OpenIddictClientOwinBuilder>? configuration = null,
        bool defaults = true)
    {
        var services = new ServiceCollection();
        services.AddLogging();

        services.AddOpenIddict()
            .AddClient(options =>
            {
                options.AllowAuthorizationCodeFlow();
                options.DisableTokenStorage();
                options.SetRedirectionEndpointUris("callback");

                options.AddEphemeralEncryptionKey()
                       .AddEphemeralSigningKey();

                var registration = new OpenIddictClientRegistration
                {
                    BackchannelLogoutUri = new Uri("backchannel-logout", UriKind.Relative),
                    ClientId = "Fabrikam",
                    ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                    Configuration = new OpenIddictConfiguration
                    {
                        AuthorizationEndpoint = new Uri("https://contoso.com/connect/authorize", UriKind.Absolute),
                        CodeChallengeMethodsSupported = { CodeChallengeMethods.Sha256 },
                        GrantTypesSupported = { GrantTypes.AuthorizationCode },
                        Issuer = Issuer,
                        ResponseModesSupported = { ResponseModes.Query },
                        ResponseTypesSupported = { ResponseTypes.Code },
                        TokenEndpoint = new Uri("https://contoso.com/connect/token", UriKind.Absolute),
                        TokenEndpointAuthMethodsSupported = { ClientAuthenticationMethods.ClientSecretPost }
                    },
                    FrontchannelLogoutUri = new Uri("frontchannel-logout", UriKind.Relative),
                    Issuer = Issuer,
                    ProviderName = "Contoso",
                    RedirectUri = new Uri("callback", UriKind.Relative),
                    RegistrationId = "Contoso"
                };

                registration.Configuration.SigningKeys.Add(SigningKey);

                options.AddRegistration(registration);

                options.AddEventHandler<ExtractTokenResponseContext>(builder => builder.UseInlineHandler(context =>
                {
                    context.Response = new OpenIddictResponse
                    {
                        AccessToken = "access_token",
                        TokenType = TokenTypes.Bearer
                    };

                    return default;
                }));

                var host = options.UseOwin()
                    .DisableTransportSecurityRequirement()
                    .EnableRedirectionEndpointPassthrough();

                // Note: the logout endpoints must be able to terminate sessions to pass the options validation.
                if (defaults)
                {
                    host.SetFrontchannelLogoutSignOutAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);
                }

                configuration?.Invoke(host);
            });

        if (defaults && configure is null)
        {
            services.AddOpenIddict().AddClient().AddSessionStore(new TestSessionStore());
        }

        configure?.Invoke(services);

        var provider = services.BuildServiceProvider();

        return TestServer.Create(app =>
        {
            app.Use(async (context, next) =>
            {
                await using var scope = provider.CreateAsyncScope();

                context.Set(typeof(IServiceProvider).FullName, scope.ServiceProvider);

                try
                {
                    await next();
                }

                finally
                {
                    context.Environment.Remove(typeof(IServiceProvider).FullName);
                }
            });

            app.UseCookieAuthentication(new CookieAuthenticationOptions());

            app.UseOpenIddictClient();

            app.Run(async context =>
            {
                if (context.Request.Path == new PathString("/challenge"))
                {
                    context.Authentication.Challenge(OpenIddictClientOwinDefaults.AuthenticationType);
                }

                else if (context.Request.Path == new PathString("/callback"))
                {
                    var result = await context.Authentication.AuthenticateAsync(OpenIddictClientOwinDefaults.AuthenticationType);
                    string? state = null;
                    result?.Properties?.Dictionary.TryGetValue(Properties.SessionState, out state);

                    await context.Response.WriteAsync(state ?? string.Empty);
                }

                else if (context.Request.Path == new PathString("/signin"))
                {
                    var identity = new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationType);
                    identity.AddClaim(new Claim(Claims.Subject, "Bob"));
                    identity.AddClaim(new Claim(Claims.SessionId, context.Request.Query["sid"], ClaimValueTypes.String, Issuer.AbsoluteUri));
                    identity.AddClaim(new Claim(Claims.Private.RegistrationId, "Contoso"));

                    context.Authentication.SignIn(identity);
                }

                else if (context.Request.Path == new PathString("/backchannel-logout"))
                {
                    var result = await context.Authentication.AuthenticateAsync(OpenIddictClientOwinDefaults.AuthenticationType);
                    var principal = new ClaimsPrincipal(result!.Identity);

                    await context.Response.WriteAsync(string.Join("|", "passthrough",
                        principal.GetClaim(Claims.Subject),
                        principal.GetClaim(Claims.SessionId),
                        principal.GetClaim(Claims.Private.RegistrationId)));
                }
            });
        });
    }

    private sealed class TestSessionStore : IOpenIddictClientSessionStore
    {
        public List<(string?, string?, string?)> Calls { get; } = [];

        public int Failures { get; set; }

        public ValueTask<long> RemoveSessionsAsync(OpenIddictClientRegistration registration,
            string? subject, string? sessionId, CancellationToken cancellationToken)
        {
            Calls.Add((registration.RegistrationId, subject, sessionId));

            if (Failures > 0)
            {
                Failures--;
                throw new InvalidOperationException("The session store is not available.");
            }

            return new(1);
        }
    }
}
