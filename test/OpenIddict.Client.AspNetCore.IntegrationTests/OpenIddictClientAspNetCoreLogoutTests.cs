/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using static OpenIddict.Client.OpenIddictClientEvents;
using Properties = OpenIddict.Client.AspNetCore.OpenIddictClientAspNetCoreConstants.Properties;

namespace OpenIddict.Client.AspNetCore.IntegrationTests;

public class OpenIddictClientAspNetCoreLogoutTests
{
    private static readonly Uri Issuer = new("https://contoso.com/", UriKind.Absolute);
    private static readonly RsaSecurityKey SigningKey = new(RSA.Create(keySizeInBits: 2048)) { KeyId = "key" };

    [Fact]
    public async Task BackchannelLogout_ValidLogoutTokenRemovesMatchingSessions()
    {
        // Arrange
        var store = new TestSessionStore();
        using var host = await CreateHostAsync(services => services.AddOpenIddict().AddClient().AddSessionStore(store));
        using var client = host.GetTestClient();

        // Act
        using var response = await client.PostAsync("/backchannel-logout", new FormUrlEncodedContent(
            [new KeyValuePair<string, string>(Parameters.LogoutToken, CreateLogoutToken(sub: "Bob", sid: "session"))]));

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Equal(("Contoso", "Bob", "session"), Assert.Single(store.Calls));
    }

    [Theory]
    [InlineData("nonce")]
    [InlineData("missing")]
    [InlineData("replayed")]
    public async Task BackchannelLogout_InvalidRequestsAreRejectedWithJsonError(string scenario)
    {
        // Arrange
        var store = new TestSessionStore();
        using var host = await CreateHostAsync(services => services.AddOpenIddict().AddClient().AddSessionStore(store));
        using var client = host.GetTestClient();

        var token = CreateLogoutToken(sid: "session", nonce: scenario is "nonce" ? "nonce" : null);

        if (scenario is "replayed")
        {
            using var first = await client.PostAsync("/backchannel-logout", new FormUrlEncodedContent(
                [new KeyValuePair<string, string>(Parameters.LogoutToken, token)]));

            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
            store.Calls.Clear();
        }

        // Act
        using var response = await client.PostAsync("/backchannel-logout", new FormUrlEncodedContent(scenario is "missing" ?
            [] : [new KeyValuePair<string, string>(Parameters.LogoutToken, token)]));

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());

        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(Errors.InvalidRequest, document.RootElement.GetProperty(Parameters.Error).GetString());
        Assert.Empty(store.Calls);
    }

    [Fact]
    public async Task BackchannelLogout_GetRequestsAreRejected()
    {
        // Arrange
        using var host = await CreateHostAsync();
        using var client = host.GetTestClient();

        // Act
        using var response = await client.GetAsync("/backchannel-logout?logout_token=" + CreateLogoutToken(sid: "session"));

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task BackchannelLogout_PassthroughModeExposesTheLogoutTokenPrincipal()
    {
        // Arrange
        using var host = await CreateHostAsync(configuration: options => options.EnableBackchannelLogoutEndpointPassthrough());
        using var client = host.GetTestClient();

        // Act
        using var response = await client.PostAsync("/backchannel-logout", new FormUrlEncodedContent(
            [new KeyValuePair<string, string>(Parameters.LogoutToken, CreateLogoutToken(sub: "Bob", sid: "session"))]));

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("passthrough|Bob|session|Contoso", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task FrontchannelLogout_MatchingSessionIsSignedOut()
    {
        // Arrange
        var store = new TestSessionStore();
        using var host = await CreateHostAsync(
            services => services.AddOpenIddict().AddClient().AddSessionStore(store),
            options => options.SetFrontchannelLogoutSignOutScheme(CookieAuthenticationDefaults.AuthenticationScheme));

        using var client = host.GetTestClient();
        var cookie = await SignInAsync(client, "session");

        using var request = new HttpRequestMessage(HttpMethod.Get,
            $"/frontchannel-logout?iss={Uri.EscapeDataString(Issuer.AbsoluteUri)}&sid=session");
        request.Headers.Add("Cookie", cookie);

        // Act
        using var response = await client.SendAsync(request);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.CacheControl is { NoCache: true, NoStore: true });
        Assert.Contains("no-cache", response.Headers.Pragma.ToString(), StringComparison.Ordinal);
        Assert.Contains(response.Headers.GetValues("Set-Cookie"), value => value.Contains("expires=Thu, 01 Jan 1970", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(("Contoso", null, "session"), Assert.Single(store.Calls));
    }

    [Fact]
    public async Task FrontchannelLogout_NonMatchingSessionIsNotSignedOut()
    {
        // Arrange
        using var host = await CreateHostAsync(configuration: options =>
            options.SetFrontchannelLogoutSignOutScheme(CookieAuthenticationDefaults.AuthenticationScheme));

        using var client = host.GetTestClient();
        var cookie = await SignInAsync(client, "other_session");

        using var request = new HttpRequestMessage(HttpMethod.Get,
            $"/frontchannel-logout?iss={Uri.EscapeDataString(Issuer.AbsoluteUri)}&sid=session");
        request.Headers.Add("Cookie", cookie);

        // Act
        using var response = await client.SendAsync(request);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False(response.Headers.TryGetValues("Set-Cookie", out _));
    }

    [Theory]
    [InlineData("?sid=session")]
    [InlineData("?iss=https%3A%2F%2Fcontoso.com%2F")]
    [InlineData("?iss=https%3A%2F%2Ffabrikam.com%2F&sid=session")]
    public async Task FrontchannelLogout_InvalidRequestsAreRejected(string query)
    {
        // Arrange
        using var host = await CreateHostAsync();
        using var client = host.GetTestClient();

        // Act
        using var response = await client.GetAsync("/frontchannel-logout" + query);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task FrontchannelLogout_PassthroughModeExposesTheSessionIdentifier()
    {
        // Arrange
        using var host = await CreateHostAsync(configuration: options => options.EnableFrontchannelLogoutEndpointPassthrough());
        using var client = host.GetTestClient();

        // Act
        using var response = await client.GetAsync($"/frontchannel-logout?iss={Uri.EscapeDataString(Issuer.AbsoluteUri)}&sid=session");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("passthrough|session|Contoso", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Redirection_SessionStateIsExposedInAuthenticationProperties()
    {
        // Arrange
        using var host = await CreateHostAsync();
        using var client = host.GetTestClient();

        using var challenge = await client.GetAsync("/challenge");
        Assert.Equal(HttpStatusCode.Redirect, challenge.StatusCode);

        var parameters = QueryHelpers.ParseQuery(challenge.Headers.Location!.Query);

        using var request = new HttpRequestMessage(HttpMethod.Get, "/callback?code=authorization_code&session_state=state_value&state=" +
            Uri.EscapeDataString(parameters[Parameters.State]!));

        foreach (var cookie in challenge.Headers.GetValues("Set-Cookie"))
        {
            request.Headers.Add("Cookie", cookie.Split(';')[0]);
        }

        // Act
        using var callback = await client.SendAsync(request);

        // Assert
        Assert.Equal("state_value", await callback.Content.ReadAsStringAsync());
    }

    private static async Task<string> SignInAsync(HttpClient client, string session)
    {
        using var response = await client.GetAsync("/signin?sid=" + session);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        return response.Headers.GetValues("Set-Cookie").First().Split(';')[0];
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

    private static async Task<IHost> CreateHostAsync(
        Action<IServiceCollection>? services = null,
        Action<OpenIddictClientAspNetCoreBuilder>? configuration = null)
    {
        var builder = new HostBuilder();

        builder.ConfigureServices(collection =>
        {
            collection.AddAuthentication().AddCookie();

            collection.AddOpenIddict()
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

                    var host = options.UseAspNetCore()
                        .DisableTransportSecurityRequirement()
                        .EnableRedirectionEndpointPassthrough();

                    configuration?.Invoke(host);
                });

            services?.Invoke(collection);
        });

        builder.ConfigureWebHost(options =>
        {
            options.UseTestServer();
            options.Configure(app =>
            {
                app.UseAuthentication();

                app.Run(async context =>
                {
                    if (context.Request.Path == "/challenge")
                    {
                        await context.ChallengeAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);
                    }

                    else if (context.Request.Path == "/callback")
                    {
                        var result = await context.AuthenticateAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);
                        result.Properties!.Items.TryGetValue(Properties.SessionState, out var state);

                        await context.Response.WriteAsync(state ?? string.Empty);
                    }

                    else if (context.Request.Path == "/signin")
                    {
                        var identity = new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationScheme);
                        identity.AddClaim(new Claim(Claims.Subject, "Bob"));
                        identity.AddClaim(new Claim(Claims.SessionId, context.Request.Query["sid"]!, ClaimValueTypes.String, Issuer.AbsoluteUri));
                        identity.AddClaim(new Claim(Claims.Private.RegistrationId, "Contoso"));

                        await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));
                    }

                    else if (context.Request.Path == "/backchannel-logout")
                    {
                        var result = await context.AuthenticateAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);
                        var principal = result.Properties!.GetParameter<ClaimsPrincipal>(Properties.LogoutTokenPrincipal);

                        await context.Response.WriteAsync(string.Join("|", "passthrough",
                            principal?.GetClaim(Claims.Subject),
                            principal?.GetClaim(Claims.SessionId),
                            result.Principal?.GetClaim(Claims.Private.RegistrationId)));
                    }

                    else if (context.Request.Path == "/frontchannel-logout")
                    {
                        var result = await context.AuthenticateAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);
                        var transaction = context.Features.Get<OpenIddictClientAspNetCoreFeature>()?.Transaction;

                        await context.Response.WriteAsync(string.Join("|", "passthrough",
                            transaction?.Request?[Parameters.Sid],
                            result.Principal?.GetClaim(Claims.Private.RegistrationId)));
                    }
                });
            });
        });

        return await builder.StartAsync();
    }

    private sealed class TestSessionStore : IOpenIddictClientSessionStore
    {
        public List<(string?, string?, string?)> Calls { get; } = [];

        public ValueTask<long> RemoveSessionsAsync(OpenIddictClientRegistration registration,
            string? subject, string? sessionId, CancellationToken cancellationToken)
        {
            Calls.Add((registration.RegistrationId, subject, sessionId));

            return new(1);
        }
    }
}
