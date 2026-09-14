using System.Collections.Concurrent;
using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using static OpenIddict.Client.OpenIddictClientEvents;
using Tokens = OpenIddict.Client.AspNetCore.OpenIddictClientAspNetCoreConstants.Tokens;

namespace OpenIddict.Client.AspNetCore.Bff.Tests;

/// <summary>
/// Hosts a BFF application backed by a mocked authorization server token endpoint.
/// </summary>
public sealed class OpenIddictClientAspNetCoreBffTestHost : IAsyncDisposable
{
    public static readonly Uri Issuer = new("https://contoso.com/", UriKind.Absolute);

    private OpenIddictClientAspNetCoreBffTestHost(IHost host, TokenEndpoint endpoint, SecurityKey key)
    {
        Host = host;
        Endpoint = endpoint;
        SigningKey = key;
        Client = host.GetTestClient();
    }

    public IHost Host { get; }

    public HttpClient Client { get; }

    public TokenEndpoint Endpoint { get; }

    public SecurityKey SigningKey { get; }

    public IServiceProvider Services => Host.Services;

    public static async Task<OpenIddictClientAspNetCoreBffTestHost> CreateAsync(
        Action<OpenIddictClientBuilder>? client = null,
        Action<OpenIddictClientAspNetCoreBffBuilder>? bff = null,
        Action<IServiceCollection>? services = null,
        Action<IEndpointRouteBuilder>? endpoints = null,
        bool middleware = true,
        SecurityKey? signingKey = null)
    {
        var endpoint = new TokenEndpoint();
        var key = signingKey ?? new RsaSecurityKey(RSA.Create(2048)) { KeyId = "signing_key" };

        var builder = new HostBuilder();

        builder.ConfigureServices(collection =>
        {
            collection.AddRouting();
            collection.AddAuthorization();

            collection.AddAuthentication(options => options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie();

            collection.AddOpenIddict()
                .AddClient(options =>
                {
                    options.AllowAuthorizationCodeFlow()
                           .AllowClientCredentialsFlow()
                           .AllowRefreshTokenFlow();

                    options.DisableTokenStorage();

                    options.AddEphemeralEncryptionKey()
                           .AddEphemeralSigningKey();

                    options.AddRegistration(new OpenIddictClientRegistration
                    {
                        ClientId = "Fabrikam",
                        ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                        Configuration = new OpenIddictConfiguration
                        {
                            AuthorizationEndpoint = new Uri("https://contoso.com/connect/authorize", UriKind.Absolute),
                            CodeChallengeMethodsSupported = { CodeChallengeMethods.Sha256 },
                            GrantTypesSupported = { GrantTypes.AuthorizationCode, GrantTypes.ClientCredentials, GrantTypes.RefreshToken },
                            Issuer = Issuer,
                            ResponseModesSupported = { ResponseModes.Query },
                            ResponseTypesSupported = { ResponseTypes.Code },
                            SigningKeys = { key },
                            TokenEndpoint = new Uri("https://contoso.com/connect/token", UriKind.Absolute),
                            TokenEndpointAuthMethodsSupported = { ClientAuthenticationMethods.ClientSecretPost }
                        },
                        Issuer = Issuer,
                        ProviderName = "Contoso",
                        RedirectUri = new Uri("bff/callback/login", UriKind.Relative),
                        RegistrationId = "Contoso",
                        Scopes = { Scopes.OpenId }
                    });

                    options.UseAspNetCore()
                           .DisableTransportSecurityRequirement();

                    options.AddEventHandler<ExtractTokenResponseContext>(handler => handler.UseInlineHandler(endpoint.HandleAsync));

                    var host = options.UseBff();
                    bff?.Invoke(host);

                    client?.Invoke(options);
                });

            services?.Invoke(collection);
        });

        builder.ConfigureWebHost(options =>
        {
            options.UseTestServer();
            options.Configure(app =>
            {
                app.UseRouting();
                app.UseAuthentication();
                if (middleware)
                {
                    app.UseOpenIddictBff();
                }

                app.UseAuthorization();

                app.UseEndpoints(routes =>
                {
                    routes.MapOpenIddictBffEndpoints();

                    // Signs in a user whose tokens are specified in the query string.
                    routes.MapGet("/test/signin", async context =>
                    {
                        var identity = new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationScheme, Claims.Name, Claims.Role);
                        identity.AddClaim(new Claim(Claims.Subject, "Bob"));
                        identity.AddClaim(new Claim(Claims.Name, "Bob le Magnifique"));
                        identity.AddClaim(new Claim(Claims.SessionId, "session"));
                        identity.AddClaim(new Claim(Claims.Private.RegistrationId, "Contoso"));

                        var properties = new AuthenticationProperties();
                        var tokens = new List<AuthenticationToken>();

                        foreach (var name in (string[]) [Tokens.BackchannelAccessToken, Tokens.BackchannelAccessTokenExpirationDate,
                                                         Tokens.BackchannelAccessTokenType, Tokens.RefreshToken])
                        {
                            if (!string.IsNullOrEmpty(context.Request.Query[name]))
                            {
                                tokens.Add(new AuthenticationToken { Name = name, Value = context.Request.Query[name]! });
                            }
                        }

                        properties.StoreTokens(tokens);

                        await context.SignInAsync(new ClaimsPrincipal(identity), properties);
                    });

                    // Returns the user access token or 401 if no token is available.
                    routes.MapGet("/test/token", async context =>
                    {
                        var manager = context.RequestServices.GetRequiredService<OpenIddictClientAspNetCoreBffTokenManager>();

                        var token = await manager.GetUserAccessTokenAsync(context);
                        if (token is null)
                        {
                            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                            return;
                        }

                        await context.Response.WriteAsync(token.Value);
                    });

                    // Returns the refresh token stored in the ticket.
                    routes.MapGet("/test/refresh_token", async context =>
                    {
                        var result = await context.AuthenticateAsync();
                        await context.Response.WriteAsync(result.Properties?.GetTokenValue(Tokens.RefreshToken) ?? string.Empty);
                    });

                    endpoints?.Invoke(routes);
                });
            });
        });

        return new OpenIddictClientAspNetCoreBffTestHost(await builder.StartAsync(), endpoint, key);
    }

    public static string FormatDate(DateTimeOffset date) => date.ToString("o", CultureInfo.InvariantCulture);

    /// <summary>
    /// Signs in a user and returns the authentication cookie.
    /// </summary>
    public async Task<string> SignInAsync(string? accessToken = "old_access_token", DateTimeOffset? expiration = null,
        string? refreshToken = "old_refresh_token", string? type = null)
    {
        var query = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            [Tokens.BackchannelAccessToken] = accessToken,
            [Tokens.BackchannelAccessTokenExpirationDate] = expiration is DateTimeOffset date ? FormatDate(date) : null,
            [Tokens.BackchannelAccessTokenType] = type,
            [Tokens.RefreshToken] = refreshToken
        };

        using var response = await Client.GetAsync(Microsoft.AspNetCore.WebUtilities.QueryHelpers.AddQueryString("/test/signin", query));
        response.EnsureSuccessStatusCode();

        return GetCookie(response) ?? throw new InvalidOperationException("No cookie was returned.");
    }

    public static string? GetCookie(HttpResponseMessage response)
        => response.Headers.TryGetValues("Set-Cookie", out var values)
            ? values.Select(static value => value.Split(';')[0])
                    .FirstOrDefault(static value => value.StartsWith(".AspNetCore.Cookies=", StringComparison.Ordinal))
            : null;

    public Task<HttpResponseMessage> SendAsync(HttpMethod method, string uri, string? cookie, bool antiforgery = false)
    {
        var request = new HttpRequestMessage(method, uri);

        if (!string.IsNullOrEmpty(cookie))
        {
            request.Headers.Add("Cookie", cookie);
        }

        if (antiforgery)
        {
            request.Headers.Add("X-CSRF", "1");
        }

        return Client.SendAsync(request);
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await Host.StopAsync();
        Host.Dispose();
    }

    /// <summary>
    /// Represents the mocked token endpoint of the authorization server.
    /// </summary>
    public sealed class TokenEndpoint
    {
        public ConcurrentQueue<OpenIddictRequest> Requests { get; } = new();

        public Func<OpenIddictRequest, Task<OpenIddictResponse>> Handler { get; set; } = static request =>
            Task.FromResult(new OpenIddictResponse
            {
                AccessToken = "new_access_token",
                ExpiresIn = 3600,
                RefreshToken = "new_refresh_token",
                TokenType = TokenTypes.Bearer
            });

        public async ValueTask HandleAsync(ExtractTokenResponseContext context)
        {
            Requests.Enqueue(context.Request);

            context.Response = await Handler(context.Request);
        }
    }
}
