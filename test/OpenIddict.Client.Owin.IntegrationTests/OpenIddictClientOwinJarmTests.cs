using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Testing;
using OpenIddict.Server;
using Owin;
using Xunit;
using static OpenIddict.Client.OpenIddictClientEvents;
using Tokens = OpenIddict.Client.Owin.OpenIddictClientOwinConstants.Tokens;

namespace OpenIddict.Client.Owin.IntegrationTests;

public class OpenIddictClientOwinJarmTests
{
    private static readonly Uri Issuer = new("https://contoso.com/", UriKind.Absolute);
    private static readonly RsaSecurityKey ServerSigningKey = new(RSA.Create(keySizeInBits: 2048)) { KeyId = "server_key" };
    private static readonly RsaSecurityKey ClientEncryptionKey = new(RSA.Create(keySizeInBits: 2048)) { KeyId = "client_key" };

    [Fact]
    public async Task Challenge_JwtResponseModeIsUsedWhenRequired()
    {
        // Arrange
        using var server = CreateServer(new TokenRequestRecorder());
        using var client = server.HttpClient;

        // Act
        using var challenge = await client.GetAsync("/challenge");

        // Assert
        Assert.Equal(HttpStatusCode.Redirect, challenge.StatusCode);
        Assert.Equal(ResponseModes.QueryJwt, ParseQuery(challenge.Headers.Location!)[Parameters.ResponseMode]);
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("POST")]
    public async Task Callback_JwtErrorResponseIsValidatedAndExtracted(string method)
    {
        // Arrange
        using var server = CreateServer(new TokenRequestRecorder());
        using var client = server.HttpClient;

        var (state, cookies) = await ChallengeAsync(client);
        var token = CreateToken(new(StringComparer.Ordinal)
        {
            [Parameters.Error] = Errors.AccessDenied,
            [Parameters.State] = state
        }, ServerSigningKey);

        // Act
        using var callback = await SendCallbackAsync(client, method, token, cookies);

        // Assert
        Assert.Equal(Errors.AccessDenied + "|" + SR.GetResourceString(SR.ID2149) + "||", await callback.Content.ReadAsStringAsync());
    }

    [Theory]
    [InlineData("GET", false)]
    [InlineData("POST", false)]
    [InlineData("GET", true)]
    [InlineData("POST", true)]
    public async Task Callback_JwtSuccessResponseIsValidatedAndCodeIsRedeemed(string method, bool encrypted)
    {
        // Arrange
        var recorder = new TokenRequestRecorder();

        using var server = CreateServer(recorder);
        using var client = server.HttpClient;

        var (state, cookies) = await ChallengeAsync(client);
        var token = CreateToken(new(StringComparer.Ordinal)
        {
            [Parameters.Code] = "SplxlOBeZQQYbYS6WxSbIA",
            [Parameters.State] = state
        }, ServerSigningKey, encrypted ? ClientEncryptionKey : null);

        // Act
        using var callback = await SendCallbackAsync(client, method, token, cookies);

        // Assert
        Assert.Equal("||access_token|SplxlOBeZQQYbYS6WxSbIA", await callback.Content.ReadAsStringAsync());
        Assert.Equal("SplxlOBeZQQYbYS6WxSbIA", Assert.Single(recorder.Codes));
    }

    [Fact]
    public async Task Callback_PlainResponseIsRejected()
    {
        // Arrange
        using var server = CreateServer(new TokenRequestRecorder());
        using var client = server.HttpClient;

        var (state, cookies) = await ChallengeAsync(client);

        // Act
        using var request = new HttpRequestMessage(HttpMethod.Get, "/callback?error=access_denied&state=" + Uri.EscapeDataString(state));
        AttachCookies(request, cookies);

        using var callback = await client.SendAsync(request);

        // Assert
        Assert.Equal(Errors.InvalidRequest + "|" + SR.GetResourceString(SR.ID2321) + "||", await callback.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Callback_JwtResponseSignedWithUntrustedKeyIsRejected()
    {
        // Arrange
        var recorder = new TokenRequestRecorder();

        using var server = CreateServer(recorder);
        using var client = server.HttpClient;

        var (state, cookies) = await ChallengeAsync(client);
        var token = CreateToken(new(StringComparer.Ordinal)
        {
            [Parameters.Code] = "SplxlOBeZQQYbYS6WxSbIA",
            [Parameters.State] = state
        }, new RsaSecurityKey(RSA.Create(keySizeInBits: 2048)) { KeyId = "server_key" });

        // Act
        using var callback = await SendCallbackAsync(client, "GET", token, cookies);

        // Assert
        Assert.Equal(Errors.InvalidRequest + "|" + SR.GetResourceString(SR.ID2322) + "||", await callback.Content.ReadAsStringAsync());
        Assert.Empty(recorder.Codes);
    }

    [Theory]
    [InlineData(ResponseModes.Query)]
    [InlineData(ResponseModes.FormPost)]
    public async Task Interop_OpenIddictServerJwtResponseIsAcceptedByOpenIddictClient(string mode)
    {
        // Arrange
        using var authorizationServer = CreateAuthorizationServer();
        using var backchannel = authorizationServer.HttpClient;

        using var keys = await backchannel.GetAsync("/.well-known/jwks");
        var set = new JsonWebKeySet(await keys.Content.ReadAsStringAsync());

        var recorder = new TokenRequestRecorder();

        using var server = CreateServer(recorder, set.GetSigningKeys());
        using var client = server.HttpClient;

        using var challenge = await client.GetAsync("/challenge?mode=" + mode);
        Assert.Equal(HttpStatusCode.Redirect, challenge.StatusCode);
        Assert.Equal(mode + ".jwt", ParseQuery(challenge.Headers.Location!)[Parameters.ResponseMode]);

        var cookies = challenge.Headers.GetValues("Set-Cookie").ToList();

        // Send the authorization request to the OpenIddict server.
        using var authorization = await backchannel.GetAsync(challenge.Headers.Location!.PathAndQuery);

        string token;

        if (mode is ResponseModes.Query)
        {
            Assert.Equal(HttpStatusCode.Redirect, authorization.StatusCode);
            Assert.Equal("/callback", authorization.Headers.Location!.AbsolutePath);

            var parameters = ParseQuery(authorization.Headers.Location!);
            Assert.Equal(Parameters.Response, Assert.Single(parameters).Key);

            token = parameters[Parameters.Response];
        }

        else
        {
            var match = Regex.Match(await authorization.Content.ReadAsStringAsync(),
                "name=\"response\" value=\"(?<value>[^\"]+)\"", RegexOptions.None, TimeSpan.FromSeconds(5));
            Assert.True(match.Success);

            token = WebUtility.HtmlDecode(match.Groups["value"].Value);
        }

        var code = new JsonWebToken(token).GetPayloadValue<string>(Parameters.Code);
        Assert.False(string.IsNullOrEmpty(code));

        // Act
        using var callback = await SendCallbackAsync(client, mode is ResponseModes.Query ? "GET" : "POST", token, cookies);

        // Assert
        Assert.Equal("||access_token|" + code, await callback.Content.ReadAsStringAsync());
        Assert.Equal(code, Assert.Single(recorder.Codes));
    }

    private static Dictionary<string, string> ParseQuery(Uri uri)
        => uri.Query.TrimStart('?').Split('&')
            .Select(static parameter => parameter.Split('='))
            .ToDictionary(static parts => Uri.UnescapeDataString(parts[0]), static parts => Uri.UnescapeDataString(parts[1]), StringComparer.Ordinal);

    private static async Task<(string State, IEnumerable<string> Cookies)> ChallengeAsync(HttpClient client)
    {
        using var challenge = await client.GetAsync("/challenge");

        return (ParseQuery(challenge.Headers.Location!)[Parameters.State], challenge.Headers.GetValues("Set-Cookie").ToList());
    }

    private static async Task<HttpResponseMessage> SendCallbackAsync(
        HttpClient client, string method, string token, IEnumerable<string> cookies)
    {
        using var request = method is "GET"
            ? new HttpRequestMessage(HttpMethod.Get, "/callback?response=" + Uri.EscapeDataString(token))
            : new HttpRequestMessage(HttpMethod.Post, "/callback")
            {
                Content = new FormUrlEncodedContent([new(Parameters.Response, token)])
            };

        AttachCookies(request, cookies);

        return await client.SendAsync(request);
    }

    private static void AttachCookies(HttpRequestMessage request, IEnumerable<string> cookies)
    {
        foreach (var cookie in cookies)
        {
            request.Headers.Add("Cookie", cookie.Split(';')[0]);
        }
    }

    private static string CreateToken(Dictionary<string, object> claims, SecurityKey key, SecurityKey? encryptionKey = null)
        => new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Audience = "Fabrikam",
            Claims = claims,
            EncryptingCredentials = encryptionKey is null ? null : new EncryptingCredentials(
                encryptionKey, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes128CbcHmacSha256),
            Expires = DateTime.UtcNow.AddMinutes(5),
            Issuer = Issuer.AbsoluteUri,
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256)
        });

    private sealed class TokenRequestRecorder
    {
        public List<string> Codes { get; } = [];
    }

    private static TestServer CreateServer(TokenRequestRecorder recorder, IEnumerable<SecurityKey>? signingKeys = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();

        services.AddOpenIddict()
            .AddClient(options =>
            {
                options.AllowAuthorizationCodeFlow();
                options.DisableTokenStorage();
                options.SetRedirectionEndpointUris("callback");

                options.AddEncryptionKey(ClientEncryptionKey)
                       .AddEphemeralSigningKey();

                var configuration = new OpenIddictConfiguration
                {
                    AuthorizationEndpoint = new Uri("https://contoso.com/connect/authorize", UriKind.Absolute),
                    CodeChallengeMethodsSupported = { CodeChallengeMethods.Sha256 },
                    GrantTypesSupported = { GrantTypes.AuthorizationCode },
                    Issuer = Issuer,
                    ResponseModesSupported =
                    {
                        ResponseModes.FormPost, ResponseModes.FormPostJwt,
                        ResponseModes.Query, ResponseModes.QueryJwt
                    },
                    ResponseTypesSupported = { ResponseTypes.Code },
                    TokenEndpoint = new Uri("https://contoso.com/connect/token", UriKind.Absolute),
                    TokenEndpointAuthMethodsSupported = { ClientAuthenticationMethods.ClientSecretPost }
                };

                foreach (var key in signingKeys ?? [ServerSigningKey])
                {
                    configuration.SigningKeys.Add(key);
                }

                options.AddRegistration(new OpenIddictClientRegistration
                {
                    ClientId = "Fabrikam",
                    ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                    Configuration = configuration,
                    Issuer = Issuer,
                    ProviderName = "Contoso",
                    RedirectUri = new Uri("callback", UriKind.Relative),
                    RequireJwtSecuredAuthorizationResponses = true
                });

                // Note: the token endpoint is not called: a static token response is returned instead.
                options.AddEventHandler<ExtractTokenResponseContext>(builder => builder.UseInlineHandler(context =>
                {
                    lock (recorder)
                    {
                        recorder.Codes.Add(context.Request.Code!);
                    }

                    context.Response = new OpenIddictResponse
                    {
                        AccessToken = "access_token",
                        ExpiresIn = 3600,
                        TokenType = TokenTypes.Bearer
                    };

                    return default;
                }));

                options.UseOwin()
                    .DisableTransportSecurityRequirement()
                    .EnableErrorPassthrough()
                    .EnableRedirectionEndpointPassthrough();
            });

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

            app.UseOpenIddictClient();

            app.Run(async context =>
            {
                if (context.Request.Path == new PathString("/challenge"))
                {
                    var properties = new AuthenticationProperties();

                    if (context.Request.Query["mode"] is { Length: > 0 } mode)
                    {
                        properties.Dictionary[OpenIddictClientOwinConstants.Properties.ResponseMode] = mode;
                    }

                    context.Authentication.Challenge(properties, "Contoso");
                }

                else if (context.Request.Path == new PathString("/callback"))
                {
                    var result = await context.Authentication.AuthenticateAsync(OpenIddictClientOwinDefaults.AuthenticationType);

                    string? error = null, description = null, token = null;
                    result?.Properties.Dictionary.TryGetValue(OpenIddictClientOwinConstants.Properties.Error, out error);
                    result?.Properties.Dictionary.TryGetValue(OpenIddictClientOwinConstants.Properties.ErrorDescription, out description);
                    result?.Properties.Dictionary.TryGetValue(Tokens.BackchannelAccessToken, out token);

                    await context.Response.WriteAsync(string.Join("|", error, description, token,
                        string.IsNullOrEmpty(token) ? null : recorder.Codes.LastOrDefault()));
                }
            });
        });
    }

    private static TestServer CreateAuthorizationServer()
    {
        var services = new ServiceCollection();
        services.AddLogging();

        services.AddOpenIddict()
            .AddServer(options =>
            {
                options.EnableDegradedMode();
                options.SetIssuer(Issuer);

                options.SetAuthorizationEndpointUris("connect/authorize")
                       .SetJsonWebKeySetEndpointUris(".well-known/jwks")
                       .SetTokenEndpointUris("connect/token");

                options.AllowAuthorizationCodeFlow();
                options.EnableJwtSecuredAuthorizationResponses();

                options.AddSigningKey(ServerSigningKey)
                       .AddEphemeralEncryptionKey();

                options.AddEventHandler<OpenIddictServerEvents.ValidateAuthorizationRequestContext>(builder =>
                    builder.UseInlineHandler(context => default));

                options.AddEventHandler<OpenIddictServerEvents.ValidateTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context => default));

                options.AddEventHandler<OpenIddictServerEvents.HandleAuthorizationRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType))
                            .SetClaim(Claims.Subject, "Bob le Magnifique");

                        return default;
                    }));

                options.UseOwin()
                       .DisableTransportSecurityRequirement();
            });

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

            app.UseOpenIddictServer();
        });
    }
}
