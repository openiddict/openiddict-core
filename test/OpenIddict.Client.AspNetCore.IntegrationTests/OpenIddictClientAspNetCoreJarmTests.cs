using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;
using Xunit;
using static OpenIddict.Client.OpenIddictClientEvents;
using Tokens = OpenIddict.Client.AspNetCore.OpenIddictClientAspNetCoreConstants.Tokens;

namespace OpenIddict.Client.AspNetCore.IntegrationTests;

public class OpenIddictClientAspNetCoreJarmTests
{
    private static readonly Uri Issuer = new("https://contoso.com/", UriKind.Absolute);
    private static readonly RsaSecurityKey ServerSigningKey = new(RSA.Create(keySizeInBits: 2048)) { KeyId = "server_key" };
    private static readonly RsaSecurityKey ClientEncryptionKey = new(RSA.Create(keySizeInBits: 2048)) { KeyId = "client_key" };

    [Fact]
    public async Task Challenge_JwtResponseModeIsUsedWhenRequired()
    {
        // Arrange
        using var host = await CreateHostAsync(new TokenRequestRecorder());
        using var client = host.GetTestClient();

        // Act
        using var challenge = await client.GetAsync("/challenge");

        // Assert
        Assert.Equal(HttpStatusCode.Redirect, challenge.StatusCode);

        var parameters = QueryHelpers.ParseQuery(challenge.Headers.Location!.Query);
        Assert.Equal(ResponseModes.QueryJwt, parameters[Parameters.ResponseMode]);
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("POST")]
    public async Task Callback_JwtErrorResponseIsValidatedAndExtracted(string method)
    {
        // Arrange
        using var host = await CreateHostAsync(new TokenRequestRecorder());
        using var client = host.GetTestClient();

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

        using var host = await CreateHostAsync(recorder);
        using var client = host.GetTestClient();

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
    public async Task Callback_CodeSentOutsideJwtIsIgnored()
    {
        // Arrange
        var recorder = new TokenRequestRecorder();

        using var host = await CreateHostAsync(recorder);
        using var client = host.GetTestClient();

        var (state, cookies) = await ChallengeAsync(client);
        var token = CreateToken(new(StringComparer.Ordinal)
        {
            [Parameters.Code] = "SplxlOBeZQQYbYS6WxSbIA",
            [Parameters.State] = state
        }, ServerSigningKey);

        // Act
        using var request = new HttpRequestMessage(HttpMethod.Get,
            "/callback?code=injected_code&response=" + Uri.EscapeDataString(token));
        AttachCookies(request, cookies);

        using var callback = await client.SendAsync(request);

        // Assert
        Assert.Equal("||access_token|SplxlOBeZQQYbYS6WxSbIA", await callback.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Callback_PlainResponseIsRejected()
    {
        // Arrange
        using var host = await CreateHostAsync(new TokenRequestRecorder());
        using var client = host.GetTestClient();

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

        using var host = await CreateHostAsync(recorder);
        using var client = host.GetTestClient();

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
        using var server = await CreateServerHostAsync();
        using var backchannel = server.GetTestClient();

        using var keys = await backchannel.GetAsync("/.well-known/jwks");
        var set = new JsonWebKeySet(await keys.Content.ReadAsStringAsync());

        var recorder = new TokenRequestRecorder();

        using var host = await CreateHostAsync(recorder, set.GetSigningKeys());
        using var client = host.GetTestClient();

        using var challenge = await client.GetAsync("/challenge?mode=" + mode);
        Assert.Equal(HttpStatusCode.Redirect, challenge.StatusCode);
        Assert.Equal(mode + ".jwt", QueryHelpers.ParseQuery(challenge.Headers.Location!.Query)[Parameters.ResponseMode]);

        var cookies = challenge.Headers.GetValues("Set-Cookie").ToList();

        // Send the authorization request to the OpenIddict server.
        using var authorization = await backchannel.GetAsync(challenge.Headers.Location!.PathAndQuery);

        string token;

        if (mode is ResponseModes.Query)
        {
            Assert.Equal(HttpStatusCode.Redirect, authorization.StatusCode);
            Assert.Equal("/callback", authorization.Headers.Location!.AbsolutePath);

            var parameters = QueryHelpers.ParseQuery(authorization.Headers.Location!.Query);
            Assert.Equal(Parameters.Response, Assert.Single(parameters).Key);

            token = parameters[Parameters.Response]!;
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

    private static async Task<(string State, IEnumerable<string> Cookies)> ChallengeAsync(HttpClient client)
    {
        using var challenge = await client.GetAsync("/challenge");

        var parameters = QueryHelpers.ParseQuery(challenge.Headers.Location!.Query);
        return (parameters[Parameters.State]!, challenge.Headers.GetValues("Set-Cookie").ToList());
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

    private static async Task<IHost> CreateHostAsync(TokenRequestRecorder recorder, IEnumerable<SecurityKey>? signingKeys = null)
    {
        var builder = new HostBuilder();

        builder.ConfigureServices(services =>
        {
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

                    options.UseAspNetCore()
                        .DisableTransportSecurityRequirement()
                        .EnableErrorPassthrough()
                        .EnableRedirectionEndpointPassthrough();
                });
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
                        var properties = new AuthenticationProperties();

                        if (context.Request.Query.TryGetValue("mode", out var mode))
                        {
                            properties.Items[OpenIddictClientAspNetCoreConstants.Properties.ResponseMode] = mode;
                        }

                        await context.ChallengeAsync("Contoso", properties);
                        return;
                    }

                    if (context.Request.Path == "/callback")
                    {
                        var result = await context.AuthenticateAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);

                        string? error = null, description = null;
                        result.Properties?.Items.TryGetValue(OpenIddictClientAspNetCoreConstants.Properties.Error, out error);
                        result.Properties?.Items.TryGetValue(OpenIddictClientAspNetCoreConstants.Properties.ErrorDescription, out description);

                        await context.Response.WriteAsync(string.Join("|",
                            error, description,
                            result.Succeeded ? result.Properties?.GetTokenValue(Tokens.BackchannelAccessToken) : null,
                            result.Succeeded ? recorder.Codes.LastOrDefault() : null));
                    }
                });
            });
        });

        return await builder.StartAsync();
    }

    private static async Task<IHost> CreateServerHostAsync()
    {
        var builder = new HostBuilder();

        builder.ConfigureServices(services =>
        {
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

                    options.UseAspNetCore()
                           .DisableTransportSecurityRequirement();
                });
        });

        builder.ConfigureWebHost(options =>
        {
            options.UseTestServer();
            options.Configure(app => app.UseAuthentication());
        });

        return await builder.StartAsync();
    }
}
