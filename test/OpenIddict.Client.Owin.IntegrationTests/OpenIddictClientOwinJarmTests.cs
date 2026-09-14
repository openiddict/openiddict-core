using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Testing;
using Owin;
using Xunit;

namespace OpenIddict.Client.Owin.IntegrationTests;

public class OpenIddictClientOwinJarmTests
{
    private static readonly Uri Issuer = new("https://contoso.com/", UriKind.Absolute);
    private static readonly RsaSecurityKey ServerSigningKey = new(RSA.Create(keySizeInBits: 2048)) { KeyId = "server_key" };

    [Fact]
    public async Task Challenge_JwtResponseModeIsUsedWhenRequired()
    {
        // Arrange
        using var server = CreateServer();
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
    public async Task Callback_JwtResponseIsValidatedAndExtracted(string method)
    {
        // Arrange
        using var server = CreateServer();
        using var client = server.HttpClient;

        var (state, cookies) = await ChallengeAsync(client);
        var token = CreateToken(state, ServerSigningKey);

        // Act
        using var request = method is "GET"
            ? new HttpRequestMessage(HttpMethod.Get, "/callback?response=" + Uri.EscapeDataString(token))
            : new HttpRequestMessage(HttpMethod.Post, "/callback")
            {
                Content = new FormUrlEncodedContent([new(Parameters.Response, token)])
            };

        AttachCookies(request, cookies);

        using var callback = await client.SendAsync(request);

        // Assert
        Assert.Equal(Errors.AccessDenied + "|" + SR.GetResourceString(SR.ID2149), await callback.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Callback_PlainResponseIsRejected()
    {
        // Arrange
        using var server = CreateServer();
        using var client = server.HttpClient;

        var (state, cookies) = await ChallengeAsync(client);

        // Act
        using var request = new HttpRequestMessage(HttpMethod.Get, "/callback?error=access_denied&state=" + Uri.EscapeDataString(state));
        AttachCookies(request, cookies);

        using var callback = await client.SendAsync(request);

        // Assert
        Assert.Equal(Errors.InvalidRequest + "|" + SR.GetResourceString(SR.ID2321), await callback.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Callback_JwtResponseSignedWithUntrustedKeyIsRejected()
    {
        // Arrange
        using var server = CreateServer();
        using var client = server.HttpClient;

        var (state, cookies) = await ChallengeAsync(client);
        var token = CreateToken(state, new RsaSecurityKey(RSA.Create(keySizeInBits: 2048)) { KeyId = "server_key" });

        // Act
        using var request = new HttpRequestMessage(HttpMethod.Get, "/callback?response=" + Uri.EscapeDataString(token));
        AttachCookies(request, cookies);

        using var callback = await client.SendAsync(request);

        // Assert
        Assert.Equal(Errors.InvalidRequest + "|" + SR.GetResourceString(SR.ID2322), await callback.Content.ReadAsStringAsync());
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

    private static void AttachCookies(HttpRequestMessage request, IEnumerable<string> cookies)
    {
        foreach (var cookie in cookies)
        {
            request.Headers.Add("Cookie", cookie.Split(';')[0]);
        }
    }

    private static string CreateToken(string state, SecurityKey key)
        => new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Audience = "Fabrikam",
            Claims = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [Parameters.Error] = Errors.AccessDenied,
                [Parameters.State] = state
            },
            Expires = DateTime.UtcNow.AddMinutes(5),
            Issuer = Issuer.AbsoluteUri,
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256)
        });

    private static TestServer CreateServer()
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

                var configuration = new OpenIddictConfiguration
                {
                    AuthorizationEndpoint = new Uri("https://contoso.com/connect/authorize", UriKind.Absolute),
                    CodeChallengeMethodsSupported = { CodeChallengeMethods.Sha256 },
                    GrantTypesSupported = { GrantTypes.AuthorizationCode },
                    Issuer = Issuer,
                    ResponseModesSupported = { ResponseModes.Query, ResponseModes.QueryJwt },
                    ResponseTypesSupported = { ResponseTypes.Code }
                };

                configuration.SigningKeys.Add(ServerSigningKey);

                options.AddRegistration(new OpenIddictClientRegistration
                {
                    ClientId = "Fabrikam",
                    Configuration = configuration,
                    Issuer = Issuer,
                    ProviderName = "Contoso",
                    RedirectUri = new Uri("callback", UriKind.Relative),
                    RequireJwtSecuredAuthorizationResponses = true
                });

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
                    context.Authentication.Challenge("Contoso");
                }

                else if (context.Request.Path == new PathString("/callback"))
                {
                    var result = await context.Authentication.AuthenticateAsync(OpenIddictClientOwinDefaults.AuthenticationType);

                    string? error = null, description = null;
                    result?.Properties.Dictionary.TryGetValue(OpenIddictClientOwinConstants.Properties.Error, out error);
                    result?.Properties.Dictionary.TryGetValue(OpenIddictClientOwinConstants.Properties.ErrorDescription, out description);

                    await context.Response.WriteAsync(string.Join("|", error, description));
                }
            });
        });
    }
}
