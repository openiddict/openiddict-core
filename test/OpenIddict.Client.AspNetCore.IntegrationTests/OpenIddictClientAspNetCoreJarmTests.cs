using System.Net;
using System.Security.Cryptography;
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
using Xunit;

namespace OpenIddict.Client.AspNetCore.IntegrationTests;

public class OpenIddictClientAspNetCoreJarmTests
{
    private static readonly Uri Issuer = new("https://contoso.com/", UriKind.Absolute);
    private static readonly RsaSecurityKey ServerSigningKey = new(RSA.Create(keySizeInBits: 2048)) { KeyId = "server_key" };

    [Fact]
    public async Task Challenge_JwtResponseModeIsUsedWhenRequired()
    {
        // Arrange
        using var host = await CreateHostAsync();
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
    public async Task Callback_JwtResponseIsValidatedAndExtracted(string method)
    {
        // Arrange
        using var host = await CreateHostAsync();
        using var client = host.GetTestClient();

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
        using var host = await CreateHostAsync();
        using var client = host.GetTestClient();

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
        using var host = await CreateHostAsync();
        using var client = host.GetTestClient();

        var (state, cookies) = await ChallengeAsync(client);
        var token = CreateToken(state, new RsaSecurityKey(RSA.Create(keySizeInBits: 2048)) { KeyId = "server_key" });

        // Act
        using var request = new HttpRequestMessage(HttpMethod.Get, "/callback?response=" + Uri.EscapeDataString(token));
        AttachCookies(request, cookies);

        using var callback = await client.SendAsync(request);

        // Assert
        Assert.Equal(Errors.InvalidRequest + "|" + SR.GetResourceString(SR.ID2322), await callback.Content.ReadAsStringAsync());
    }

    private static async Task<(string State, IEnumerable<string> Cookies)> ChallengeAsync(HttpClient client)
    {
        using var challenge = await client.GetAsync("/challenge");

        var parameters = QueryHelpers.ParseQuery(challenge.Headers.Location!.Query);
        return (parameters[Parameters.State]!, challenge.Headers.GetValues("Set-Cookie").ToList());
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

    private static async Task<IHost> CreateHostAsync()
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
                        await context.ChallengeAsync("Contoso");
                        return;
                    }

                    if (context.Request.Path == "/callback")
                    {
                        var result = await context.AuthenticateAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);

                        await context.Response.WriteAsync(string.Join("|",
                            result.Properties?.Items[OpenIddictClientAspNetCoreConstants.Properties.Error],
                            result.Properties?.Items[OpenIddictClientAspNetCoreConstants.Properties.ErrorDescription]));
                    }
                });
            });
        });

        return await builder.StartAsync();
    }
}
