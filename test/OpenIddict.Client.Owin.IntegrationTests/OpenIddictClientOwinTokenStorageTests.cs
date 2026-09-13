using System.Net;
using System.Net.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Owin;
using Microsoft.Owin.Testing;
using Owin;
using Xunit;
using static OpenIddict.Client.OpenIddictClientEvents;
using Tokens = OpenIddict.Client.Owin.OpenIddictClientOwinConstants.Tokens;

namespace OpenIddict.Client.Owin.IntegrationTests;

public class OpenIddictClientOwinTokenStorageTests
{
    private static readonly Uri Issuer = new("https://contoso.com/", UriKind.Absolute);

    [Theory]
    [InlineData(TokenTypes.Bearer)]
    [InlineData(TokenTypes.DPoP)]
    public async Task Callback_BackchannelAccessTokenTypeIsStoredInAuthenticationProperties(string type)
    {
        // Arrange
        using var server = CreateServer(type);
        using var client = server.HttpClient;

        using var challenge = await client.GetAsync("/challenge");
        Assert.Equal(HttpStatusCode.Redirect, challenge.StatusCode);

        var state = challenge.Headers.Location!.Query.TrimStart('?').Split('&')
            .Select(static parameter => parameter.Split('='))
            .Single(static parts => parts[0] is Parameters.State)[1];

        using var request = new HttpRequestMessage(HttpMethod.Get, "/callback?code=authorization_code&state=" + state);

        foreach (var cookie in challenge.Headers.GetValues("Set-Cookie"))
        {
            request.Headers.Add("Cookie", cookie.Split(';')[0]);
        }

        // Act
        using var callback = await client.SendAsync(request);

        // Assert
        Assert.Equal("access_token|" + type, await callback.Content.ReadAsStringAsync());
    }

    private static TestServer CreateServer(string type)
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

                options.AddRegistration(new OpenIddictClientRegistration
                {
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
                    Issuer = Issuer,
                    ProviderName = "Contoso",
                    RedirectUri = new Uri("callback", UriKind.Relative),
                    RegistrationId = "Contoso"
                });

                options.AddEventHandler<ExtractTokenResponseContext>(builder => builder.UseInlineHandler(context =>
                {
                    context.Response = new OpenIddictResponse
                    {
                        AccessToken = "access_token",
                        ExpiresIn = 3600,
                        TokenType = type
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
                    context.Authentication.Challenge(OpenIddictClientOwinDefaults.AuthenticationType);
                }

                else if (context.Request.Path == new PathString("/callback"))
                {
                    var result = await context.Authentication.AuthenticateAsync(OpenIddictClientOwinDefaults.AuthenticationType);
                    if (result?.Properties is null)
                    {
                        context.Response.StatusCode = 500;
                        return;
                    }

                    result.Properties.Dictionary.TryGetValue(Tokens.BackchannelAccessToken, out var token);
                    result.Properties.Dictionary.TryGetValue(Tokens.BackchannelAccessTokenType, out var type);

                    await context.Response.WriteAsync(token + "|" + type);
                }
            });
        });
    }
}
