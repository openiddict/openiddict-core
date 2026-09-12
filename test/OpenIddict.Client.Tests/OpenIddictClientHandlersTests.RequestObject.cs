using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using static OpenIddict.Client.OpenIddictClientEvents;
using static OpenIddict.Client.OpenIddictClientHandlers;

namespace OpenIddict.Client.Tests;

public class OpenIddictClientHandlersRequestObjectTests
{
    private static readonly RsaSecurityKey SigningKey = new(RSA.Create(keySizeInBits: 2048));

    [Theory]
    [InlineData(true, false, false, false)]
    [InlineData(true, false, true, true)]
    [InlineData(null, true, false, true)]
    [InlineData(false, true, true, true)]
    [InlineData(null, null, true, false)]
    [InlineData(false, false, true, false)]
    public async Task EvaluateRequestObject_RequestObjectIsSentWhenSupportedAndEnabledOrRequired(
        bool? supported, bool? required, bool enabled, bool expected)
    {
        // Arrange
        using var provider = CreateProvider(enabled);
        var context = CreateContext(provider);
        context.Configuration.RequestParameterSupported = supported;
        context.Configuration.RequireSignedRequestObject = required;

        // Act
        await new EvaluateRequestObject().HandleAsync(context);

        // Assert
        Assert.Equal(expected, context.SendRequestObject);
    }

    [Fact]
    public async Task EvaluateRequestObject_ThrowsAnExceptionWhenNoAsymmetricSigningKeyIsAvailable()
    {
        // Arrange
        using var provider = CreateProvider(enabled: true);
        var context = CreateContext(provider);
        context.Configuration.RequireSignedRequestObject = true;
        context.Registration.SigningCredentials.Clear();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await new EvaluateRequestObject().HandleAsync(context));

        Assert.Equal(SR.GetResourceString(SR.ID0526), exception.Message);
    }

    [Fact]
    public async Task GenerateRequestObject_AuthorizationRequestParametersAreReplacedBySignedRequestObject()
    {
        // Arrange
        using var provider = CreateProvider(enabled: true);
        var context = CreateContext(provider);
        context.Configuration.RequestParameterSupported = true;

        context.Request.ClientId = "Fabrikam";
        context.Request.RedirectUri = "https://www.fabrikam.com/callback";
        context.Request.ResponseType = ResponseTypes.Code;
        context.Request.Scope = "openid profile";
        context.Request.Resources = ["https://www.fabrikam.com/api/1", "https://www.fabrikam.com/api/2"];
        context.Request.State = "af0ifjsldkj";

        // Act
        await new EvaluateRequestObject().HandleAsync(context);
        await new PrepareRequestObjectPrincipal().HandleAsync(context);
        await new GenerateRequestObject(provider.GetRequiredService<IOpenIddictClientDispatcher>()).HandleAsync(context);

        // Assert
        Assert.Equal("Fabrikam", context.Request.ClientId);
        Assert.Equal(context.RequestObject, context.Request.Request);
        Assert.Equal(2, context.Request.Count);

        var result = await new JsonWebTokenHandler().ValidateTokenAsync(context.RequestObject, new TokenValidationParameters
        {
            IssuerSigningKey = SigningKey,
            ValidAudience = "https://www.contoso.com/",
            ValidIssuer = "Fabrikam",
            ValidTypes = [JsonWebTokenTypes.AuthorizationRequest]
        });

        Assert.True(result.IsValid, result.Exception?.Message);

        var token = (JsonWebToken) result.SecurityToken;
        Assert.Equal("https://www.fabrikam.com/callback", token.GetPayloadValue<string>(Parameters.RedirectUri));
        Assert.Equal(ResponseTypes.Code, token.GetPayloadValue<string>(Parameters.ResponseType));
        Assert.Equal("openid profile", token.GetPayloadValue<string>(Parameters.Scope));
        Assert.Equal("af0ifjsldkj", token.GetPayloadValue<string>(Parameters.State));
        Assert.Equal("Fabrikam", token.GetPayloadValue<string>(Parameters.ClientId));
        Assert.Equal(["https://www.fabrikam.com/api/1", "https://www.fabrikam.com/api/2"],
            token.GetPayloadValue<string[]>(Parameters.Resource));
        Assert.True(token.TryGetPayloadValue(Claims.JwtId, out string _));
        Assert.True(token.TryGetPayloadValue(Claims.ExpiresAt, out long _));
    }

    private static ServiceProvider CreateProvider(bool enabled)
    {
        var services = new ServiceCollection();

        services.AddOpenIddict()
            .AddClient(options =>
            {
                options.AllowAuthorizationCodeFlow()
                       .SetRedirectionEndpointUris("callback/login");

                options.AddEphemeralEncryptionKey()
                       .AddEphemeralSigningKey();

                options.AddRegistration(new OpenIddictClientRegistration
                {
                    ClientId = "Fabrikam",
                    Configuration = new OpenIddictConfiguration
                    {
                        Issuer = new Uri("https://www.contoso.com/", UriKind.Absolute)
                    },
                    Issuer = new Uri("https://www.contoso.com/", UriKind.Absolute),
                    SigningCredentials = { new SigningCredentials(SigningKey, SecurityAlgorithms.RsaSha256) },
                    UseSignedRequestObjects = enabled
                });
            });

        return services.BuildServiceProvider();
    }

    private static ProcessChallengeContext CreateContext(IServiceProvider provider)
    {
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>().CurrentValue;

        var transaction = new OpenIddictClientTransaction
        {
            CancellationToken = CancellationToken.None,
            Configuration = new OpenIddictConfiguration(),
            Options = options,
            Registration = options.Registrations[0],
            Request = new OpenIddictRequest(),
            ServiceProvider = provider
        };

        return new ProcessChallengeContext(transaction)
        {
            ClientId = "Fabrikam",
            GrantType = GrantTypes.AuthorizationCode,
            Principal = new ClaimsPrincipal(new ClaimsIdentity())
        };
    }
}
