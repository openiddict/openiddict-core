/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using static OpenIddict.Client.OpenIddictClientEvents;
using static OpenIddict.Client.OpenIddictClientHandlers;
using static OpenIddict.Client.OpenIddictClientHandlers.Discovery;

namespace OpenIddict.Client.Tests;

public class OpenIddictClientHandlersJarmTests
{
    private const string Issuer = "https://www.contoso.com/";
    private const string State = "state_token";

    private static readonly RsaSecurityKey ServerSigningKey = new(RSA.Create(keySizeInBits: 2048)) { KeyId = "server_key" };

    [Theory]
    [InlineData(ResponseModes.Query, ResponseModes.QueryJwt)]
    [InlineData(ResponseModes.Fragment, ResponseModes.FragmentJwt)]
    [InlineData(ResponseModes.FormPost, ResponseModes.FormPostJwt)]
    [InlineData(ResponseModes.Jwt, ResponseModes.Jwt)]
    public async Task AttachJwtResponseMode_ResponseModeIsReplacedWhenRequired(string mode, string expected)
    {
        // Arrange
        using var provider = CreateProvider(required: true);
        var context = new ProcessChallengeContext(CreateTransaction(provider)) { ResponseMode = mode };

        // Act
        await new AttachJwtResponseMode().HandleAsync(context);

        // Assert
        Assert.Equal(expected, context.ResponseMode);
    }

    [Fact]
    public async Task AttachJwtResponseMode_ResponseModeIsNotReplacedWhenNotRequired()
    {
        // Arrange
        using var provider = CreateProvider(required: false);
        var context = new ProcessChallengeContext(CreateTransaction(provider)) { ResponseMode = ResponseModes.Query };

        // Act
        await new AttachJwtResponseMode().HandleAsync(context);

        // Assert
        Assert.Equal(ResponseModes.Query, context.ResponseMode);
    }

    [Fact]
    public async Task AttachJwtResponseMode_ThrowsAnExceptionWhenServerDoesNotSupportJwtVariant()
    {
        // Arrange
        using var provider = CreateProvider(required: true);
        var transaction = CreateTransaction(provider);
        transaction.Configuration.ResponseModesSupported.Add(ResponseModes.Query);

        var context = new ProcessChallengeContext(transaction) { ResponseMode = ResponseModes.Query };

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await new AttachJwtResponseMode().HandleAsync(context));

        Assert.Equal(SR.FormatID0647(ResponseModes.QueryJwt), exception.Message);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ResolveAuthorizationResponseToken_StateIsExtractedFromToken(bool encrypted)
    {
        // Arrange
        using var provider = CreateProvider(required: true);
        var context = CreateAuthenticationContext(provider, CreateToken(encryption: encrypted ? GetEncryptionCredentials(provider) : null));
        context.AuthorizationResponseToken = null;
        context.ExtractStateToken = true;
        context.StateToken = null;

        // Act
        await new ResolveAuthorizationResponseToken().HandleAsync(context);

        // Assert
        Assert.NotNull(context.AuthorizationResponseToken);
        Assert.Equal(State, context.StateToken);
    }

    [Fact]
    public async Task ResolveAuthorizationResponseToken_MalformedTokenIsIgnored()
    {
        // Arrange
        using var provider = CreateProvider(required: true);
        var context = CreateAuthenticationContext(provider, "malformed");
        context.AuthorizationResponseToken = null;
        context.ExtractStateToken = true;
        context.StateToken = null;

        // Act
        await new ResolveAuthorizationResponseToken().HandleAsync(context);

        // Assert
        Assert.Equal("malformed", context.AuthorizationResponseToken);
        Assert.Null(context.StateToken);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ValidateAuthorizationResponseToken_ParametersAreExtractedFromValidToken(bool encrypted)
    {
        // Arrange
        using var provider = CreateProvider(required: true);
        var context = CreateAuthenticationContext(provider, CreateToken(encryption: encrypted ? GetEncryptionCredentials(provider) : null));
        context.Request[Parameters.Code] = "injected_code";

        // Act
        await CreateHandler(provider).HandleAsync(context);

        // Assert
        Assert.False(context.IsRejected);
        Assert.NotNull(context.AuthorizationResponseTokenPrincipal);
        Assert.Equal("SplxlOBeZQQYbYS6WxSbIA", context.Request.Code);
        Assert.Equal(State, context.Request.State);
        Assert.Null(context.Request[Parameters.Response]);
        Assert.Null(context.Request[Claims.Audience]);
        Assert.Null(context.Request[Claims.ExpiresAt]);
        Assert.Null(context.Request[Parameters.Iss]);
    }

    [Fact]
    public async Task ValidateAuthorizationResponseToken_IssuerParameterIsKeptWhenSupported()
    {
        // Arrange
        using var provider = CreateProvider(required: true);
        var context = CreateAuthenticationContext(provider, CreateToken());
        context.Configuration.AuthorizationResponseIssParameterSupported = true;

        // Act
        await CreateHandler(provider).HandleAsync(context);

        // Assert
        Assert.False(context.IsRejected);
        Assert.Equal(Issuer, (string?) context.Request[Parameters.Iss]);
    }

    [Fact]
    public async Task ValidateAuthorizationResponseToken_ErrorsAreExtractedFromToken()
    {
        // Arrange
        using var provider = CreateProvider(required: true);
        var context = CreateAuthenticationContext(provider, CreateToken(parameters: new(StringComparer.Ordinal)
        {
            [Parameters.Error] = Errors.AccessDenied,
            [Parameters.State] = State
        }));

        // Act
        await CreateHandler(provider).HandleAsync(context);

        // Assert
        Assert.False(context.IsRejected);
        Assert.Equal(Errors.AccessDenied, (string?) context.Request[Parameters.Error]);
    }

    [Fact]
    public async Task ValidateAuthorizationResponseToken_MissingTokenIsRejectedWhenRequired()
    {
        // Arrange
        using var provider = CreateProvider(required: true);
        var context = CreateAuthenticationContext(provider, token: null);

        // Act
        await CreateHandler(provider).HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(Errors.InvalidRequest, context.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2321), context.ErrorDescription);
    }

    [Theory]
    [InlineData(ResponseModes.QueryJwt, true)]
    [InlineData(ResponseModes.Query, false)]
    [InlineData(null, false)]
    public async Task ValidateAuthorizationResponseToken_MissingTokenIsRejectedWhenJwtResponseModeWasUsed(string? mode, bool rejected)
    {
        // Arrange
        using var provider = CreateProvider(required: false);
        var context = CreateAuthenticationContext(provider, token: null);
        context.StateTokenPrincipal!.SetClaim(Claims.Private.ResponseMode, mode);

        // Act
        await CreateHandler(provider).HandleAsync(context);

        // Assert
        Assert.Equal(rejected, context.IsRejected);
    }

    [Fact]
    public async Task ValidateAuthorizationResponseToken_TokenSignedWithUntrustedKeyIsRejected()
    {
        // Arrange
        using var provider = CreateProvider(required: true);
        var context = CreateAuthenticationContext(provider, CreateToken(signing: new SigningCredentials(
            new RsaSecurityKey(RSA.Create(keySizeInBits: 2048)) { KeyId = "server_key" }, SecurityAlgorithms.RsaSha256)));

        // Act
        await CreateHandler(provider).HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(SR.GetResourceString(SR.ID2322), context.ErrorDescription);
    }

    [Fact]
    public async Task ValidateAuthorizationResponseToken_TokenSignedWithClientKeyIsRejected()
    {
        // Arrange
        using var provider = CreateProvider(required: true);
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>().CurrentValue;
        var context = CreateAuthenticationContext(provider, CreateToken(signing: options.SigningCredentials[0]));

        // Act
        await CreateHandler(provider).HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(SR.GetResourceString(SR.ID2322), context.ErrorDescription);
    }

    [Fact]
    public async Task ValidateAuthorizationResponseToken_UnsignedTokenIsRejected()
    {
        // Arrange
        using var provider = CreateProvider(required: true);
        var context = CreateAuthenticationContext(provider, CreateToken(unsigned: true));

        // Act
        await CreateHandler(provider).HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(SR.GetResourceString(SR.ID2322), context.ErrorDescription);
    }

    [Fact]
    public async Task ValidateAuthorizationResponseToken_TokenFromAnotherIssuerIsRejected()
    {
        // Arrange
        using var provider = CreateProvider(required: true);
        var context = CreateAuthenticationContext(provider, CreateToken(issuer: "https://www.fabrikam.com/"));

        // Act
        await CreateHandler(provider).HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(SR.GetResourceString(SR.ID2322), context.ErrorDescription);
    }

    [Fact]
    public async Task ValidateAuthorizationResponseToken_TokenIssuedToAnotherClientIsRejected()
    {
        // Arrange
        using var provider = CreateProvider(required: true);
        var context = CreateAuthenticationContext(provider, CreateToken(audience: "Contoso"));

        // Act
        await CreateHandler(provider).HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(SR.GetResourceString(SR.ID2323), context.ErrorDescription);
    }

    [Fact]
    public async Task ValidateAuthorizationResponseToken_TokenWithoutExpirationIsRejected()
    {
        // Arrange
        using var provider = CreateProvider(required: true);
        var context = CreateAuthenticationContext(provider, CreateToken(includeExpiration: false));

        // Act
        await CreateHandler(provider).HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(SR.FormatID2324(Claims.ExpiresAt), context.ErrorDescription);
    }

    [Fact]
    public async Task ValidateAuthorizationResponseToken_ExpiredTokenIsRejected()
    {
        // Arrange
        using var provider = CreateProvider(required: true);
        var context = CreateAuthenticationContext(provider, CreateToken(expiration: DateTimeOffset.UtcNow.AddMinutes(-5)));

        // Act
        await CreateHandler(provider).HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(SR.GetResourceString(SR.ID2322), context.ErrorDescription);
    }

    [Fact]
    public async Task ValidateAuthorizationResponseToken_TokenWithDifferentStateIsRejected()
    {
        // Arrange
        using var provider = CreateProvider(required: true);
        var context = CreateAuthenticationContext(provider, CreateToken(parameters: new(StringComparer.Ordinal)
        {
            [Parameters.Code] = "SplxlOBeZQQYbYS6WxSbIA",
            [Parameters.State] = "another_state_token"
        }));

        // Act
        await CreateHandler(provider).HandleAsync(context);

        // Assert
        Assert.True(context.IsRejected);
        Assert.Equal(SR.GetResourceString(SR.ID2322), context.ErrorDescription);
    }

    [Fact]
    public async Task ExtractAuthorizationResponseAlgorithms_AlgorithmsAreExtracted()
    {
        // Arrange
        using var provider = CreateProvider(required: false);
        var context = new HandleConfigurationResponseContext(CreateTransaction(provider))
        {
            Configuration = new OpenIddictConfiguration(),
            Response = new OpenIddictResponse
            {
                [Metadata.AuthorizationSigningAlgValuesSupported] = new OpenIddictParameter(JsonSerializer.SerializeToElement(new[] { SecurityAlgorithms.RsaSha256 })),
                [Metadata.AuthorizationEncryptionAlgValuesSupported] = new OpenIddictParameter(JsonSerializer.SerializeToElement(new[] { SecurityAlgorithms.RsaOAEP })),
                [Metadata.AuthorizationEncryptionEncValuesSupported] = new OpenIddictParameter(JsonSerializer.SerializeToElement(new[] { SecurityAlgorithms.Aes128CbcHmacSha256 }))
            }
        };

        // Act
        await new ExtractAuthorizationResponseAlgorithms().HandleAsync(context);

        // Assert
        Assert.Equal([SecurityAlgorithms.RsaSha256], context.Configuration.AuthorizationSigningAlgValuesSupported);
        Assert.Equal([SecurityAlgorithms.RsaOAEP], context.Configuration.AuthorizationEncryptionAlgValuesSupported);
        Assert.Equal([SecurityAlgorithms.Aes128CbcHmacSha256], context.Configuration.AuthorizationEncryptionEncValuesSupported);
    }

    private static ValidateAuthorizationResponseToken CreateHandler(IServiceProvider provider)
        => new(provider.GetRequiredService<IOpenIddictClientDispatcher>());

    private static EncryptingCredentials GetEncryptionCredentials(IServiceProvider provider)
    {
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>().CurrentValue;

        return new EncryptingCredentials(options.EncryptionCredentials[0].Key,
            SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes128CbcHmacSha256);
    }

    private static string CreateToken(
        string issuer = Issuer,
        string audience = "Fabrikam",
        Dictionary<string, object>? parameters = null,
        SigningCredentials? signing = null,
        EncryptingCredentials? encryption = null,
        bool unsigned = false,
        DateTimeOffset? expiration = null,
        bool includeExpiration = true)
    {
        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [Claims.Audience] = audience,
            [Claims.Issuer] = issuer
        };

        if (includeExpiration)
        {
            claims[Claims.ExpiresAt] = (expiration ?? DateTimeOffset.UtcNow.AddMinutes(5)).ToUnixTimeSeconds();
        }

        foreach (var parameter in parameters ?? new(StringComparer.Ordinal)
        {
            [Parameters.Code] = "SplxlOBeZQQYbYS6WxSbIA",
            [Parameters.State] = State
        })
        {
            claims[parameter.Key] = parameter.Value;
        }

        return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor
        {
            Claims = claims,
            EncryptingCredentials = encryption,
            SigningCredentials = unsigned ? null : signing ?? new SigningCredentials(ServerSigningKey, SecurityAlgorithms.RsaSha256)
        });
    }

    private static OpenIddictClientTransaction CreateTransaction(IServiceProvider provider)
    {
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>().CurrentValue;

        var configuration = new OpenIddictConfiguration { Issuer = new Uri(Issuer, UriKind.Absolute) };
        configuration.SigningKeys.Add(ServerSigningKey);

        return new OpenIddictClientTransaction
        {
            CancellationToken = CancellationToken.None,
            Configuration = configuration,
            EndpointType = OpenIddictClientEndpointType.Redirection,
            Options = options,
            Registration = options.Registrations[0],
            ServiceProvider = provider
        };
    }

    private static ProcessAuthenticationContext CreateAuthenticationContext(IServiceProvider provider, string? token)
    {
        var transaction = CreateTransaction(provider);
        transaction.Request = new OpenIddictRequest();

        if (token is not null)
        {
            transaction.Request[Parameters.Response] = token;
        }

        return new ProcessAuthenticationContext(transaction)
        {
            AuthorizationResponseToken = token,
            StateToken = State,
            StateTokenPrincipal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
        };
    }

    private static ServiceProvider CreateProvider(bool required)
    {
        var services = new ServiceCollection();

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
                    Configuration = new OpenIddictConfiguration
                    {
                        Issuer = new Uri(Issuer, UriKind.Absolute)
                    },
                    Issuer = new Uri(Issuer, UriKind.Absolute),
                    RegistrationId = "Contoso",
                    RequireJwtSecuredAuthorizationResponses = required
                });
            });

        return services.BuildServiceProvider();
    }
}
