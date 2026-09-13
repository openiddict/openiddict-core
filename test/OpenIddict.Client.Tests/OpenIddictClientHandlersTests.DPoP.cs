using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Client.SystemNetHttp;
using Xunit;
using static OpenIddict.Client.OpenIddictClientEvents;
using static OpenIddict.Client.OpenIddictClientHandlers;
using static OpenIddict.Client.SystemNetHttp.OpenIddictClientSystemNetHttpHandlers;

namespace OpenIddict.Client.Tests;

public class OpenIddictClientHandlersDPoPTests
{
    [Fact]
    public void PostConfigure_EphemeralDPoPKeyIsGeneratedWhenDPoPIsEnabled()
    {
        // Arrange
        using var provider = CreateProvider(enabled: true);

        // Act
        var registration = provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>().CurrentValue.Registrations[0];

        // Assert
        Assert.NotNull(registration.DPoPSigningCredentials);
        Assert.IsType<ECDsaSecurityKey>(registration.DPoPSigningCredentials.Key);
        Assert.Equal(SecurityAlgorithms.EcdsaSha256, registration.DPoPSigningCredentials.Algorithm);
    }

    [Fact]
    public void PostConfigure_NoDPoPKeyIsGeneratedWhenDPoPIsDisabled()
    {
        // Arrange
        using var provider = CreateProvider(enabled: false);

        // Act
        var registration = provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>().CurrentValue.Registrations[0];

        // Assert
        Assert.Null(registration.DPoPSigningCredentials);
    }

    [Theory]
    [InlineData(true, SecurityAlgorithms.EcdsaSha256, TokenBindingMethods.Private.DPoP)]
    [InlineData(true, SecurityAlgorithms.RsaSsaPssSha256, null)]
    [InlineData(true, null, null)]
    [InlineData(false, SecurityAlgorithms.EcdsaSha256, null)]
    public async Task AttachTokenEndpointTokenBindingMethod_DPoPIsNegotiatedWhenSupported(bool enabled, string? algorithm, string? expected)
    {
        // Arrange
        using var provider = CreateProvider(enabled);
        var context = CreateAuthenticationContext(provider);

        if (!string.IsNullOrEmpty(algorithm))
        {
            context.Configuration.DPoPSigningAlgValuesSupported.Add(algorithm);
        }

        // Act
        await new AttachTokenEndpointTokenBindingMethod().HandleAsync(context);

        // Assert
        Assert.Equal(expected, context.TokenEndpointTokenBindingMethod);
    }

    [Fact]
    public async Task ExtractDPoPSigningAlgorithms_MetadataIsExtracted()
    {
        // Arrange
        using var provider = CreateProvider(enabled: true);
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>().CurrentValue;

        var context = new HandleConfigurationResponseContext(new OpenIddictClientTransaction
        {
            CancellationToken = CancellationToken.None,
            Configuration = new OpenIddictConfiguration(),
            Options = options,
            Registration = options.Registrations[0],
            ServiceProvider = provider
        })
        {
            Response = new OpenIddictResponse(JsonSerializer.Deserialize<JsonElement>("""
            {
              "dpop_signing_alg_values_supported": [ "ES256", "PS256" ]
            }
            """))
        };

        // Act
        await new OpenIddictClientHandlers.Discovery.ExtractDPoPSigningAlgorithms().HandleAsync(context);

        // Assert
        Assert.True(context.Configuration.DPoPSigningAlgValuesSupported.SetEquals(["ES256", "PS256"]));
    }

    [Fact]
    public async Task CreateDPoPProofAsync_ValidProofIsReturned()
    {
        // Arrange
        using var provider = CreateProvider(enabled: true);
        var service = provider.GetRequiredService<OpenIddictClientService>();
        var registration = provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>().CurrentValue.Registrations[0];

        // Act
        var proof = await service.CreateDPoPProofAsync(registration, "GET",
            new Uri("https://api.contoso.com/resource?query=value#fragment"), token: "access_token", nonce: "nonce");

        // Assert
        var token = await ValidateProofAsync(proof);
        Assert.Equal("GET", token.GetPayloadValue<string>(Claims.HttpMethod));
        Assert.Equal("https://api.contoso.com/resource", token.GetPayloadValue<string>(Claims.HttpUri));
        Assert.Equal("nonce", token.GetPayloadValue<string>(Claims.Nonce));
        Assert.Equal(Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes("access_token"))),
            token.GetPayloadValue<string>(Claims.DPoPAccessTokenHash));
        Assert.False(string.IsNullOrEmpty(token.GetPayloadValue<string>(Claims.JwtId)));

        var jwk = token.GetHeaderValue<JsonElement>(JwtHeaderParameterNames.Jwk);
        Assert.False(jwk.TryGetProperty(JsonWebKeyParameterNames.D, out _));
        Assert.Equal(service.GetDPoPJsonWebKeyThumbprint(registration),
            Base64UrlEncoder.Encode(new JsonWebKey(jwk.GetRawText()).ComputeJwkThumbprint()));
    }

    [Theory]
    [InlineData("GET", "https://api.contoso.com/resource", null, "ES256")]
    [InlineData("POST", "https://api.contoso.com/resource?query", "access_token", "PS256")]
    public async Task CreateDPoPProofAsync_ProofIsAcceptedByDPoPProofValidator(string method, string uri, string? token, string algorithm)
    {
        // Arrange
        using var provider = CreateProvider(enabled: true);
        var service = provider.GetRequiredService<OpenIddictClientService>();
        var registration = provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>().CurrentValue.Registrations[0];

        if (algorithm is SecurityAlgorithms.RsaSsaPssSha256)
        {
            registration.DPoPSigningCredentials = new SigningCredentials(
                new RsaSecurityKey(RSA.Create(keySizeInBits: 2048)) { KeyId = "key" }, algorithm);
        }

        // Act
        var proof = await service.CreateDPoPProofAsync(registration, method, new Uri(uri), token);

        var result = await OpenIddictDPoPHelpers.ValidateProofAsync(proof, method, new Uri(uri),
            OpenIddictDPoPHelpers.SupportedAlgorithms, DateTimeOffset.UtcNow, TimeSpan.FromMinutes(1), token);

        // Assert
        Assert.Equal(OpenIddictDPoPHelpers.ProofError.None, result.Error);
        Assert.Equal(service.GetDPoPJsonWebKeyThumbprint(registration), result.Thumbprint);
    }

    [Fact]
    public async Task CreateDPoPProofAsync_ThrowsAnExceptionWhenNoDPoPKeyIsAvailable()
    {
        // Arrange
        using var provider = CreateProvider(enabled: false);
        var service = provider.GetRequiredService<OpenIddictClientService>();
        var registration = provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>().CurrentValue.Registrations[0];

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await service.CreateDPoPProofAsync(registration, "GET", new Uri("https://api.contoso.com/resource")));

        Assert.Equal(SR.GetResourceString(SR.ID0550), exception.Message);
    }

    [Fact]
    public async Task AuthenticateWithClientCredentialsAsync_TokenRequestIsSentAgainWithServerNonce()
    {
        // Arrange
        var nonces = new List<string?>();
        var attempts = 0;

        using var provider = CreateProvider(enabled: true, options =>
        {
            options.AddEventHandler<PrepareTokenRequestContext>(builder => builder.UseInlineHandler(context =>
            {
                Assert.NotNull(context.DPoPSigningCredentials);
                Assert.Equal("7Fjfp0ZBr1KtDRbnfVdmIw", context.Request.ClientSecret);

                nonces.Add(context.DPoPNonce);

                return ValueTask.CompletedTask;
            }));

            options.AddEventHandler<ExtractTokenResponseContext>(builder => builder.UseInlineHandler(context =>
            {
                context.DPoPNonce = "server_nonce";
                context.Response = ++attempts is 1
                    ? new OpenIddictResponse { Error = Errors.UseDPoPNonce }
                    : new OpenIddictResponse { AccessToken = "access_token", TokenType = TokenTypes.DPoP };

                return ValueTask.CompletedTask;
            }));
        });

        var service = provider.GetRequiredService<OpenIddictClientService>();

        // Act
        var result = await service.AuthenticateWithClientCredentialsAsync(new()
        {
            RegistrationId = "Contoso"
        });

        // Assert
        Assert.Equal("access_token", result.TokenResponse.AccessToken);
        Assert.Equal(TokenTypes.DPoP, result.TokenResponse.TokenType);
        Assert.Equal(new List<string?> { null, "server_nonce" }, nonces);
    }

    [Fact]
    public async Task AttachDPoPProof_ProofIsAttachedToHttpRequest()
    {
        // Arrange
        using var provider = CreateProvider(enabled: true);
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>().CurrentValue;

        using var message = new HttpRequestMessage(HttpMethod.Get, "https://www.contoso.com/connect/userinfo?parameter=value");
        message.Headers.Authorization = new("DPoP", "access_token");

        var transaction = new OpenIddictClientTransaction
        {
            CancellationToken = CancellationToken.None,
            Options = options,
            ServiceProvider = provider
        };

        transaction.SetProperty(typeof(HttpRequestMessage).FullName!, message);

        var context = new PrepareUserInfoRequestContext(transaction)
        {
            DPoPNonce = "nonce",
            DPoPSigningCredentials = options.Registrations[0].DPoPSigningCredentials,
            RemoteUri = new Uri("https://www.contoso.com/connect/userinfo")
        };

        // Act
        await new AttachDPoPProof<PrepareUserInfoRequestContext>().HandleAsync(context);

        // Assert
        Assert.NotNull(context.DPoPProof);
        Assert.Equal(context.DPoPProof, Assert.Single(message.Headers.GetValues("DPoP")));

        var token = await ValidateProofAsync(context.DPoPProof);
        Assert.Equal("GET", token.GetPayloadValue<string>(Claims.HttpMethod));
        Assert.Equal("https://www.contoso.com/connect/userinfo", token.GetPayloadValue<string>(Claims.HttpUri));
        Assert.Equal("nonce", token.GetPayloadValue<string>(Claims.Nonce));
        Assert.Equal(Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes("access_token"))),
            token.GetPayloadValue<string>(Claims.DPoPAccessTokenHash));
    }

    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public async Task SendPushedAuthorizationRequest_DPoPKeyIsOnlyUsedWhenCertificateBindingIsNotPossible(
        bool certificate, bool expected)
    {
        // Arrange
        SigningCredentials? credentials = null;

        using var provider = CreateProvider(enabled: true, options =>
        {
            options.AddEventHandler<PreparePushedAuthorizationRequestContext>(builder => builder.UseInlineHandler(context =>
            {
                credentials = context.DPoPSigningCredentials;
                context.HandleRequest();

                return ValueTask.CompletedTask;
            }));

            options.AddEventHandler<ExtractPushedAuthorizationResponseContext>(builder => builder.UseInlineHandler(context =>
            {
                context.Response = new OpenIddictResponse();
                context.HandleRequest();

                return ValueTask.CompletedTask;
            }));

            options.AddEventHandler<HandlePushedAuthorizationResponseContext>(builder => builder.UseInlineHandler(context =>
            {
                context.HandleRequest();

                return ValueTask.CompletedTask;
            }));
        });

        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>().CurrentValue;
        options.TokenBindingMethods.Add(TokenBindingMethods.Private.TlsClientCertificate);

        if (certificate)
        {
            options.Registrations[0].SigningCredentials.Add(new SigningCredentials(
                new X509SecurityKey(CreateClientAuthenticationCertificate()), SecurityAlgorithms.RsaSha256));
        }

        var context = new ProcessChallengeContext(new OpenIddictClientTransaction
        {
            CancellationToken = CancellationToken.None,
            Configuration = options.Registrations[0].Configuration!,
            Options = options,
            Registration = options.Registrations[0],
            ServiceProvider = provider
        })
        {
            PushedAuthorizationEndpoint = new Uri("https://www.contoso.com/connect/par"),
            PushedAuthorizationRequest = new OpenIddictRequest()
        };

        // Act
        await new SendPushedAuthorizationRequest(provider.GetRequiredService<OpenIddictClientService>()).HandleAsync(context);

        // Assert
        Assert.Equal(expected, credentials is not null);

        static X509Certificate2 CreateClientAuthenticationCertificate()
        {
            using var algorithm = RSA.Create(keySizeInBits: 2048);

            var request = new CertificateRequest("CN=OpenIddict Client Tests", algorithm, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") }, critical: false));

            return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        }
    }

    private static async Task<JsonWebToken> ValidateProofAsync(string proof)
    {
        var header = new JsonWebToken(proof).GetHeaderValue<JsonElement>(JwtHeaderParameterNames.Jwk);

        var result = await new JsonWebTokenHandler().ValidateTokenAsync(proof, new TokenValidationParameters
        {
            IssuerSigningKey = new JsonWebKey(header.GetRawText()),
            ValidateAudience = false,
            ValidateIssuer = false,
            ValidateLifetime = false,
            RequireExpirationTime = false,
            ValidTypes = [JsonWebTokenTypes.DPoPProof]
        });

        Assert.True(result.IsValid, result.Exception?.Message);

        return (JsonWebToken) result.SecurityToken;
    }

    private static ServiceProvider CreateProvider(bool enabled, Action<OpenIddictClientBuilder>? configuration = null)
    {
        var services = new ServiceCollection();

        services.AddOpenIddict()
            .AddClient(options =>
            {
                options.AllowClientCredentialsFlow();

                options.AddEphemeralEncryptionKey()
                       .AddEphemeralSigningKey();

                if (enabled)
                {
                    options.EnableDPoPTokenBinding();
                }

                options.AddRegistration(new OpenIddictClientRegistration
                {
                    ClientId = "Fabrikam",
                    ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                    Configuration = new OpenIddictConfiguration
                    {
                        DPoPSigningAlgValuesSupported = { SecurityAlgorithms.EcdsaSha256 },
                        GrantTypesSupported = { GrantTypes.ClientCredentials },
                        Issuer = new Uri("https://www.contoso.com/", UriKind.Absolute),
                        TokenEndpoint = new Uri("https://www.contoso.com/connect/token", UriKind.Absolute),
                        TokenEndpointAuthMethodsSupported = { ClientAuthenticationMethods.ClientSecretPost }
                    },
                    Issuer = new Uri("https://www.contoso.com/", UriKind.Absolute),
                    RegistrationId = "Contoso"
                });

                configuration?.Invoke(options);
            });

        return services.BuildServiceProvider();
    }

    private static ProcessAuthenticationContext CreateAuthenticationContext(IServiceProvider provider)
    {
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>().CurrentValue;

        var transaction = new OpenIddictClientTransaction
        {
            CancellationToken = CancellationToken.None,
            Configuration = new OpenIddictConfiguration(),
            Options = options,
            Registration = options.Registrations[0],
            ServiceProvider = provider
        };

        return new ProcessAuthenticationContext(transaction)
        {
            GrantType = GrantTypes.ClientCredentials
        };
    }
}
