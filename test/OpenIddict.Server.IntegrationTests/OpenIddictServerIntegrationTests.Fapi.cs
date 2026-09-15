/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers;
using static OpenIddict.Server.OpenIddictServerHandlers.Protection;

namespace OpenIddict.Server.IntegrationTests;

public abstract partial class OpenIddictServerIntegrationTests
{
    [Fact]
    public async Task HandleConfigurationRequest_Fapi2SecurityProfileMetadataIsReturned()
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureFapiServer);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.Equal([CodeChallengeMethods.Sha256], (ImmutableArray<string?>?) response[Metadata.CodeChallengeMethodsSupported]);
        Assert.Equal([ResponseTypes.Code], (ImmutableArray<string?>?) response[Metadata.ResponseTypesSupported]);
        Assert.True((bool) response[Metadata.RequirePushedAuthorizationRequests]);
        Assert.True((bool) response[Metadata.AuthorizationResponseIssParameterSupported]);

        var methods = (ImmutableArray<string?>?) response[Metadata.TokenEndpointAuthMethodsSupported];
        Assert.NotNull(methods);
        Assert.Contains(ClientAuthenticationMethods.PrivateKeyJwt, methods.Value, StringComparer.Ordinal);
        Assert.DoesNotContain(ClientAuthenticationMethods.ClientSecretBasic, methods.Value, StringComparer.Ordinal);
        Assert.DoesNotContain(ClientAuthenticationMethods.ClientSecretPost, methods.Value, StringComparer.Ordinal);

        var grants = (ImmutableArray<string?>?) response[Metadata.GrantTypesSupported];
        Assert.NotNull(grants);
        Assert.DoesNotContain(GrantTypes.Password, grants.Value, StringComparer.Ordinal);
        Assert.DoesNotContain(GrantTypes.Implicit, grants.Value, StringComparer.Ordinal);

        Assert.Equal([SecurityAlgorithms.RsaSsaPssSha256], ((ImmutableArray<string?>?) response[Metadata.IdTokenSigningAlgValuesSupported])!.Value, StringComparer.Ordinal);
        Assert.Equal([SecurityAlgorithms.EcdsaSha256, SecurityAlgorithms.RsaSsaPssSha256],
            ((ImmutableArray<string?>?) response[Metadata.DPoPSigningAlgValuesSupported])!.Value.Order(StringComparer.Ordinal), StringComparer.Ordinal);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_Fapi2SecurityProfileRejectsRequestsSentWithoutPar()
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureFapiServer);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            CodeChallengeMethod = CodeChallengeMethods.Sha256,
            RedirectUri = "https://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2029(Parameters.RequestUri), response.ErrorDescription);

        // Note: errors returned before the redirect_uri is validated must never be sent to the
        // client (FAPI 2.0 forbids open redirectors), in which case no "iss" parameter is attached.
        Assert.Null(response.Iss);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(CodeChallengeMethods.Plain)]
    public async Task ValidatePushedAuthorizationRequest_Fapi2SecurityProfileRequiresS256CodeChallenge(string? method)
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureFapiServer);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            CodeChallengeMethod = method,
            RedirectUri = "https://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(method is null ? SR.FormatID2029(Parameters.CodeChallengeMethod) : SR.FormatID2032(Parameters.CodeChallengeMethod),
            response.ErrorDescription);
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_Fapi2SecurityProfileRequiresCodeChallenge()
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureFapiServer);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "https://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2029(Parameters.CodeChallenge), response.ErrorDescription);
    }

    [Theory]
    [InlineData("code id_token")]
    [InlineData("token")]
    public async Task ValidatePushedAuthorizationRequest_Fapi2SecurityProfileRejectsImplicitAndHybridResponseTypes(string type)
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureFapiServer);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            CodeChallengeMethod = CodeChallengeMethods.Sha256,
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "https://www.fabrikam.com/path",
            ResponseType = type,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.UnsupportedResponseType, response.Error);
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_Fapi2SecurityProfileRequiresRedirectUri()
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureFapiServer);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", CreateFapiPushedAuthorizationRequest(redirectUri: null));

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2029(Parameters.RedirectUri), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2029), response.ErrorUri);
    }

    [Theory]
    [InlineData("http://www.fabrikam.com/path")]
    [InlineData("http://localhost:5000/callback")]
    public async Task ValidatePushedAuthorizationRequest_Fapi2SecurityProfileRejectsNonLoopbackHttpRedirectUri(string uri)
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureFapiServer);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", CreateFapiPushedAuthorizationRequest(uri));

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2484(Parameters.RedirectUri), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2484), response.ErrorUri);
    }

    [Theory]
    [InlineData("https://www.fabrikam.com/path")]
    [InlineData("http://127.0.0.1:5000/callback")]
    [InlineData("http://[::1]:5000/callback")]
    [InlineData("com.fabrikam.app:/callback")]
    public async Task ValidatePushedAuthorizationRequest_Fapi2SecurityProfileAcceptsHttpsLoopbackAndPrivateUseRedirectUris(string uri)
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureFapiServer);
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", CreateFapiPushedAuthorizationRequest(uri));

        // Assert
        Assert.Null(response.Error);
        Assert.NotNull(response.RequestUri);
    }

    [Fact]
    public async Task HandlePushedAuthorizationRequest_Fapi2SecurityProfileLimitsRequestUriLifetime()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            ConfigureFapiServer(options);

            // Attach a lifetime that exceeds the maximum value allowed by the profile.
            options.AddEventHandler<ProcessSignInContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    context.Principal!.SetRequestTokenLifetime(TimeSpan.FromHours(1));

                    return ValueTask.CompletedTask;
                });

                builder.SetOrder(PrepareRequestTokenPrincipal.Descriptor.Order - 1);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", CreateFapiPushedAuthorizationRequest("https://www.fabrikam.com/path"));

        // Assert
        Assert.Null(response.Error);
        Assert.NotNull(response.ExpiresIn);
        Assert.InRange(response.ExpiresIn.Value, 1, 300);
    }

    [Fact]
    public async Task ProcessSignIn_Fapi2SecurityProfileLimitsAuthorizationCodeLifetimeAndReturnsIssuer()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            ConfigureFapiServer(options);

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique")
                        .SetAuthorizationCodeLifetime(TimeSpan.FromMinutes(10));

                    return ValueTask.CompletedTask;
                }));

            options.AddEventHandler<ProcessSignInContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    if (context.EndpointType is not OpenIddictServerEndpointType.Authorization)
                    {
                        return ValueTask.CompletedTask;
                    }

                    Assert.NotNull(context.AuthorizationCodePrincipal);
                    Assert.Equal(TimeSpan.FromSeconds(60),
                        context.AuthorizationCodePrincipal.GetExpirationDate() - context.AuthorizationCodePrincipal.GetCreationDate());

                    return ValueTask.CompletedTask;
                });

                builder.SetOrder(Fapi.LimitAuthorizationCodeLifetime.Descriptor.Order + 1);
            });
        });

        await using var client = await server.CreateClientAsync();

        var pushed = await client.PostAsync("/connect/par", CreateFapiPushedAuthorizationRequest("https://www.fabrikam.com/path"));
        Assert.NotNull(pushed.RequestUri);

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RequestUri = pushed.RequestUri
        });

        // Assert
        Assert.Null(response.Error);
        Assert.NotNull(response.Code);
        Assert.Equal("http://localhost/", response.Iss);
    }

    [Fact]
    public async Task ValidateTokenRequest_Fapi2SecurityProfileRejectsClientSecrets()
    {
        // Arrange
        await using var server = await CreateServerAsync(ConfigureFapiServer);
        await using var client = await server.CreateClientAsync();
        client.RequestHeaders["DPoP"] = [CreateDPoPProof()];

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
            GrantType = GrantTypes.ClientCredentials
        });

        // Assert
        //
        // Note: the client secret authentication methods are removed from the server options by the profile,
        // so the request is rejected before Fapi.ValidateClientAuthentication is invoked (covered by unit tests).
        Assert.Equal(Errors.InvalidClient, response.Error);
        Assert.Equal(SR.FormatID2174(ClientAuthenticationMethods.ClientSecretPost), response.ErrorDescription);
    }

    [Fact]
    public async Task ValidateIntrospectionRequest_Fapi2SecurityProfileRejectsPublicClients()
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);
        });

        await using var server = await CreateServerAsync(options =>
        {
            ConfigureFapiServer(options);

            options.Configure(options => options.EnableDegradedMode = false);
            options.Services.AddSingleton(manager);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Token = "2YotnFZFEjr1zCsicMWpAA"
        });

        // Assert
        Assert.Equal(Errors.InvalidClient, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2482), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2482), response.ErrorUri);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ValidateTokenRequest_Fapi2SecurityProfileRequiresClientAssertionsWithStringAudience(bool array)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            ConfigureFapiServer(options);
            AttachClientAssertionPrincipal(options);
        });

        await using var client = await server.CreateClientAsync();
        client.RequestHeaders["DPoP"] = [CreateDPoPProof()];

        // Note: the principal is attached by the test handler, but the raw payload is inspected by the profile.
        var payload = new JsonObject
        {
            [Claims.Audience] = array ? new JsonArray("http://localhost/") : (JsonNode) JsonValue.Create("http://localhost/"),
            [Claims.Issuer] = "Fabrikam",
            [Claims.Subject] = "Fabrikam"
        };

        var assertion = string.Concat(
            Base64UrlEncoder.Encode("""{"alg":"PS256","typ":"JWT"}"""), ".",
            Base64UrlEncoder.Encode(payload.ToJsonString()), ".",
            Base64UrlEncoder.Encode("signature"));

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            ClientAssertion = assertion,
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            GrantType = GrantTypes.ClientCredentials
        });

        // Assert
        if (array)
        {
            Assert.Equal(Errors.InvalidClient, response.Error);
            Assert.Equal(SR.GetResourceString(SR.ID2481), response.ErrorDescription);
            Assert.Equal(SR.FormatID8000(SR.ID2481), response.ErrorUri);
        }

        else
        {
            Assert.Null(response.Error);
            Assert.Equal(TokenTypes.DPoP, response.TokenType);
        }
    }

    [Fact]
    public async Task ValidateTokenRequest_Fapi2SecurityProfileRejectsClientAssertionsIssuedInTheFuture()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            ConfigureFapiServer(options);
            AttachClientAssertionPrincipal(options, issuedAt: DateTimeOffset.UtcNow.AddMinutes(5));
        });

        await using var client = await server.CreateClientAsync();
        client.RequestHeaders["DPoP"] = [CreateDPoPProof()];

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            ClientAssertion = "assertion",
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            GrantType = GrantTypes.ClientCredentials
        });

        // Assert
        Assert.Equal(Errors.InvalidClient, response.Error);
        Assert.Equal(SR.FormatID2485(Claims.IssuedAt), response.ErrorDescription);
    }

    [Fact]
    public async Task ValidateTokenRequest_Fapi2SecurityProfileAcceptsClientAssertionsIssuedSlightlyInTheFuture()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            ConfigureFapiServer(options);
            AttachClientAssertionPrincipal(options, issuedAt: DateTimeOffset.UtcNow.AddSeconds(10));
        });

        await using var client = await server.CreateClientAsync();
        client.RequestHeaders["DPoP"] = [CreateDPoPProof()];

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            ClientAssertion = "assertion",
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            GrantType = GrantTypes.ClientCredentials
        });

        // Assert
        Assert.Null(response.Error);
        Assert.Equal(TokenTypes.DPoP, response.TokenType);
    }

    [Theory]
    [InlineData(SecurityAlgorithms.RsaSsaPssSha256, true)]
    [InlineData(SecurityAlgorithms.EcdsaSha256, true)]
    [InlineData(SecurityAlgorithms.RsaSha256, false)]
    [InlineData(SecurityAlgorithms.HmacSha256, false)]
    [InlineData(SecurityAlgorithms.EcdsaSha384, false)]
    public async Task ValidateTokenRequest_Fapi2SecurityProfileRestrictsClientAssertionAlgorithms(string algorithm, bool valid)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            ConfigureFapiServer(options);
            AttachFapiClientSigningKeys(options, TokenTypeIdentifiers.Private.ClientAssertion);
        });

        await using var client = await server.CreateClientAsync();
        client.RequestHeaders["DPoP"] = [CreateDPoPProof()];

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            ClientAssertion = CreateFapiClientToken(algorithm, JsonWebTokenTypes.ClientAuthentication, new(StringComparer.Ordinal)
            {
                [Claims.JwtId] = Guid.NewGuid().ToString(),
                [Claims.Subject] = "Fabrikam"
            }),
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            GrantType = GrantTypes.ClientCredentials
        });

        // Assert
        if (valid)
        {
            Assert.Null(response.Error);
            Assert.Equal(TokenTypes.DPoP, response.TokenType);
        }

        else
        {
            Assert.Equal(Errors.InvalidClient, response.Error);
        }
    }

    [Theory]
    [InlineData(SecurityAlgorithms.RsaSsaPssSha256, false, true)]
    [InlineData(SecurityAlgorithms.RsaSsaPssSha256, true, true)]
    [InlineData(SecurityAlgorithms.EcdsaSha256, true, true)]
    [InlineData(SecurityAlgorithms.RsaSha256, false, false)]
    [InlineData(SecurityAlgorithms.RsaSha256, true, false)]
    [InlineData(SecurityAlgorithms.HmacSha256, false, false)]
    public async Task ValidatePushedAuthorizationRequest_Fapi2SecurityProfileRestrictsRequestObjectAlgorithms(
        string algorithm, bool encrypted, bool valid)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            ConfigureFapiServer(options);
            options.EnableRequestObjectSupport();
            options.AddEncryptionKey(FapiServerEncryptionKey);
            AttachFapiClientSigningKeys(options, TokenTypeIdentifiers.Private.RequestObject);
        });

        await using var client = await server.CreateClientAsync();

        // Note: the key management and content encryption algorithms of encrypted
        // request objects must not be restricted by the allowed signing algorithms.
        var request = CreateFapiClientToken(algorithm, JsonWebTokenTypes.AuthorizationRequest, CreateFapiRequestObjectClaims(),
            encryption: encrypted ? new EncryptingCredentials(FapiServerEncryptionKey,
                SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes256CbcHmacSha512) : null);

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Request = request
        });

        // Assert
        if (valid)
        {
            Assert.Null(response.Error);
            Assert.NotNull(response.RequestUri);
        }

        else
        {
            Assert.Equal(Errors.InvalidRequestObject, response.Error);
            Assert.Equal(SR.GetResourceString(SR.ID2211), response.ErrorDescription);
        }
    }

    [Theory]
    [InlineData(120, false)]
    [InlineData(10, true)]
    public async Task ValidatePushedAuthorizationRequest_Fapi2SecurityProfileRejectsRequestObjectsIssuedInTheFuture(int offset, bool valid)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            ConfigureFapiServer(options);
            options.EnableRequestObjectSupport();
            AttachFapiClientSigningKeys(options, TokenTypeIdentifiers.Private.RequestObject);
        });

        await using var client = await server.CreateClientAsync();

        var claims = CreateFapiRequestObjectClaims();
        claims[Claims.IssuedAt] = DateTimeOffset.UtcNow.AddSeconds(offset).ToUnixTimeSeconds();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Request = CreateFapiClientToken(SecurityAlgorithms.RsaSsaPssSha256, JsonWebTokenTypes.AuthorizationRequest, claims)
        });

        // Assert
        if (valid)
        {
            Assert.Null(response.Error);
        }

        else
        {
            // Note: the specific error returned by the FAPI handler (ID2485) is replaced by a generic error.
            Assert.Equal(Errors.InvalidRequestObject, response.Error);
            Assert.Equal(SR.GetResourceString(SR.ID2211), response.ErrorDescription);
        }
    }

    [Fact]
    public async Task HandleConfigurationRequest_Fapi2SecurityProfileRestrictsRequestObjectSigningAlgorithms()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            ConfigureFapiServer(options);
            options.EnableRequestObjectSupport();
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.Equal([SecurityAlgorithms.RsaSsaPssSha256, SecurityAlgorithms.EcdsaSha256],
            ((ImmutableArray<string?>?) response[Metadata.RequestObjectSigningAlgValuesSupported])!.Value, StringComparer.Ordinal);
    }

    [Fact]
    public async Task ValidateTokenRequest_Fapi2SecurityProfileRequiresSenderConstrainedAccessTokens()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            ConfigureFapiServer(options);
            AttachClientAssertionPrincipal(options);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            ClientAssertion = "assertion",
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            GrantType = GrantTypes.ClientCredentials
        });

        // Assert
        Assert.Equal(Errors.InvalidDPoPProof, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2483), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2483), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateTokenRequest_Fapi2SecurityProfileReturnsDPoPBoundAccessTokens()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            ConfigureFapiServer(options);
            AttachClientAssertionPrincipal(options);
        });

        await using var client = await server.CreateClientAsync();
        client.RequestHeaders["DPoP"] = [CreateDPoPProof()];

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            ClientAssertion = "assertion",
            ClientAssertionType = ClientAssertionTypes.JwtBearer,
            GrantType = GrantTypes.ClientCredentials
        });

        // Assert
        Assert.Null(response.Error);
        Assert.NotNull(response.AccessToken);
        Assert.Equal(TokenTypes.DPoP, response.TokenType);
    }

    [Fact]
    public async Task ValidateTokenRequest_SenderConstraintIsNotRequiredWhenProfileIsDisabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            ConfigureFapiServer(options);
            options.Configure(options => options.EnableFapi2SecurityProfile = false);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
            GrantType = GrantTypes.ClientCredentials
        });

        // Assert
        Assert.Null(response.Error);
        Assert.Equal(TokenTypes.Bearer, response.TokenType);
    }

    private static void ConfigureFapiServer(OpenIddictServerBuilder options)
    {
        options.EnableDegradedMode();
        options.EnableDPoPSupport();

        // Note: the flows enabled by default in the tests are not allowed by the FAPI 2.0 security profile.
        options.Configure(options =>
        {
            options.AcceptAnonymousClients = false;
            options.GrantTypes.Remove(GrantTypes.Implicit);
            options.GrantTypes.Remove(GrantTypes.Password);
            options.ResponseTypes.RemoveWhere(static type => type is not ResponseTypes.Code);
        });

        options.EnableFapi2SecurityProfile();

        options.AddEventHandler<HandleTokenRequestContext>(builder =>
            builder.UseInlineHandler(context =>
            {
                context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                    .SetClaim(Claims.Subject, "Bob le Magnifique");

                return ValueTask.CompletedTask;
            }));
    }

    private static void AttachClientAssertionPrincipal(OpenIddictServerBuilder options, DateTimeOffset? issuedAt = null)
    {
        options.AddEventHandler<ValidateTokenContext>(builder =>
        {
            builder.UseInlineHandler(context =>
            {
                if (!context.ValidTokenTypes.Contains(TokenTypeIdentifiers.Private.ClientAssertion))
                {
                    return ValueTask.CompletedTask;
                }

                var identity = new ClaimsIdentity("Bearer");
                identity.AddClaim(new Claim(Claims.Issuer, "Fabrikam"));
                identity.AddClaim(new Claim(Claims.Subject, "Fabrikam"));
                identity.AddClaim(new Claim(Claims.ExpiresAt,
                    DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64));
                identity.AddClaim(new Claim(Claims.IssuedAt,
                    (issuedAt ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64));

                context.Principal = new ClaimsPrincipal(identity)
                    .SetTokenType(TokenTypeIdentifiers.Private.ClientAssertion)
                    .SetClaim(Claims.Audience, "http://localhost/");

                return ValueTask.CompletedTask;
            });

            builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
        });
    }

    private static readonly RsaSecurityKey FapiClientRsaKey = new(RSA.Create(keySizeInBits: 2048)) { KeyId = "fapi_rsa" };
    private static readonly ECDsaSecurityKey FapiClientP256Key = new(ECDsa.Create(ECCurve.NamedCurves.nistP256)) { KeyId = "fapi_p256" };
    private static readonly ECDsaSecurityKey FapiClientP384Key = new(ECDsa.Create(ECCurve.NamedCurves.nistP384)) { KeyId = "fapi_p384" };
    private static readonly SymmetricSecurityKey FapiClientSymmetricKey = new(RandomNumberGenerator.GetBytes(32)) { KeyId = "fapi_hmac" };
    private static readonly RsaSecurityKey FapiServerEncryptionKey = new(RSA.Create(keySizeInBits: 2048)) { KeyId = "fapi_encryption" };

    private static void AttachFapiClientSigningKeys(OpenIddictServerBuilder options, string type)
    {
        // Note: in degraded mode, the signing keys used to validate client tokens must be attached manually.
        options.AddEventHandler<ValidateTokenContext>(builder =>
        {
            builder.UseInlineHandler(context =>
            {
                if (context.ValidTokenTypes.Contains(type))
                {
                    context.TokenValidationParameters.IssuerSigningKeys =
                        new SecurityKey[] { FapiClientRsaKey, FapiClientP256Key, FapiClientP384Key, FapiClientSymmetricKey };
                }

                return ValueTask.CompletedTask;
            });

            builder.SetOrder(ResolveTokenValidationParameters.Descriptor.Order + 500);
        });
    }

    private static Dictionary<string, object> CreateFapiRequestObjectClaims() => new(StringComparer.Ordinal)
    {
        [Claims.ClientId] = "Fabrikam",
        [Parameters.CodeChallenge] = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        [Parameters.CodeChallengeMethod] = CodeChallengeMethods.Sha256,
        [Parameters.RedirectUri] = "https://www.fabrikam.com/path",
        [Parameters.ResponseType] = ResponseTypes.Code
    };

    private static string CreateFapiClientToken(string algorithm, string type,
        Dictionary<string, object> claims, EncryptingCredentials? encryption = null)
    {
        SecurityKey key = algorithm switch
        {
            SecurityAlgorithms.EcdsaSha256 => FapiClientP256Key,
            SecurityAlgorithms.EcdsaSha384 => FapiClientP384Key,
            SecurityAlgorithms.HmacSha256  => FapiClientSymmetricKey,
            _                              => FapiClientRsaKey
        };

        var now = DateTimeOffset.UtcNow;

        if (!claims.ContainsKey(Claims.IssuedAt))
        {
            claims[Claims.IssuedAt] = now.ToUnixTimeSeconds();
        }

        return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor
        {
            Audience = "http://localhost/",
            Claims = claims,
            EncryptingCredentials = encryption,
            Expires = now.AddMinutes(1).UtcDateTime,
            Issuer = "Fabrikam",
            SigningCredentials = new SigningCredentials(key, algorithm),
            TokenType = type
        });
    }

    private static OpenIddictRequest CreateFapiPushedAuthorizationRequest(string? redirectUri) => new()
    {
        ClientId = "Fabrikam",
        CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        CodeChallengeMethod = CodeChallengeMethods.Sha256,
        RedirectUri = redirectUri,
        ResponseType = ResponseTypes.Code
    };
}
