

/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Tokens;
using Moq;
using OpenIddict.Core;
using Xunit;
using Xunit.Abstractions;
using static OpenIddict.Validation.OpenIddictValidationEvents;
using static OpenIddict.Validation.OpenIddictValidationHandlers;
using static OpenIddict.Validation.OpenIddictValidationHandlers.Protection;

namespace OpenIddict.Validation.IntegrationTests;

public abstract partial class OpenIddictValidationIntegrationTests
{
    protected OpenIddictValidationIntegrationTests(ITestOutputHelper outputHelper)
    {
        OutputHelper = outputHelper;
    }

    protected ITestOutputHelper OutputHelper { get; }

    [Fact]
    public async Task ProcessAuthentication_EvalutesCorrectValidatedTokens()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.AddEventHandler<ProcessAuthenticationContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    // Assert
                    Assert.True(context.ExtractAccessToken);
                    Assert.True(context.RequireAccessToken);
                    Assert.True(context.ValidateAccessToken);

                    return default;
                });

                builder.SetOrder(EvaluateValidatedTokens.Descriptor.Order + 1);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/authenticate", new OpenIddictRequest());

        // Assert
        Assert.Equal(0, response.Count);
    }

    [Fact]
    public async Task ProcessAuthentication_RejectsDemandWhenAccessTokenIsMissing()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.AddEventHandler<ProcessAuthenticationContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    // Assert
                    Assert.True(context.IsRejected);
                    Assert.Equal(Errors.MissingToken, context.Error);
                    Assert.Equal(SR.GetResourceString(SR.ID2000), context.ErrorDescription);

                    return default;
                });

                builder.SetOrder(ValidateRequiredTokens.Descriptor.Order + 1);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/authenticate", new OpenIddictRequest());

        // Assert
        Assert.Equal(0, response.Count);
    }

    [Fact]
    public async Task ProcessAuthentication_RejectsDemandWhenAccessTokenIsInvalid()
    {
        // Arrange
        await using var server = await CreateServerAsync();
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/authenticate", new OpenIddictRequest
        {
            AccessToken = "SlAV32hkKG"
        });

        // Assert
        Assert.Equal(Errors.InvalidToken, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2004), response.ErrorDescription);
    }

    [Fact]
    public async Task ProcessAuthentication_ReturnsExpectedIdentityWhenAccessTokenIsValid()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("access_token", context.Token);
                    Assert.Equal(new[] { TokenTypeHints.AccessToken }, context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeHints.AccessToken)
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/authenticate", new OpenIddictRequest
        {
            AccessToken = "access_token"
        });

        // Assert
        Assert.Equal("Bob le Magnifique", (string?) response[Claims.Subject]);
    }

    [Fact]
    public async Task ProcessChallenge_ReturnsDefaultErrorWhenNoneIsSpecified()
    {
        // Arrange
        await using var server = await CreateServerAsync();
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/challenge", new OpenIddictRequest());

        // Assert
        Assert.Equal(Errors.InsufficientAccess, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2095), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2095), response.ErrorUri);
    }

    [Theory]
    [InlineData("custom_error", null, null)]
    [InlineData("custom_error", "custom_description", null)]
    [InlineData("custom_error", "custom_description", "custom_uri")]
    [InlineData(null, "custom_description", null)]
    [InlineData(null, "custom_description", "custom_uri")]
    [InlineData(null, null, "custom_uri")]
    [InlineData(null, null, null)]
    public async Task ProcessChallenge_AllowsRejectingRequest(string error, string description, string uri)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.AddEventHandler<ProcessChallengeContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Reject(error, description, uri);

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/challenge", new OpenIddictRequest());

        // Assert
        Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
        Assert.Equal(description, response.ErrorDescription);
        Assert.Equal(uri, response.ErrorUri);
    }

    [Fact]
    public async Task ProcessChallenge_AllowsHandlingResponse()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.AddEventHandler<ProcessChallengeContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Transaction.SetProperty("custom_response", new
                    {
                        name = "Bob le Bricoleur"
                    });

                    context.HandleRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/challenge", new OpenIddictRequest());

        // Assert
        Assert.Equal("Bob le Bricoleur", (string?) response["name"]);
    }

    protected virtual void ConfigureServices(IServiceCollection services)
    {
        services.AddOpenIddict()
            .AddCore(options =>
            {
                options.SetDefaultAuthorizationEntity<OpenIddictAuthorization>()
                       .SetDefaultTokenEntity<OpenIddictToken>();

                options.Services.AddSingleton(CreateAuthorizationManager())
                                .AddSingleton(CreateTokenManager());
            })

            .AddValidation(options =>
            {
                options.SetIssuer(new Uri("https://contoso.com/"));

                options.SetConfiguration(new OpenIddictConfiguration
                {
                    SigningKeys =
                    {
                        new X509SecurityKey(GetSigningCertificate(
                            assembly: typeof(OpenIddictValidationIntegrationTests).Assembly,
                            resource: "OpenIddict.Validation.IntegrationTests.Certificate.cer",
                            password: null))
                    }
                });
            });

        static X509Certificate2 GetSigningCertificate(Assembly assembly, string resource, string? password)
        {
            using var stream = assembly.GetManifestResourceStream(resource) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0064));

            using var buffer = new MemoryStream();
            stream.CopyTo(buffer);

            return new X509Certificate2(buffer.ToArray(), password, X509KeyStorageFlags.MachineKeySet);
        }
    }

    protected abstract ValueTask<OpenIddictValidationIntegrationTestServer> CreateServerAsync(
        Action<OpenIddictValidationBuilder>? configuration = null);

    protected OpenIddictAuthorizationManager<OpenIddictAuthorization> CreateAuthorizationManager(
        Action<Mock<OpenIddictAuthorizationManager<OpenIddictAuthorization>>>? configuration = null)
    {
        var manager = new Mock<OpenIddictAuthorizationManager<OpenIddictAuthorization>>(
            Mock.Of<IOpenIddictAuthorizationCache<OpenIddictAuthorization>>(),
            OutputHelper.ToLogger<OpenIddictAuthorizationManager<OpenIddictAuthorization>>(),
            Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(),
            Mock.Of<IOpenIddictAuthorizationStoreResolver>());

        configuration?.Invoke(manager);

        return manager.Object;
    }

    protected OpenIddictTokenManager<OpenIddictToken> CreateTokenManager(
        Action<Mock<OpenIddictTokenManager<OpenIddictToken>>>? configuration = null)
    {
        var manager = new Mock<OpenIddictTokenManager<OpenIddictToken>>(
            Mock.Of<IOpenIddictTokenCache<OpenIddictToken>>(),
            OutputHelper.ToLogger<OpenIddictTokenManager<OpenIddictToken>>(),
            Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(),
            Mock.Of<IOpenIddictTokenStoreResolver>());

        configuration?.Invoke(manager);

        return manager.Object;
    }

    public class OpenIddictAuthorization { }
    public class OpenIddictToken { }
}
