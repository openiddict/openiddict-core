using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Server.Tests;

public class OpenIddictServerFapi2ProfileTests
{
    [Fact]
    public void EnableFapi2SecurityProfile_AppliesProfileDefaults()
    {
        // Arrange
        var services = new ServiceCollection().AddOptions();
        var builder = new OpenIddictServerBuilder(services);

        // Act
        builder.EnableFapi2SecurityProfile();

        // Assert
        var options = services.BuildServiceProvider().GetRequiredService<IOptions<OpenIddictServerOptions>>().Value;

        Assert.True(options.EnableFapi2SecurityProfile);
        Assert.False(options.EnableFapi2MessageSigningProfile);
        Assert.True(options.RequirePushedAuthorizationRequests);
        Assert.True(options.RequireProofKeyForCodeExchange);
        Assert.True(options.DisableRollingRefreshTokens);
        Assert.Equal(TimeSpan.FromSeconds(60), options.AuthorizationCodeLifetime);
        Assert.Equal(TimeSpan.FromMinutes(5), options.RequestTokenLifetime);
        Assert.Equal(TimeSpan.FromSeconds(60), options.DPoPProofLifetime);
    }

    [Fact]
    public void EnableFapi2SecurityProfile_KeepsCompliantLifetimes()
    {
        // Arrange
        var services = new ServiceCollection().AddOptions();
        var builder = new OpenIddictServerBuilder(services);

        builder.SetAuthorizationCodeLifetime(TimeSpan.FromSeconds(30));
        builder.Configure(options => options.RequestTokenLifetime = TimeSpan.FromSeconds(90));

        // Act
        builder.EnableFapi2SecurityProfile();

        // Assert
        var options = services.BuildServiceProvider().GetRequiredService<IOptions<OpenIddictServerOptions>>().Value;

        Assert.Equal(TimeSpan.FromSeconds(30), options.AuthorizationCodeLifetime);
        Assert.Equal(TimeSpan.FromSeconds(90), options.RequestTokenLifetime);
    }

    [Fact]
    public void EnableFapi2MessageSigningProfile_EnablesSignedRequestsAndIntrospectionResponses()
    {
        // Arrange
        var services = new ServiceCollection().AddOptions();
        var builder = new OpenIddictServerBuilder(services);

        // Act
        builder.EnableFapi2MessageSigningProfile();

        // Assert
        var options = services.BuildServiceProvider().GetRequiredService<IOptions<OpenIddictServerOptions>>().Value;

        Assert.True(options.EnableFapi2SecurityProfile);
        Assert.True(options.EnableFapi2MessageSigningProfile);
        Assert.True(options.EnableRequestObjectSupport);
        Assert.True(options.RequireSignedRequestObjects);
        Assert.True(options.EnableJsonWebTokenIntrospectionResponses);
    }

    [Fact]
    public void PostConfigure_RemovesValuesNotAllowedByTheProfile()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateCompliantOptions();
        options.ClientAuthenticationMethods.Add(ClientAuthenticationMethods.ClientSecretBasic);
        options.ClientAuthenticationMethods.Add(ClientAuthenticationMethods.ClientSecretJwt);
        options.ClientAuthenticationMethods.Add(ClientAuthenticationMethods.TlsClientAuth);
        options.DPoPSigningAlgorithms.Add(SecurityAlgorithms.RsaSha256);

        // Act
        configuration.PostConfigure(name: null, options);

        // Assert
        Assert.Equal([ClientAuthenticationMethods.PrivateKeyJwt, ClientAuthenticationMethods.TlsClientAuth],
            options.ClientAuthenticationMethods.OrderBy(static method => method, StringComparer.Ordinal), StringComparer.Ordinal);
        Assert.Equal([CodeChallengeMethods.Sha256], options.CodeChallengeMethods);
        Assert.Equal([SecurityAlgorithms.EcdsaSha256, SecurityAlgorithms.RsaSsaPssSha256],
            options.DPoPSigningAlgorithms.OrderBy(static algorithm => algorithm, StringComparer.Ordinal), StringComparer.Ordinal);
    }

    [Fact]
    public void PostConfigure_UsesPS256ForRsaSigningCredentials()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateCompliantOptions();
        options.SigningCredentials.Clear();
        options.SigningCredentials.Add(new SigningCredentials(new RsaSecurityKey(RSA.Create(2048)), SecurityAlgorithms.RsaSha256));

        // Act
        configuration.PostConfigure(name: null, options);

        // Assert
        Assert.Equal(SecurityAlgorithms.RsaSsaPssSha256, Assert.Single(options.SigningCredentials).Algorithm);
    }

    [Fact]
    public void PostConfigure_DoesNotChangeValuesWhenProfileIsDisabled()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = new OpenIddictServerOptions { TimeProvider = TimeProvider.System };
        options.ClientAuthenticationMethods.Add(ClientAuthenticationMethods.ClientSecretBasic);
        options.SigningCredentials.Add(new SigningCredentials(new RsaSecurityKey(RSA.Create(2048)), SecurityAlgorithms.RsaSha256));

        // Act
        configuration.PostConfigure(name: null, options);

        // Assert
        Assert.Contains(ClientAuthenticationMethods.ClientSecretBasic, options.ClientAuthenticationMethods);
        Assert.Contains(CodeChallengeMethods.Plain, options.CodeChallengeMethods);
        Assert.Equal(SecurityAlgorithms.RsaSha256, Assert.Single(options.SigningCredentials).Algorithm);
    }

    [Fact]
    public void Validate_DoesNotReturnFapiErrorsForCompliantConfiguration()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateCompliantOptions();
        configuration.PostConfigure(name: null, options);

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.True(result.Succeeded, string.Join(Environment.NewLine, result.Failures ?? []));
    }

    [Theory]
    [InlineData(GrantTypes.Password)]
    [InlineData(GrantTypes.Implicit)]
    public void Validate_ReturnsAnErrorWhenDisallowedGrantTypeIsEnabled(string type)
        => AssertFailure(options => options.GrantTypes.Add(type), SR.ID0960);

    [Theory]
    [InlineData(ResponseTypes.None)]
    [InlineData(ResponseTypes.IdToken)]
    [InlineData(ResponseTypes.Code + " " + ResponseTypes.IdToken)]
    public void Validate_ReturnsAnErrorWhenDisallowedResponseTypeIsEnabled(string type)
        => AssertFailure(options => options.ResponseTypes.Add(type), SR.ID0961);

    [Theory]
    [InlineData(null)]
    [InlineData(61)]
    public void Validate_ReturnsAnErrorWhenAuthorizationCodeLifetimeIsTooLong(int? seconds)
        => AssertFailure(options => options.AuthorizationCodeLifetime =
            seconds is null ? null : TimeSpan.FromSeconds(seconds.Value), SR.ID0962);

    [Theory]
    [InlineData(null)]
    [InlineData(600)]
    public void Validate_ReturnsAnErrorWhenRequestTokenLifetimeIsTooLong(int? seconds)
        => AssertFailure(options => options.RequestTokenLifetime =
            seconds is null ? null : TimeSpan.FromSeconds(seconds.Value), SR.ID0963);

    [Fact]
    public void Validate_ReturnsAnErrorWhenPushedAuthorizationRequestsAreNotRequired()
        => AssertFailure(options => options.RequirePushedAuthorizationRequests = false, SR.ID0964);

    [Fact]
    public void Validate_ReturnsAnErrorWhenProofKeyForCodeExchangeIsNotRequired()
        => AssertFailure(options => options.RequireProofKeyForCodeExchange = false, SR.ID0964);

    [Fact]
    public void Validate_ReturnsAnErrorWhenAccessTokensAreNotSenderConstrained()
        => AssertFailure(options =>
        {
            options.EnableDPoPSupport = false;
            options.UseClientCertificateBoundAccessTokens = false;
        }, SR.ID0965);

    [Fact]
    public void Validate_ReturnsAnErrorWhenSigningCredentialsUseDisallowedAlgorithm()
        => AssertFailure(options => options.SigningCredentials.Add(new SigningCredentials(
            new ECDsaSecurityKey(ECDsa.Create(ECCurve.NamedCurves.nistP384)), SecurityAlgorithms.EcdsaSha384)), SR.ID0966);

    [Fact]
    public void Validate_ReturnsAnErrorWhenAnonymousClientsAreAccepted()
        => AssertFailure(options => options.AcceptAnonymousClients = true, SR.ID0967);

    [Fact]
    public void Validate_ReturnsAnErrorWhenMessageSigningProfileIsIncomplete()
        => AssertFailure(options => options.EnableFapi2MessageSigningProfile = true, SR.ID0968);

    [Fact]
    public void Validate_ReturnsAnErrorWhenIntrospectionResponseSigningAlgorithmIsEmpty()
        => AssertFailure(options => options.IntrospectionResponseSigningAlgorithms.Add(string.Empty), SR.ID0971);

    [Fact]
    public void Validate_ReturnsAnErrorWhenDPoPProofLifetimeIsTooLong()
        => AssertFailure(options => options.DPoPProofLifetime = TimeSpan.FromMinutes(5), SR.ID0989);

    [Fact]
    public void Validate_DoesNotReturnAnErrorWhenRollingRefreshTokensAreEnabled()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateCompliantOptions();
        options.DisableRollingRefreshTokens = false;
        configuration.PostConfigure(name: null, options);

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.True(result.Succeeded, string.Join(Environment.NewLine, result.Failures ?? []));
    }

    [Theory]
    [InlineData(SecurityAlgorithms.RsaSsaPssSha256, true)]
    [InlineData(SecurityAlgorithms.EcdsaSha256, false)]
    public void Validate_ReturnsAnErrorWhenNoCredentialsMatchIntrospectionResponseSigningAlgorithms(string algorithm, bool failure)
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateCompliantOptions();
        options.EnableJsonWebTokenIntrospectionResponses = true;
        options.IntrospectionResponseSigningAlgorithms.Add(algorithm);
        configuration.PostConfigure(name: null, options);

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Equal(failure, result.Failures?.Contains(SR.GetResourceString(SR.ID0990), StringComparer.Ordinal) ?? false);
    }

    [Theory]
    [InlineData(OpenIddictServerEndpointType.Token, true)]
    [InlineData(OpenIddictServerEndpointType.PushedAuthorization, true)]
    [InlineData(OpenIddictServerEndpointType.Introspection, true)]
    [InlineData(OpenIddictServerEndpointType.Authorization, false)]
    public async Task ValidateClientAuthentication_RejectsClientSecrets(OpenIddictServerEndpointType type, bool rejected)
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));

        var options = CreateCompliantOptions();
        options.EnableDegradedMode = true;

        var transaction = new OpenIddictServerTransaction
        {
            CancellationToken = CancellationToken.None,
            EndpointType = type,
            Options = options,
            Request = new OpenIddictRequest { ClientId = "Fabrikam", ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw" },
            ServiceProvider = services.BuildServiceProvider()
        };

        var context = new ProcessAuthenticationContext(transaction);

        // Act
        await new OpenIddictServerHandlers.Fapi.ValidateClientAuthentication().HandleAsync(context);

        // Assert
        Assert.Equal(rejected, context.IsRejected);

        if (rejected)
        {
            Assert.Equal(Errors.InvalidClient, context.Error);
            Assert.Equal(SR.GetResourceString(SR.ID2480), context.ErrorDescription);
            Assert.Equal(SR.FormatID8000(SR.ID2480), context.ErrorUri);
        }
    }

    private static void AssertFailure(Action<OpenIddictServerOptions> configure, string identifier)
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateCompliantOptions();
        configure(options);
        configuration.PostConfigure(name: null, options);

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(identifier), result.Failures!, StringComparer.Ordinal);
    }

    private static OpenIddictServerOptions CreateCompliantOptions()
    {
        var options = new OpenIddictServerOptions
        {
            AuthorizationCodeLifetime = TimeSpan.FromSeconds(60),
            EnableDPoPSupport = true,
            DPoPProofLifetime = TimeSpan.FromSeconds(60),
            EnableFapi2SecurityProfile = true,
            RequestTokenLifetime = TimeSpan.FromMinutes(5),
            RequireProofKeyForCodeExchange = true,
            RequirePushedAuthorizationRequests = true,
            TimeProvider = TimeProvider.System
        };

        options.GrantTypes.Add(GrantTypes.AuthorizationCode);
        options.ResponseTypes.Add(ResponseTypes.Code);
        options.AuthorizationEndpointUris.Add(new Uri("/connect/authorize", UriKind.Relative));
        options.TokenEndpointUris.Add(new Uri("/connect/token", UriKind.Relative));

        options.EncryptionCredentials.Add(new EncryptingCredentials(
            new SymmetricSecurityKey(new byte[32]), SecurityAlgorithms.Aes256KW, SecurityAlgorithms.Aes256CbcHmacSha512));
        options.SigningCredentials.Add(new SigningCredentials(
            new ECDsaSecurityKey(ECDsa.Create(ECCurve.NamedCurves.nistP256)), SecurityAlgorithms.EcdsaSha256));

        return options;
    }
}
