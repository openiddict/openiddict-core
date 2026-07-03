using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace OpenIddict.Server.Tests;

public class OpenIddictServerConfigurationTests
{
    [Fact]
    public void Constructor_ThrowsAnExceptionForNullProvider()
    {
        // Arrange
        var provider = (IServiceProvider) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => new OpenIddictServerConfiguration(provider));
        Assert.Equal("provider", exception.ParamName);
    }

    [Fact]
    public void PostConfigure_ThrowsAnExceptionForNullOptions()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => configuration.PostConfigure(name: null, options: null!));
        Assert.Equal("options", exception.ParamName);
    }

    [Fact]
    public void PostConfigure_SetsTimeProviderToSystemWhenNotRegistered()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = new OpenIddictServerOptions();

        // Act
        configuration.PostConfigure(name: null, options);

        // Assert
        Assert.Same(TimeProvider.System, options.TimeProvider);
    }

    [Fact]
    public void PostConfigure_UsesRegisteredTimeProvider()
    {
        // Arrange
        var timeProvider = new FakeTimeProvider();
        var services = new ServiceCollection();
        services.AddSingleton<TimeProvider>(timeProvider);

        var configuration = new OpenIddictServerConfiguration(services.BuildServiceProvider());
        var options = new OpenIddictServerOptions();

        // Act
        configuration.PostConfigure(name: null, options);

        // Assert
        Assert.Same(timeProvider, options.TimeProvider);
    }

    [Fact]
    public void PostConfigure_DoesNotOverrideExplicitlySetTimeProvider()
    {
        // Arrange
        var explicitProvider = new FakeTimeProvider();
        var registeredProvider = new FakeTimeProvider();

        var services = new ServiceCollection();
        services.AddSingleton<TimeProvider>(registeredProvider);

        var configuration = new OpenIddictServerConfiguration(services.BuildServiceProvider());
        var options = new OpenIddictServerOptions { TimeProvider = explicitProvider };

        // Act
        configuration.PostConfigure(name: null, options);

        // Assert
        Assert.Same(explicitProvider, options.TimeProvider);
    }

    [Fact]
    public void PostConfigure_DisablesFeaturesWhenDegradedModeIsEnabled()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = new OpenIddictServerOptions
        {
            EnableDegradedMode = true,
            EnableAuthorizationRequestCaching = true,
            EnableEndSessionRequestCaching = true,
            UseReferenceAccessTokens = true,
            UseReferenceRefreshTokens = true
        };

        // Act
        configuration.PostConfigure(name: null, options);

        // Assert
        Assert.True(options.DisableAuthorizationStorage);
        Assert.True(options.DisableTokenStorage);
        Assert.True(options.DisableRollingRefreshTokens);
        Assert.False(options.EnableAuthorizationRequestCaching);
        Assert.False(options.EnableEndSessionRequestCaching);
        Assert.True(options.IgnoreEndpointPermissions);
        Assert.True(options.IgnoreGrantTypePermissions);
        Assert.True(options.IgnoreResponseTypePermissions);
        Assert.True(options.IgnoreScopePermissions);
        Assert.False(options.UseReferenceAccessTokens);
        Assert.False(options.UseReferenceRefreshTokens);
    }

    [Fact]
    public void PostConfigure_DisablesUserCodeFormattingWhenTokenStorageIsDisabled()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = new OpenIddictServerOptions
        {
            DisableTokenStorage = true
        };

        // Act
        configuration.PostConfigure(name: null, options);

        // Assert
        Assert.True(options.DisableRollingRefreshTokens);
        Assert.Equal(0, options.UserCodeLength);
        Assert.Empty(options.UserCodeCharset);
        Assert.Null(options.UserCodeDisplayFormat);
    }

    [Fact]
    public void Validate_ThrowsAnExceptionForNullOptions()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => configuration.Validate(name: null, options: null!));
        Assert.Equal("options", exception.ParamName);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenJsonWebTokenHandlerIsMissing()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();
        options.JsonWebTokenHandler = null!;

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0075), result.Failures!);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenNoFlowIsEnabled()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0076), result.Failures!);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenEndpointUrisAreNotUnique()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();

        var uri = new Uri("https://www.contoso.com/connect/shared");
        options.AuthorizationEndpointUris.Add(uri);
        options.TokenEndpointUris.Add(uri);

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0285), result.Failures!);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenAuthorizationEndpointIsMissingForAuthorizationCodeGrant()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();
        options.GrantTypes.Add(GrantTypes.AuthorizationCode);

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0077), result.Failures!);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenTokenEndpointIsMissingForPasswordGrant()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();
        options.GrantTypes.Add(GrantTypes.Password);

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0079), result.Failures!);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenDeviceVerificationEndpointIsMissingForDeviceGrant()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();
        options.GrantTypes.Add(GrantTypes.DeviceCode);

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0080), result.Failures!);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenDeviceEndpointIsEnabledWithoutDeviceGrant()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();
        options.DeviceAuthorizationEndpointUris.Add(new Uri("https://www.contoso.com/connect/device"));

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0084), result.Failures!);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenNoClientAuthenticationMethodIsEnabledForNonInteractiveEndpoints()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();

        options.TokenEndpointUris.Add(new Uri("https://www.contoso.com/connect/token"));
        options.ClientAuthenticationMethods.Clear();

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0419), result.Failures!);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenPrivateKeyJwtIsEnabledWithoutJwtBearerAssertionType()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();

        options.ClientAuthenticationMethods.Clear();
        options.ClientAuthenticationMethods.Add(ClientAuthenticationMethods.PrivateKeyJwt);
        options.ClientAssertionTypes.Clear();

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.FormatID0420(ClientAssertionTypes.JwtBearer, ClientAuthenticationMethods.PrivateKeyJwt), result.Failures!);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenTlsClientAuthMethodIsEnabledWithoutPolicy()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();
        options.ClientAuthenticationMethods.Add(ClientAuthenticationMethods.TlsClientAuth);

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0505), result.Failures!);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenSelfSignedTlsClientAuthMethodIsEnabledWithoutPolicy()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();
        options.ClientAuthenticationMethods.Add(ClientAuthenticationMethods.SelfSignedTlsClientAuth);

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0506), result.Failures!);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenSubjectTypesAreMissing()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();
        options.SubjectTypes.Clear();

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0421), result.Failures!);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenReferenceTokensAreEnabledWithDisabledTokenStorage()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();

        options.DisableTokenStorage = true;
        options.UseReferenceAccessTokens = true;

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0083), result.Failures!);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenRequestCachingIsEnabledWithDisabledTokenStorage()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();

        options.DisableTokenStorage = true;
        options.EnableAuthorizationRequestCaching = true;

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0465), result.Failures!);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenDeviceGrantIsEnabledWithDisabledTokenStorageOutsideDegradedMode()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();

        options.DisableTokenStorage = true;
        options.EnableDegradedMode = false;
        options.GrantTypes.Add(GrantTypes.DeviceCode);

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0367), result.Failures!);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenTokenExchangeGrantIsEnabledWithoutSubjectTokenTypes()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();
        options.GrantTypes.Add(GrantTypes.TokenExchange);
        options.SubjectTokenTypes.Clear();

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0486), result.Failures!);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenDefaultRequestedTokenTypeIsMissing()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();
        options.DefaultRequestedTokenType = string.Empty;

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0490), result.Failures!);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenDefaultRequestedTokenTypeIsNotAllowed()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();
        options.RequestedTokenTypes.Clear();
        options.DefaultRequestedTokenType = TokenTypeIdentifiers.AccessToken;

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0492), result.Failures!);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenEncryptionCredentialsAreMissing()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0085), result.Failures!);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenNoAsymmetricSigningCredentialIsRegistered()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();

        options.EncryptionCredentials.Add(new EncryptingCredentials(
            new SymmetricSecurityKey(new byte[32]),
            SecurityAlgorithms.Aes256KW,
            SecurityAlgorithms.Aes256CbcHmacSha512));

        options.SigningCredentials.Add(new SigningCredentials(
            new SymmetricSecurityKey(new byte[32]),
            SecurityAlgorithms.HmacSha256));

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0086), result.Failures!);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenMtlsEndpointAliasIsInvalid()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();

        options.MtlsTokenEndpointAliasUri = new Uri("http://www.contoso.com/connect/token", UriKind.Absolute);

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0499), result.Failures!);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenMtlsEndpointAliasIsConfiguredWithoutEndpoint()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();

        options.MtlsTokenEndpointAliasUri = new Uri("https://www.contoso.com/connect/token", UriKind.Absolute);

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0510), result.Failures!);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenMtlsEndpointAliasIsConfiguredWithoutIssuer()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();

        options.TokenEndpointUris.Add(new Uri("https://www.contoso.com/connect/token"));
        options.MtlsTokenEndpointAliasUri = new Uri("https://mtls.contoso.com/connect/token", UriKind.Absolute);

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0500), result.Failures!);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenDegradedModeIsEnabledAndCustomTokenEndpointHandlersAreMissing()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();
        options.EnableDegradedMode = true;
        options.TokenEndpointUris.Add(new Uri("https://www.contoso.com/connect/token"));

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.GetResourceString(SR.ID0094), result.Failures!);
    }

    [Fact]
    public void Validate_ReturnsAnErrorWhenUserCodeLengthIsTooShort()
    {
        // Arrange
        var configuration = new OpenIddictServerConfiguration(new ServiceCollection().BuildServiceProvider());
        var options = CreateBaseOptions();
        options.UserCodeLength = 5;

        // Act
        var result = configuration.Validate(name: null, options);

        // Assert
        Assert.Contains(SR.FormatID0439(6), result.Failures!);
    }

    private static OpenIddictServerOptions CreateBaseOptions()
        => new()
        {
            TimeProvider = TimeProvider.System
        };

    private sealed class FakeTimeProvider : TimeProvider;
}
