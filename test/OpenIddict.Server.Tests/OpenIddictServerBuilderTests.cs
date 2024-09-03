using System.Globalization;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Server.Tests;

public class OpenIddictServerBuilderTests
{
    [Fact]
    public void Constructor_ThrowsAnExceptionForNullServices()
    {
        // Arrange
        var services = (IServiceCollection) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => new OpenIddictServerBuilder(services));

        Assert.Equal("services", exception.ParamName);
    }

    [Fact]
    public void AddEventHandler_ThrowsAnExceptionWhenConfigurationIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.AddEventHandler<BaseContext>(configuration: null!));
        Assert.Equal("configuration", exception.ParamName);
    }

    [Fact]
    public void AddEventHandler_ThrowsAnExceptionWhenDescriptorIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.AddEventHandler(descriptor: null!));
        Assert.Equal("descriptor", exception.ParamName);
    }

    [Fact]
    public void AddEventHandler_HandlerIsAttached()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.AddEventHandler<CustomContext>(x =>
        {
            x.UseSingletonHandler<CustomHandler>();
        });

        // Assert
        Assert.Contains(services, service => service.ServiceType == typeof(CustomHandler));
    }

    [Fact]
    public void AddEventHandler_HandlerInstanceIsRegistered()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.AddEventHandler<CustomContext>(x =>
        {
            x.UseSingletonHandler(new CustomHandler());
        });

        // Assert
        Assert.Contains(services, service =>
            service.ServiceType == typeof(CustomHandler) &&
            service.ImplementationInstance?.GetType() == typeof(CustomHandler) &&
            service.Lifetime == ServiceLifetime.Singleton);
    }

    [Fact]
    public void AddEventHandler_SingletonHandlerIsRegisteredAsASingleton()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.AddEventHandler<CustomContext>(x =>
        {
            x.UseSingletonHandler<CustomHandler>();
        });

        // Assert
        Assert.Contains(services, service =>
            service.ServiceType == typeof(CustomHandler) &&
            service.Lifetime == ServiceLifetime.Singleton);
    }

    [Fact]
    public void AddEventHandler_ScopedHandlerIsRegisteredAsScoped()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.AddEventHandler<CustomContext>(x =>
        {
            x.UseScopedHandler<CustomHandler>();
        });

        // Assert
        Assert.Contains(services, service =>
            service.ServiceType == typeof(CustomHandler) &&
            service.Lifetime == ServiceLifetime.Scoped);
    }

    [Fact]
    public void AddEncryptionCredentials_ThrowsExceptionWhenCredentialsAreNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.AddEncryptionCredentials(credentials: null!));
        Assert.Equal("credentials", exception.ParamName);
    }

    [Fact]
    public void AddEncryptionKey_ThrowsExceptionWhenKeyIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.AddEncryptionKey(key: null!));
        Assert.Equal("key", exception.ParamName);
    }

    [Fact]
    public void AddEncryptionKey_ThrowsExceptionWhenAsymmetricKeyPrivateKeyIsMissing()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);
        var key = Mock.Of<AsymmetricSecurityKey>(key => key.PrivateKeyStatus == PrivateKeyStatus.DoesNotExist);

        // Act and assert
        var exception = Assert.Throws<InvalidOperationException>(() => builder.AddEncryptionKey(key));
        Assert.Equal("The asymmetric encryption key doesn't contain the required private key.", exception.Message);
    }

    [Fact]
    public void AddEncryptionKey_EncryptingKeyIsCorrectlyAdded()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        var key = Mock.Of<SecurityKey>(mock => mock.KeySize == 256 && mock.IsSupportedAlgorithm(SecurityAlgorithms.Aes256KW));

        // Act
        builder.AddEncryptionKey(key);

        var options = GetOptions(services);

        // Assert
        Assert.Same(key, options.EncryptionCredentials[0].Key);
    }

    [Fact]
    public void AddEncryptionKey_ThrowsExceptionWhenSymmetricKeyIsTooShort()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var key = Mock.Of<SecurityKey>(mock => mock.KeySize == 128 && mock.IsSupportedAlgorithm(SecurityAlgorithms.Aes256KW));
        var exception = Assert.Throws<InvalidOperationException>(() => builder.AddEncryptionKey(key));
        Assert.Equal(SR.FormatID0283(256, 128), exception.Message);
    }

    [Fact]
    public void AddEncryptionKey_ThrowsExceptionWhenSymmetricKeyIsTooLong()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var key = Mock.Of<SecurityKey>(mock => mock.KeySize == 384 && mock.IsSupportedAlgorithm(SecurityAlgorithms.Aes256KW));
        var exception = Assert.Throws<InvalidOperationException>(() => builder.AddEncryptionKey(key));
        Assert.Equal(SR.FormatID0283(256, 384), exception.Message);
    }

    [Fact]
    public void RemoveEventHandler_ThrowsAnExceptionWhenDescriptorIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.RemoveEventHandler(descriptor: null!));
        Assert.Equal("descriptor", exception.ParamName);
    }

    [Fact]
    public void RemoveEventHandler_RemovesService()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        OpenIddictServerHandlerDescriptor descriptor = OpenIddictServerHandlerDescriptor.CreateBuilder<CustomContext>().UseSingletonHandler<CustomHandler>().Build();
        builder.AddEventHandler(descriptor);

        // Act
        builder.RemoveEventHandler(descriptor);
        var options = GetOptions(services);

        // Assert
        Assert.DoesNotContain(services, x => x.ServiceType == descriptor.ServiceDescriptor.ServiceType);
        Assert.DoesNotContain(options.Handlers, x => x.ServiceDescriptor.ServiceType == descriptor.ServiceDescriptor.ServiceType);
    }

    [Fact]
    public void Configure_DelegateIsCorrectlyRegistered()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);
        var configuration = new Action<OpenIddictServerOptions>(options => { });

        // Act
        builder.Configure(configuration);

        // Assert
        Assert.Contains(services, service => service.ServiceType == typeof(IConfigureOptions<OpenIddictServerOptions>) &&
            service.ImplementationInstance is ConfigureNamedOptions<OpenIddictServerOptions> options &&
            options.Action == configuration && string.IsNullOrEmpty(options.Name));
    }

    [Fact]
    public void Configure_ThrowsAnExceptionWhenConfigurationIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.Configure(configuration: null!));
        Assert.Equal("configuration", exception.ParamName);
    }

    [Fact]
    public void AddDevelopmentEncryptionCertificate_ThrowsAnExceptionForNullSubject()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.AddDevelopmentEncryptionCertificate(subject: null!));
        Assert.Equal("subject", exception.ParamName);
    }

#if SUPPORTS_CERTIFICATE_GENERATION
    [Fact]
    public void AddDevelopmentEncryptionCertificate_CanGenerateCertificate()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.AddDevelopmentEncryptionCertificate();

        var options = GetOptions(services);

        // Assert
        Assert.NotEmpty(options.EncryptionCredentials);
        Assert.Equal(SecurityAlgorithms.RsaOAEP, options.EncryptionCredentials[0].Alg);
        Assert.Equal(SecurityAlgorithms.Aes256CbcHmacSha512, options.EncryptionCredentials[0].Enc);
        Assert.NotNull(options.EncryptionCredentials[0].Key.KeyId);
    }
#else
    [Fact]
    public void AddDevelopmentEncryptionCertificate_ThrowsAnExceptionOnUnsupportedPlatforms()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        builder.AddDevelopmentEncryptionCertificate(
            subject: new X500DistinguishedName("CN=" + Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture)));

        var serviceProvider = services.BuildServiceProvider();

        var options = serviceProvider.GetRequiredService<IOptions<OpenIddictServerOptions>>();

        // Act and assert
        var exception = Assert.Throws<PlatformNotSupportedException>(() => options.Value);

        Assert.Equal("X.509 certificate generation is not supported on this platform.", exception.Message);
    }
#endif

    [Fact]
    public void AddDevelopmentSigningCertificate_ThrowsAnExceptionForNullSubject()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(delegate
        {
            builder.AddDevelopmentSigningCertificate(subject: null!);
        });

        Assert.Equal("subject", exception.ParamName);
    }

#if SUPPORTS_CERTIFICATE_GENERATION
    [Fact]
    public void AddDevelopmentSigningCertificate_CanGenerateCertificate()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.AddDevelopmentSigningCertificate();

        var options = GetOptions(services);

        // Assert
        Assert.NotEmpty(options.SigningCredentials);
        Assert.Equal(SecurityAlgorithms.RsaSha256, options.SigningCredentials[0].Algorithm);
        Assert.NotNull(options.SigningCredentials[0].Kid);
    }
#else
    [Fact]
    public void AddDevelopmentSigningCertificate_ThrowsAnExceptionOnUnsupportedPlatforms()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        builder.AddDevelopmentSigningCertificate(
            subject: new X500DistinguishedName("CN=" + Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture)));

        var serviceProvider = services.BuildServiceProvider();

        var options = serviceProvider.GetRequiredService<IOptions<OpenIddictServerOptions>>();

        // Act and assert
        var exception = Assert.Throws<PlatformNotSupportedException>(() => options.Value);

        Assert.Equal("X.509 certificate generation is not supported on this platform.", exception.Message);
    }
#endif

    [Fact]
    public void AddEphemeralSigningKey_SigningKeyIsCorrectlyAdded()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.AddEphemeralSigningKey();

        var options = GetOptions(services);

        // Assert
        Assert.Single(options.SigningCredentials);
    }

    [Theory]
    [InlineData(SecurityAlgorithms.RsaSha256)]
    [InlineData(SecurityAlgorithms.RsaSha384)]
    [InlineData(SecurityAlgorithms.RsaSha512)]
#if SUPPORTS_ECDSA
    [InlineData(SecurityAlgorithms.EcdsaSha256)]
    [InlineData(SecurityAlgorithms.EcdsaSha384)]
    [InlineData(SecurityAlgorithms.EcdsaSha512)]
#endif
    public void AddEphemeralSigningKey_SigningCredentialsUseSpecifiedAlgorithm(string algorithm)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.AddEphemeralSigningKey(algorithm);

        var options = GetOptions(services);
        var credentials = options.SigningCredentials[0];

        // Assert
        Assert.Equal(algorithm, credentials.Algorithm);
    }

    [Fact]
    public void AddSigningKey_ThrowsExceptionWhenKeyIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.AddSigningKey(key: null!));
        Assert.Equal("key", exception.ParamName);
    }

    [Fact]
    public void AddSigningKey_ThrowsExceptionWhenAsymmetricKeyPrivateKeyIsMissing()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);
        var key = Mock.Of<AsymmetricSecurityKey>(key => key.PrivateKeyStatus == PrivateKeyStatus.DoesNotExist);

        // Act and assert
        var exception = Assert.Throws<InvalidOperationException>(() => builder.AddSigningKey(key));
        Assert.Equal("The asymmetric signing key doesn't contain the required private key.", exception.Message);
    }

    [Theory]
    [InlineData(SecurityAlgorithms.HmacSha256)]
    [InlineData(SecurityAlgorithms.RsaSha256)]
#if SUPPORTS_ECDSA
    [InlineData(SecurityAlgorithms.EcdsaSha256)]
    [InlineData(SecurityAlgorithms.EcdsaSha384)]
    [InlineData(SecurityAlgorithms.EcdsaSha512)]
#endif
    public void AddSigningKey_SigningKeyIsCorrectlyAdded(string algorithm)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        var key = Mock.Of<SecurityKey>(mock => mock.IsSupportedAlgorithm(algorithm));

        // Act
        builder.AddSigningKey(key);

        var options = GetOptions(services);

        // Assert
        Assert.Same(key, options.SigningCredentials[0].Key);
    }

    [Fact]
    public void AddSigningCertificate_SigningKeyIsCorrectlyAdded()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.AddSigningCertificate(
            assembly: typeof(OpenIddictServerBuilderTests).GetTypeInfo().Assembly,
            resource: "OpenIddict.Server.Tests.Certificate.pfx",
            password: "OpenIddict");

        var options = GetOptions(services);

        // Assert
        Assert.IsType<X509SecurityKey>(options.SigningCredentials[0].Key);
    }

    [Fact]
    public void AllowAuthorizationCodeFlow_CodeFlowIsAdded()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.AllowAuthorizationCodeFlow();

        var options = GetOptions(services);

        // Assert
        Assert.Contains(CodeChallengeMethods.Sha256, options.CodeChallengeMethods);

        Assert.Contains(GrantTypes.AuthorizationCode, options.GrantTypes);

        Assert.Contains(ResponseModes.FormPost, options.ResponseModes);
        Assert.Contains(ResponseModes.Fragment, options.ResponseModes);
        Assert.Contains(ResponseModes.Query, options.ResponseModes);

        Assert.Contains(ResponseTypes.Code, options.ResponseTypes);
    }

    [Fact]
    public void AllowClientCredentialsFlow_ClientCredentialsFlowIsAdded()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.AllowClientCredentialsFlow();

        var options = GetOptions(services);

        // Assert
        Assert.Contains(GrantTypes.ClientCredentials, options.GrantTypes);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void AllowCustomFlow_ThrowsAnExceptionForType(string type)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.AllowCustomFlow(type));

        Assert.Equal("type", exception.ParamName);
        Assert.Contains("The grant type cannot be null or empty.", exception.Message);
    }

    [Fact]
    public void AllowCustomFlow_CustomFlowIsAdded()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.AllowCustomFlow("urn:ietf:params:oauth:grant-type:custom_grant");

        var options = GetOptions(services);

        // Assert
        Assert.Contains("urn:ietf:params:oauth:grant-type:custom_grant", options.GrantTypes);
    }

    [Fact]
    public void AddDeviceAuthorizationFlow_DeviceFlowIsAdded()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.AllowDeviceAuthorizationFlow();

        var options = GetOptions(services);

        // Assert
        Assert.Contains(GrantTypes.DeviceCode, options.GrantTypes);
    }

    [Fact]
    public void AllowHybridFlow_HybridFlowIsAdded()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.AllowHybridFlow();

        var options = GetOptions(services);

        // Assert
        Assert.Contains(CodeChallengeMethods.Sha256, options.CodeChallengeMethods);

        Assert.Contains(GrantTypes.AuthorizationCode, options.GrantTypes);
        Assert.Contains(GrantTypes.Implicit, options.GrantTypes);

        Assert.Contains(ResponseModes.FormPost, options.ResponseModes);
        Assert.Contains(ResponseModes.Fragment, options.ResponseModes);

        Assert.Contains(ResponseTypes.Code + ' ' + ResponseTypes.IdToken, options.ResponseTypes);
        Assert.Contains(ResponseTypes.Code + ' ' + ResponseTypes.IdToken + ' ' + ResponseTypes.Token, options.ResponseTypes);
        Assert.Contains(ResponseTypes.Code + ' ' + ResponseTypes.Token, options.ResponseTypes);
    }

    [Fact]
    public void AllowImplicitFlow_ImplicitFlowIsAdded()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.AllowImplicitFlow();

        var options = GetOptions(services);

        // Assert
        Assert.Contains(GrantTypes.Implicit, options.GrantTypes);

        Assert.Contains(ResponseModes.FormPost, options.ResponseModes);
        Assert.Contains(ResponseModes.Fragment, options.ResponseModes);

        Assert.Contains(ResponseTypes.IdToken, options.ResponseTypes);
        Assert.Contains(ResponseTypes.IdToken + ' ' + ResponseTypes.Token, options.ResponseTypes);
        Assert.Contains(ResponseTypes.Token, options.ResponseTypes);
    }

    [Fact]
    public void AllowPasswordFlow_PasswordFlowIsAdded()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.AllowPasswordFlow();

        var options = GetOptions(services);

        // Assert
        Assert.Contains(GrantTypes.Password, options.GrantTypes);
    }

    [Fact]
    public void AllowRefreshTokenFlow_RefreshTokenFlowIsAdded()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.AllowRefreshTokenFlow();

        var options = GetOptions(services);

        // Assert
        Assert.Contains(GrantTypes.RefreshToken, options.GrantTypes);
    }

    [Fact]
    public void DisableAccessTokenEncryption_AccessTokenEncryptionIsDisabled()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.DisableAccessTokenEncryption();

        var options = GetOptions(services);

        // Assert
        Assert.True(options.DisableAccessTokenEncryption);
    }

    [Fact]
    public void DisableAuthorizationStorage_AuthorizationStorageIsDisabled()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.DisableAuthorizationStorage();

        var options = GetOptions(services);

        // Assert
        Assert.True(options.DisableAuthorizationStorage);
    }

    [Fact]
    public void DisableRollingRefreshTokens_RollingRefreshTokensAreDisabled()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.DisableRollingRefreshTokens();

        var options = GetOptions(services);

        // Assert
        Assert.True(options.DisableRollingRefreshTokens);
    }

    [Fact]
    public void DisableScopeValidation_ScopeValidationIsDisabled()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.DisableScopeValidation();

        var options = GetOptions(services);

        // Assert
        Assert.True(options.DisableScopeValidation);
    }

    [Fact]
    public void DisableSlidingRefreshTokenExpiration_SlidingExpirationIsDisabled()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.DisableSlidingRefreshTokenExpiration();

        var options = GetOptions(services);

        // Assert
        Assert.True(options.DisableSlidingRefreshTokenExpiration);
    }

    [Fact]
    public void DisableTokenStorage_TokenStorageIsDisabled()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.DisableTokenStorage();

        var options = GetOptions(services);

        // Assert
        Assert.True(options.DisableTokenStorage);
    }

    [Fact]
    public void RequireProofKeyForCodeExchange_PkceIsEnforced()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.RequireProofKeyForCodeExchange();

        var options = GetOptions(services);

        // Assert
        Assert.True(options.RequireProofKeyForCodeExchange);
    }

    [Fact]
    public void SetAuthorizationEndpointUris_ThrowsExceptionWhenUrisIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetAuthorizationEndpointUris(uris: (null as Uri[])!));
        Assert.Equal("uris", exception.ParamName);
    }

    [Fact]
    public void SetAuthorizationEndpointUris_Strings_ThrowsExceptionWhenUrisIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetAuthorizationEndpointUris(uris: (null as string[])!));
        Assert.Equal("uris", exception.ParamName);
    }

    [Theory]
    [InlineData(@"C:\")]
    public void SetAuthorizationEndpointUris_ThrowsExceptionForMalformedUri(string uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetAuthorizationEndpointUris(new Uri(uri)));
        Assert.Equal("uris", exception.ParamName);
        Assert.Contains(SR.GetResourceString(SR.ID0072), exception.Message);
    }

    [Theory]
    [InlineData("~/path")]
    public void SetAuthorizationEndpointUris_ThrowsExceptionForInvalidRelativeUri(string uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetAuthorizationEndpointUris(new Uri(uri, UriKind.RelativeOrAbsolute)));
        Assert.Equal("uris", exception.ParamName);
        Assert.Contains(SR.FormatID0081("~"), exception.Message);
    }

    [Fact]
    public void SetAuthorizationEndpointUris_ClearsUris()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetAuthorizationEndpointUris(Array.Empty<Uri>());

        var options = GetOptions(services);

        // Assert
        Assert.Empty(options.AuthorizationEndpointUris);
    }

    [Fact]
    public void SetAuthorizationEndpointUris_AddsUri()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetAuthorizationEndpointUris("http://localhost/endpoint-path");

        var options = GetOptions(services);

        // Assert
        Assert.Contains(new Uri("http://localhost/endpoint-path"), options.AuthorizationEndpointUris);
    }

    [Fact]
    public void SetConfigurationEndpointUris_ThrowsExceptionWhenUrisIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetConfigurationEndpointUris(uris: (null as Uri[])!));
        Assert.Equal("uris", exception.ParamName);
    }

    [Fact]
    public void SetConfigurationEndpointUris_Strings_ThrowsExceptionWhenUrisIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetConfigurationEndpointUris(uris: (null as string[])!));
        Assert.Equal("uris", exception.ParamName);
    }

    [Theory]
    [InlineData(@"C:\")]
    public void SetConfigurationEndpointUris_ThrowsExceptionForMalformedUri(string uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetConfigurationEndpointUris(new Uri(uri)));
        Assert.Equal("uris", exception.ParamName);
        Assert.Contains(SR.GetResourceString(SR.ID0072), exception.Message);
    }

    [Theory]
    [InlineData("~/path")]
    public void SetConfigurationEndpointUris_ThrowsExceptionForInvalidRelativeUri(string uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetConfigurationEndpointUris(new Uri(uri, UriKind.RelativeOrAbsolute)));
        Assert.Equal("uris", exception.ParamName);
        Assert.Contains(SR.FormatID0081("~"), exception.Message);
    }

    [Fact]
    public void SetConfigurationEndpointUris_ClearsUris()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetConfigurationEndpointUris(Array.Empty<Uri>());

        var options = GetOptions(services);

        // Assert
        Assert.Empty(options.ConfigurationEndpointUris);
    }

    [Fact]
    public void SetConfigurationEndpointUris_AddsUri()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetConfigurationEndpointUris("http://localhost/endpoint-path");

        var options = GetOptions(services);

        // Assert
        Assert.Contains(new Uri("http://localhost/endpoint-path"), options.ConfigurationEndpointUris);
    }

    [Fact]
    public void SetJsonWebKeySetEndpointUris_ThrowsExceptionWhenUrisIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetJsonWebKeySetEndpointUris(uris: (null as Uri[])!));
        Assert.Equal("uris", exception.ParamName);
    }

    [Fact]
    public void SetJsonWebKeySetEndpointUris_Strings_ThrowsExceptionWhenUrisIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetJsonWebKeySetEndpointUris(uris: (null as string[])!));
        Assert.Equal("uris", exception.ParamName);
    }

    [Theory]
    [InlineData(@"C:\")]
    public void SetJsonWebKeySetEndpointUris_ThrowsExceptionForMalformedUri(string uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetJsonWebKeySetEndpointUris(new Uri(uri)));
        Assert.Equal("uris", exception.ParamName);
        Assert.Contains(SR.GetResourceString(SR.ID0072), exception.Message);
    }

    [Theory]
    [InlineData("~/path")]
    public void SetJsonWebKeySetEndpointUris_ThrowsExceptionForInvalidRelativeUri(string uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetJsonWebKeySetEndpointUris(new Uri(uri, UriKind.RelativeOrAbsolute)));
        Assert.Equal("uris", exception.ParamName);
        Assert.Contains(SR.FormatID0081("~"), exception.Message);
    }

    [Fact]
    public void SetJsonWebKeySetEndpointUris_ClearsUris()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetJsonWebKeySetEndpointUris(Array.Empty<Uri>());

        var options = GetOptions(services);

        // Assert
        Assert.Empty(options.JsonWebKeySetEndpointUris);
    }

    [Fact]
    public void SetJsonWebKeySetEndpointUris_AddsUri()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetJsonWebKeySetEndpointUris("http://localhost/endpoint-path");

        var options = GetOptions(services);

        // Assert
        Assert.Contains(new Uri("http://localhost/endpoint-path"), options.JsonWebKeySetEndpointUris);
    }

    [Fact]
    public void SetDeviceAuthorizationEndpointUris_ThrowsExceptionWhenUrisIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetDeviceAuthorizationEndpointUris(uris: (null as Uri[])!));
        Assert.Equal("uris", exception.ParamName);
    }

    [Fact]
    public void SetDeviceAuthorizationEndpointUris_Strings_ThrowsExceptionWhenUrisIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetDeviceAuthorizationEndpointUris(uris: (null as string[])!));
        Assert.Equal("uris", exception.ParamName);
    }

    [Theory]
    [InlineData(@"C:\")]
    public void SetDeviceAuthorizationEndpointUris_ThrowsExceptionForMalformedUri(string uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetDeviceAuthorizationEndpointUris(new Uri(uri)));
        Assert.Equal("uris", exception.ParamName);
        Assert.Contains(SR.GetResourceString(SR.ID0072), exception.Message);
    }

    [Theory]
    [InlineData("~/path")]
    public void SetDeviceAuthorizationEndpointUris_ThrowsExceptionForInvalidRelativeUri(string uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetDeviceAuthorizationEndpointUris(new Uri(uri, UriKind.RelativeOrAbsolute)));
        Assert.Equal("uris", exception.ParamName);
        Assert.Contains(SR.FormatID0081("~"), exception.Message);
    }

    [Fact]
    public void SetDeviceAuthorizationEndpointUris_ClearsUris()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetDeviceAuthorizationEndpointUris(Array.Empty<Uri>());

        var options = GetOptions(services);

        // Assert
        Assert.Empty(options.DeviceAuthorizationEndpointUris);
    }

    [Fact]
    public void SetDeviceAuthorizationEndpointUris_AddsUri()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetDeviceAuthorizationEndpointUris("http://localhost/endpoint-path");

        var options = GetOptions(services);

        // Assert
        Assert.Contains(new Uri("http://localhost/endpoint-path"), options.DeviceAuthorizationEndpointUris);
    }

    [Fact]
    public void SetIntrospectionEndpointUris_ThrowsExceptionWhenUrisIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetIntrospectionEndpointUris(uris: (null as Uri[])!));
        Assert.Equal("uris", exception.ParamName);
    }

    [Fact]
    public void SetIntrospectionEndpointUris_Strings_ThrowsExceptionWhenUrisIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetIntrospectionEndpointUris(uris: (null as string[])!));
        Assert.Equal("uris", exception.ParamName);
    }

    [Theory]
    [InlineData(@"C:\")]
    public void SetIntrospectionEndpointUris_ThrowsExceptionForMalformedUri(string uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetIntrospectionEndpointUris(new Uri(uri)));
        Assert.Equal("uris", exception.ParamName);
        Assert.Contains(SR.GetResourceString(SR.ID0072), exception.Message);
    }

    [Theory]
    [InlineData("~/path")]
    public void SetIntrospectionEndpointUris_ThrowsExceptionForInvalidRelativeUri(string uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetIntrospectionEndpointUris(new Uri(uri, UriKind.RelativeOrAbsolute)));
        Assert.Equal("uris", exception.ParamName);
        Assert.Contains(SR.FormatID0081("~"), exception.Message);
    }

    [Fact]
    public void SetIntrospectionEndpointUris_ClearsUris()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetIntrospectionEndpointUris(Array.Empty<Uri>());

        var options = GetOptions(services);

        // Assert
        Assert.Empty(options.IntrospectionEndpointUris);
    }

    [Fact]
    public void SetIntrospectionEndpointUris_AddsUri()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetIntrospectionEndpointUris("http://localhost/endpoint-path");

        var options = GetOptions(services);

        // Assert
        Assert.Contains(new Uri("http://localhost/endpoint-path"), options.IntrospectionEndpointUris);
    }

    [Fact]
    public void SetLogoutEndpointUris_ThrowsExceptionWhenUrisIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetEndSessionEndpointUris(uris: (null as Uri[])!));
        Assert.Equal("uris", exception.ParamName);
    }

    [Fact]
    public void SetLogoutEndpointUris_Strings_ThrowsExceptionWhenUrisIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetEndSessionEndpointUris(uris: (null as string[])!));
        Assert.Equal("uris", exception.ParamName);
    }

    [Theory]
    [InlineData(@"C:\")]
    public void SetLogoutEndpointUris_ThrowsExceptionForMalformedUri(string uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetEndSessionEndpointUris(new Uri(uri)));
        Assert.Equal("uris", exception.ParamName);
        Assert.Contains(SR.GetResourceString(SR.ID0072), exception.Message);
    }

    [Theory]
    [InlineData("~/path")]
    public void SetLogoutEndpointUris_ThrowsExceptionForInvalidRelativeUri(string uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetEndSessionEndpointUris(new Uri(uri, UriKind.RelativeOrAbsolute)));
        Assert.Equal("uris", exception.ParamName);
        Assert.Contains(SR.FormatID0081("~"), exception.Message);
    }

    [Fact]
    public void SetLogoutEndpointUris_ClearsUris()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetEndSessionEndpointUris(Array.Empty<Uri>());

        var options = GetOptions(services);

        // Assert
        Assert.Empty(options.EndSessionEndpointUris);
    }

    [Fact]
    public void SetLogoutEndpointUris_AddsUri()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetEndSessionEndpointUris("http://localhost/endpoint-path");

        var options = GetOptions(services);

        // Assert
        Assert.Contains(new Uri("http://localhost/endpoint-path"), options.EndSessionEndpointUris);
    }

    [Fact]
    public void SetRevocationEndpointUris_ThrowsExceptionWhenUrisIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetRevocationEndpointUris(uris: (null as Uri[])!));
        Assert.Equal("uris", exception.ParamName);
    }

    [Fact]
    public void SetRevocationEndpointUris_Strings_ThrowsExceptionWhenUrisIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetRevocationEndpointUris(uris: (null as string[])!));
        Assert.Equal("uris", exception.ParamName);
    }

    [Theory]
    [InlineData(@"C:\")]
    public void SetRevocationEndpointUris_ThrowsExceptionForMalformedUri(string uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetRevocationEndpointUris(new Uri(uri)));
        Assert.Equal("uris", exception.ParamName);
        Assert.Contains(SR.GetResourceString(SR.ID0072), exception.Message);
    }

    [Theory]
    [InlineData("~/path")]
    public void SetRevocationEndpointUris_ThrowsExceptionForInvalidRelativeUri(string uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetRevocationEndpointUris(new Uri(uri, UriKind.RelativeOrAbsolute)));
        Assert.Equal("uris", exception.ParamName);
        Assert.Contains(SR.FormatID0081("~"), exception.Message);
    }

    [Fact]
    public void SetRevocationEndpointUris_ClearsUris()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetRevocationEndpointUris(Array.Empty<Uri>());

        var options = GetOptions(services);

        // Assert
        Assert.Empty(options.RevocationEndpointUris);
    }

    [Fact]
    public void SetRevocationEndpointUris_AddsUri()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetRevocationEndpointUris("http://localhost/endpoint-path");

        var options = GetOptions(services);

        // Assert
        Assert.Contains(new Uri("http://localhost/endpoint-path"), options.RevocationEndpointUris);
    }

    [Fact]
    public void SetTokenEndpointUris_ThrowsExceptionWhenUrisIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetTokenEndpointUris(uris: (null as Uri[])!));
        Assert.Equal("uris", exception.ParamName);
    }

    [Fact]
    public void SetTokenEndpointUris_Strings_ThrowsExceptionWhenUrisIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetTokenEndpointUris(uris: (null as string[])!));
        Assert.Equal("uris", exception.ParamName);
    }

    [Theory]
    [InlineData(@"C:\")]
    public void SetTokenEndpointUris_ThrowsExceptionForMalformedUri(string uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetTokenEndpointUris(new Uri(uri)));
        Assert.Equal("uris", exception.ParamName);
        Assert.Contains(SR.GetResourceString(SR.ID0072), exception.Message);
    }

    [Theory]
    [InlineData("~/path")]
    public void SetTokenEndpointUris_ThrowsExceptionForInvalidRelativeUri(string uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetTokenEndpointUris(new Uri(uri, UriKind.RelativeOrAbsolute)));
        Assert.Equal("uris", exception.ParamName);
        Assert.Contains(SR.FormatID0081("~"), exception.Message);
    }

    [Fact]
    public void SetTokenEndpointUris_ClearsUris()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetTokenEndpointUris(Array.Empty<Uri>());

        var options = GetOptions(services);

        // Assert
        Assert.Empty(options.TokenEndpointUris);
    }

    [Fact]
    public void SetTokenEndpointUris_AddsUri()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetTokenEndpointUris("http://localhost/endpoint-path");

        var options = GetOptions(services);

        // Assert
        Assert.Contains(new Uri("http://localhost/endpoint-path"), options.TokenEndpointUris);
    }

    [Fact]
    public void SetUserInfoEndpointUris_ThrowsExceptionWhenUrisIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetUserInfoEndpointUris(uris: (null as Uri[])!));
        Assert.Equal("uris", exception.ParamName);
    }

    [Fact]
    public void SetUserInfoEndpointUris_Strings_ThrowsExceptionWhenUrisIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetUserInfoEndpointUris(uris: (null as string[])!));
        Assert.Equal("uris", exception.ParamName);
    }

    [Theory]
    [InlineData(@"C:\")]
    public void SetUserInfoEndpointUris_ThrowsExceptionForMalformedUri(string uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetUserInfoEndpointUris(new Uri(uri)));
        Assert.Equal("uris", exception.ParamName);
        Assert.Contains(SR.GetResourceString(SR.ID0072), exception.Message);
    }

    [Theory]
    [InlineData("~/path")]
    public void SetUserInfoEndpointUris_ThrowsExceptionForInvalidRelativeUri(string uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetUserInfoEndpointUris(new Uri(uri, UriKind.RelativeOrAbsolute)));
        Assert.Equal("uris", exception.ParamName);
        Assert.Contains(SR.FormatID0081("~"), exception.Message);
    }

    [Fact]
    public void SetUserInfoEndpointUris_ClearsUris()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetUserInfoEndpointUris(Array.Empty<Uri>());

        var options = GetOptions(services);

        // Assert
        Assert.Empty(options.UserInfoEndpointUris);
    }

    [Fact]
    public void SetUserInfoEndpointUris_AddsUri()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetUserInfoEndpointUris("http://localhost/endpoint-path");

        var options = GetOptions(services);

        // Assert
        Assert.Contains(new Uri("http://localhost/endpoint-path"), options.UserInfoEndpointUris);
    }

    [Fact]
    public void SetEndUserVerificationEndpointUris_ThrowsExceptionWhenUrisIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetEndUserVerificationEndpointUris(uris: (null as Uri[])!));
        Assert.Equal("uris", exception.ParamName);
    }

    [Fact]
    public void SetEndUserVerificationEndpointUris_Strings_ThrowsExceptionWhenUrisIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetEndUserVerificationEndpointUris(uris: (null as string[])!));
        Assert.Equal("uris", exception.ParamName);
    }

    [Theory]
    [InlineData(@"C:\")]
    public void SetEndUserVerificationEndpointUris_ThrowsExceptionForMalformedUri(string uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetEndUserVerificationEndpointUris(new Uri(uri)));
        Assert.Equal("uris", exception.ParamName);
        Assert.Contains(SR.GetResourceString(SR.ID0072), exception.Message);
    }

    [Theory]
    [InlineData("~/path")]
    public void SetEndUserVerificationEndpointUris_ThrowsExceptionForInvalidRelativeUri(string uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetEndUserVerificationEndpointUris(new Uri(uri, UriKind.RelativeOrAbsolute)));
        Assert.Equal("uris", exception.ParamName);
        Assert.Contains(SR.FormatID0081("~"), exception.Message);
    }

    [Fact]
    public void SetEndUserVerificationEndpointUris_ClearsUris()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetEndUserVerificationEndpointUris(Array.Empty<Uri>());

        var options = GetOptions(services);

        // Assert
        Assert.Empty(options.EndUserVerificationEndpointUris);
    }

    [Fact]
    public void SetEndUserVerificationEndpointUris_AddsUri()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetEndUserVerificationEndpointUris("http://localhost/endpoint-path");

        var options = GetOptions(services);

        // Assert
        Assert.Contains(new Uri("http://localhost/endpoint-path"), options.EndUserVerificationEndpointUris);
    }

    [Fact]
    public void AcceptAnonymousClients_ClientIdentificationIsOptional()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.AcceptAnonymousClients();

        var options = GetOptions(services);

        // Assert
        Assert.True(options.AcceptAnonymousClients);
    }

    [Fact]
    public void SetAccessTokenLifetime_DefaultAccessTokenLifetimeIsReplaced()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetAccessTokenLifetime(TimeSpan.FromMinutes(42));

        var options = GetOptions(services);

        // Assert
        Assert.Equal(TimeSpan.FromMinutes(42), options.AccessTokenLifetime);
    }

    [Fact]
    public void SetAccessTokenLifetime_AccessTokenLifetimeCanBeSetToNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetAccessTokenLifetime(null);

        var options = GetOptions(services);

        // Assert
        Assert.Null(options.AccessTokenLifetime);
    }

    [Fact]
    public void SetAuthorizationCodeLifetime_DefaultAuthorizationCodeLifetimeIsReplaced()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetAuthorizationCodeLifetime(TimeSpan.FromMinutes(42));

        var options = GetOptions(services);

        // Assert
        Assert.Equal(TimeSpan.FromMinutes(42), options.AuthorizationCodeLifetime);
    }

    [Fact]
    public void SetAuthorizationCodeLifetime_AuthorizationCodeLifetimeCanBeSetToNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetAuthorizationCodeLifetime(null);

        var options = GetOptions(services);

        // Assert
        Assert.Null(options.AuthorizationCodeLifetime);
    }

    [Fact]
    public void SetIdentityTokenLifetime_DefaultIdentityTokenLifetimeIsReplaced()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetIdentityTokenLifetime(TimeSpan.FromMinutes(42));

        var options = GetOptions(services);

        // Assert
        Assert.Equal(TimeSpan.FromMinutes(42), options.IdentityTokenLifetime);
    }

    [Fact]
    public void SetIdentityTokenLifetime_IdentityTokenLifetimeCanBeSetToNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetIdentityTokenLifetime(null);

        var options = GetOptions(services);

        // Assert
        Assert.Null(options.IdentityTokenLifetime);
    }

    [Fact]
    public void SetDeviceCodeLifetimeLifetime_DefaultDeviceCodeLifetimeIsReplaced()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetDeviceCodeLifetime(TimeSpan.FromMinutes(42));

        var options = GetOptions(services);

        // Assert
        Assert.Equal(TimeSpan.FromMinutes(42), options.DeviceCodeLifetime);
    }

    [Fact]
    public void SetDeviceCodeLifetimeLifetime_DeviceCodeLifetimeCanBeSetToNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetDeviceCodeLifetime(null);

        var options = GetOptions(services);

        // Assert
        Assert.Null(options.DeviceCodeLifetime);
    }

    [Fact]
    public void SetUserCodeCharset_ThrowsAnExceptionForNullCharset()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetUserCodeCharset(charset: null!));

        Assert.Equal("charset", exception.ParamName);
    }

    [Fact]
    public void SetUserCodeCharset_ThrowsAnExceptionForCharsetWithTooFewCharacters()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() => builder.SetUserCodeCharset(["0"]));

        Assert.StartsWith(SR.FormatID0440(9), exception.Message);
        Assert.Equal("charset", exception.ParamName);
    }

    [Fact]
    public void SetUserCodeCharset_ThrowsAnExceptionForCharsetWithDuplicatedCharacters()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetUserCodeCharset(
            ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "9"]));

        Assert.StartsWith(SR.GetResourceString(SR.ID0436), exception.Message);
        Assert.Equal("charset", exception.ParamName);
    }

#if SUPPORTS_TEXT_ELEMENT_ENUMERATOR
    [InlineData("")]
    [InlineData("\uD83D\uDE42\uD83D\uDE42")]
    [Theory]
    public void SetUserCodeCharset_ThrowsAnExceptionForCharsetWithInvalidCharacter(string character)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetUserCodeCharset(
            ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", character]));

        Assert.StartsWith(SR.GetResourceString(SR.ID0437), exception.Message);
        Assert.Equal("charset", exception.ParamName);
    }
#else
    [Fact]
    public void SetUserCodeCharset_ThrowsAnExceptionForCharsetWithNonAsciiCharacter()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetUserCodeCharset(
            ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "\uD83D\uDE42"]));

        Assert.StartsWith(SR.GetResourceString(SR.ID0438), exception.Message);
        Assert.Equal("charset", exception.ParamName);
    }
#endif

    [Fact]
    public void SetUserCodeCharset_ReplacesCharset()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetUserCodeCharset(["A", "B", "C", "D", "E", "F", "G", "H", "I", "J"]);

        var options = GetOptions(services);

        // Assert
        Assert.Equal(["A", "B", "C", "D", "E", "F", "G", "H", "I", "J"], options.UserCodeCharset);
    }

    [Fact]
    public void SetUserCodeDisplayFormat_ReplacesDisplayFormat()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetUserCodeDisplayFormat("{0}{1}-{2}{3}-{4}{5}-{6}{7}-{8}{9}-{10}{11}");

        var options = GetOptions(services);

        // Assert
        Assert.Equal("{0}{1}-{2}{3}-{4}{5}-{6}{7}-{8}{9}-{10}{11}", options.UserCodeDisplayFormat);
    }

    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(5)]
    [Theory]
    public void SetUserCodeLength_ThrowsAnExceptionForInvalidLength(int length)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() => builder.SetUserCodeLength(length));

        Assert.StartsWith(SR.FormatID0439(6), exception.Message);
        Assert.Equal("length", exception.ParamName);
    }

    [Fact]
    public void SetUserCodeLength_ReplacesLength()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetUserCodeLength(42);

        var options = GetOptions(services);

        // Assert
        Assert.Equal(42, options.UserCodeLength);
    }

    [Fact]
    public void SetUserCodeLifetime_DefaultUserCodeLifetimeIsReplaced()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetUserCodeLifetime(TimeSpan.FromMinutes(42));

        var options = GetOptions(services);

        // Assert
        Assert.Equal(TimeSpan.FromMinutes(42), options.UserCodeLifetime);
    }

    [Fact]
    public void SetUserCodeLifetime_UserLifetimeCanBeSetToNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetUserCodeLifetime(null);

        var options = GetOptions(services);

        // Assert
        Assert.Null(options.UserCodeLifetime);
    }

    [Fact]
    public void SetRefreshTokenLifetime_DefaultRefreshTokenLifetimeIsReplaced()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetRefreshTokenLifetime(TimeSpan.FromMinutes(42));

        var options = GetOptions(services);

        // Assert
        Assert.Equal(TimeSpan.FromMinutes(42), options.RefreshTokenLifetime);
    }

    [Fact]
    public void SetRefreshTokenLifetime_RefreshTokenLifetimeCanBeSetToNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetRefreshTokenLifetime(null);

        var options = GetOptions(services);

        // Assert
        Assert.Null(options.RefreshTokenLifetime);
    }

    [Fact]
    public void SetIssuer_ThrowsAnExceptionForNullIssuer()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetIssuer((Uri?) null!));

        Assert.Equal("uri", exception.ParamName);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void SetIssuer_ThrowsAnExceptionForNullOrEmptyIssuer(string? uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetIssuer(uri!));

        Assert.Equal("uri", exception.ParamName);
        Assert.StartsWith(SR.FormatID0366("uri"), exception.Message);
    }

    [Fact]
    public void SetIssuer_IssuerIsReplaced()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetIssuer("http://www.fabrikam.com/");

        var options = GetOptions(services);

        // Assert
        Assert.Equal(new Uri("http://www.fabrikam.com/"), options.Issuer);
    }

    [Fact]
    public void RegisterClaims_ClaimsAreAdded()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.RegisterClaims("custom_claim_1", "custom_claim_2");

        var options = GetOptions(services);

        // Assert
        Assert.Contains("custom_claim_1", options.Claims);
        Assert.Contains("custom_claim_2", options.Claims);
    }

    [Fact]
    public void RegisterClaims_ThrowsAnExceptionForNullClaims()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.RegisterClaims(claims: null!));
        Assert.Equal("claims", exception.ParamName);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void RegisterClaims_ThrowsAnExceptionForClaim(string claim)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);
        string[] claims = [claim];

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.RegisterClaims(claims));

        Assert.Equal("claims", exception.ParamName);
        Assert.Contains("Claims cannot be null or empty.", exception.Message);
    }

    [Fact]
    public void RegisterScopes_ScopesAreAdded()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.RegisterScopes("custom_scope_1", "custom_scope_2");

        var options = GetOptions(services);

        // Assert
        Assert.Contains("custom_scope_1", options.Scopes);
        Assert.Contains("custom_scope_2", options.Scopes);
    }

    [Fact]
    public void RegisterScopes_ThrowsAnExceptionForNullScopes()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.RegisterScopes(scopes: null!));
        Assert.Equal("scopes", exception.ParamName);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void RegisterScopes_ThrowsAnExceptionForScope(string scope)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);
        string[] scopes = [scope];

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.RegisterScopes(scopes));

        Assert.Equal("scopes", exception.ParamName);
        Assert.Contains("Scopes cannot be null or empty.", exception.Message);
    }

    [Fact]
    public void UseReferenceAccessTokens_ReferenceAccessTokensAreEnabled()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.UseReferenceAccessTokens();

        var options = GetOptions(services);

        // Assert
        Assert.True(options.UseReferenceAccessTokens);
    }

    [Fact]
    public void UseReferenceRefreshTokens_ReferenceRefreshTokensAreEnabled()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.UseReferenceRefreshTokens();

        var options = GetOptions(services);

        // Assert
        Assert.True(options.UseReferenceRefreshTokens);
    }

    private static IServiceCollection CreateServices()
    {
        return new ServiceCollection().AddOptions();
    }

    private static OpenIddictServerBuilder CreateBuilder(IServiceCollection services) => new(services);

    private static OpenIddictServerOptions GetOptions(IServiceCollection services)
    {
        var provider = services.BuildServiceProvider();

        var options = provider.GetRequiredService<IOptions<OpenIddictServerOptions>>();
        //return options.Get(OpenIddictServerDefaults.AuthenticationScheme);
        return options.Value;
    }

    private class CustomContext : BaseContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="BaseContext"/> class.
        /// </summary>
        public CustomContext(OpenIddictServerTransaction transaction) : base(transaction) { }
    }

    private class CustomHandler : IOpenIddictServerHandler<CustomContext>
    {
        public ValueTask HandleAsync(CustomContext context) => default;
    }
}
