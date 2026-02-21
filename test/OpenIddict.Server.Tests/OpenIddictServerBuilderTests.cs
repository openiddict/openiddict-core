using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;

#if !SUPPORTS_CERTIFICATE_GENERATION
using System.Globalization;
using System.Security.Cryptography.X509Certificates;
#endif

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

        var provider = services.BuildServiceProvider();

        var options = provider.GetRequiredService<IOptions<OpenIddictServerOptions>>();

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

        var provider = services.BuildServiceProvider();

        var options = provider.GetRequiredService<IOptions<OpenIddictServerOptions>>();

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
        Assert.Contains(GrantTypes.AuthorizationCode, options.GrantTypes);

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
    public void AllowCustomFlow_ThrowsAnExceptionForType(string? type)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.ThrowsAny<ArgumentException>(() => builder.AllowCustomFlow(type!));

        Assert.Equal("type", exception.ParamName);
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
        Assert.Contains(GrantTypes.AuthorizationCode, options.GrantTypes);
        Assert.Contains(GrantTypes.Implicit, options.GrantTypes);

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
    public void AllowTokenExchangeFlow_TokenExchangeFlowIsAdded()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.AllowTokenExchangeFlow();

        var options = GetOptions(services);

        // Assert
        Assert.Contains(GrantTypes.TokenExchange, options.GrantTypes);
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
    public void DisableAudienceValidation_AudienceValidationIsDisabled()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.DisableAudienceValidation();

        var options = GetOptions(services);

        // Assert
        Assert.True(options.DisableAudienceValidation);
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
    public void DisableResourceValidation_ResourceValidationIsDisabled()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.DisableResourceValidation();

        var options = GetOptions(services);

        // Assert
        Assert.True(options.DisableResourceValidation);
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
    public void EnablePublicKeyInfrastructureTlsClientAuthentication_ThrowsAnExceptionForNullCertificates()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() =>
            builder.EnablePublicKeyInfrastructureTlsClientAuthentication(certificates: null!));

        Assert.Equal("certificates", exception.ParamName);
    }

#if SUPPORTS_X509_CHAIN_POLICY_CUSTOM_TRUST_STORE
    [Fact]
    public void EnablePublicKeyInfrastructureTlsClientAuthentication_ThrowsAnExceptionWhenNoRootCertificateProvided()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);
        var certificates = new X509Certificate2Collection
        {
            // Intermediate certificate:
            X509Certificate2.CreateFromPem($"""
                -----BEGIN CERTIFICATE-----
                MIIFRDCCAyygAwIBAgIRALpTKvDtz6lGPaqNaK8aULowDQYJKoZIhvcNAQELBQAw
                EjEQMA4GA1UEAxMHUm9vdCBDQTAgFw0yNjAxMzAxNzM4NTVaGA8yMTI2MDEzMTE3
                Mzg1NVowGjEYMBYGA1UEAxMPSW50ZXJtZWRpYXRlIENBMIICIjANBgkqhkiG9w0B
                AQEFAAOCAg8AMIICCgKCAgEAvHiS4aNz7vL5mOJNjbpybcK75RhH1sXifLwKW8Zg
                nHm+KjdRENf3X9yp7c+xNrtpHhG4/gp8M++0G1Cz4Yvq8idZu8IpMiqk9/KT447b
                VocaRPCFC4NIC9U6g4s3rwHLUr2wMCAWiM9yjWcbXcvIlnSuA/i/lSAfAUPjrn8X
                LLDgqlEkInmWRvYvDmdmw7vdqfDobFTDh0YRWB/y/LuDvkPFBDg3cfY8+AyrDkha
                y3m1Ot3NTsg0O/HOL6MXMN9HRd4vX37XBV88kZtFE+vyHdYDs2NzGjAbfz4JZ6xz
                4+weUjklOc9ucAEgfAnwijH9w4KFBJEHAqtOMsbrIy74MvPTFj3LeayLo5nhLeqp
                GbqvJcEX1UM83vFt+JUaDVbXDUG2ECHMDe6W5r5eYQtZW1ErKkRYNTJu++I0vDZr
                EeZdYDYp15dbksMXUDyzhJ0WS0N23b7s57S6YAbok97UD/d+aGMtY3kJ/wIiftYY
                Sel/MO/QXrgNchnVtUbShgE2oFvAJUYRvlZarG9/egp3Jb3B4WNjwIyzaT6SFtnG
                Tg+IEXYPE2s5x4YZ8GINygWKrDbV7UuANRjKvoBlGmcrW/iz2Aaa+H5696p1HLVA
                k7gXTw7WlJxzP6JPs2ZjWu27k88oAUV8HJjzFzGUsRPIjkf8KcJuxAqwLPoqFelh
                uNECAwEAAaOBijCBhzASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIB
                BjAdBgNVHQ4EFgQUq7mtVl4BCJyLWTHEpSCqokobTCcwQgYDVR0jBDswOYAUKv1o
                4gZNED0vspeWdqb0WeS3N06hFqQUMBIxEDAOBgNVBAMTB1Jvb3QgQ0GCCQDNRQQ8
                F7il/DANBgkqhkiG9w0BAQsFAAOCAgEArlp0WSTwHgv8wgI+XT/QNxUQBiVyrHql
                SHIMCBA7rDPPsl2RURWzQDE7zqovA3r7fnrYMfVXAAdgzXhDLQwL15RdaeoZUsjH
                xN4y5Mtn0zv1yp7PPtZUc0mZ4Q0xWo4MPve82IfhiqWXretUxvcZ4NKY3sni0s8W
                hViZdHH77vVIWWcWK414cpRwvsDtaKkgS4h8yHiUOtlgKgTViyUd0ovphR0boLtF
                Ddw+jmLGM9c5keIs87RCTqCcHD4nP81kHHUaE60NDMtHH5UONSA5ecsHo11tC1am
                9U2TRs5+zwyBnwy4oOE/EZxXslcz27XyAX7MOhZppue+xtEDyex4gjiS27Nl8Va1
                R1I1vkI5A209OQQ4JXzJZcAtgWep/ez0hu8TOkdtn0l/6aGkj2l3iwVG8edjiwSz
                nVSPaBFKRtrHPuk9uEqu1xtP2klMeJEs7a5bVOyBOzZksafDwVTSPdRnDJDxo/Rx
                bGzSWWYqKNsDxyV9aVMZ1iABW2O7qh6eXbioICzWAWQyplLeihnZ1d0o0h9gk/Kt
                dPuLATo/WSXBA3oDfdEjjEWhmEdj6mR92KrOTQUF7JkOM74ZGs/lCxXsCOva7Z0N
                kZmmpiU3Dewr11+SUxGx8g/4Ba1FhW9pXI9jSYguzY1KY210nF2P5YLsz/HgIM2r
                SVA+QXhvcj0=
                -----END CERTIFICATE-----
                """)
        };

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() =>
            builder.EnablePublicKeyInfrastructureTlsClientAuthentication(certificates));

        Assert.Equal("certificates", exception.ParamName);
    }

    [Fact]
    public void EnablePublicKeyInfrastructureTlsClientAuthentication_ThrowsAnExceptionWhenEndCertificateProvided()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);
        var certificates = new X509Certificate2Collection
        {
            // Root certificate:
            X509Certificate2.CreateFromPem($"""
                -----BEGIN CERTIFICATE-----
                MIIE7jCCAtagAwIBAgIJAM1FBDwXuKX8MA0GCSqGSIb3DQEBCwUAMBIxEDAOBgNV
                BAMTB1Jvb3QgQ0EwIBcNMjYwMTMwMTczODU1WhgPMjEyNjAxMzExNzM4NTVaMBIx
                EDAOBgNVBAMTB1Jvb3QgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
                AQDt/Nz3V5bKbYrJoITYrk3dL9CF+rDcMM6VyJ1pj33feXMTCcRJXkydKDc25sX+
                2C/yrx75zxcUBRoWzsg++YdHJffcZI0+6Q7XBOndNKflCL8lBihvT/EUO9MQYRWV
                495ie3deXoVGebrl6XbGAfm755Ml8KikYFryU6WOxApfQxjcKxnQLNLCTkIyn3WE
                lzce9awtECPgdQfjDzCmE32xXMQcn/0HQUDxiyGvBQbBf8ZM9h3iJz4VGGVQkE7m
                Ix15CwjAyrPc7jGAnUx00QGOCGzfT4bQaHOAZMgEJ8/KJhmx0Fmd6KR1fNJDqDvx
                JYW683y1P512QZgN16e2ZEOdg9fsuXV/PaS6NmHOh7s/hwZsoIf3CJ5dX/M1h1BA
                4buxlvRfeZdANQHJLuQFPC4DQ8SWgbxXhL8KCo0jS9rUPTaxikL7+prFK/t39YFt
                LzowUL8d+sMvUrn3v9yXb363wBB7fja1ZG1EOl7r2YO1uGleRR1ztymfRVziQ/Np
                wRjDeBb9rWL9srPPilvo+5VsJe2a/XtfZuxMoH6vNEl04W6/iyYE4cVizwRC8GTW
                hSHdhk2vT2/eyGSK3Cj5U74x+orHD+3XS6xHd63qB1oo+hJl2Ln/7pBAm9qFnNed
                u6Wn/++Oi7M7nMU/ngEkbPKUfwrR/fEKQuweJaXTgiqj3QIDAQABo0UwQzASBgNV
                HRMBAf8ECDAGAQH/AgEBMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUKv1o4gZN
                ED0vspeWdqb0WeS3N04wDQYJKoZIhvcNAQELBQADggIBACLp5z1zaemqoFPtQ5Sr
                Ii2ijs03Gc52Y/Pbg1V83xg1nMa+vI4aQYc90FZnNOv7I4VAmR6I3cI5bA3tnrzB
                /yCMOkdxiFt6W0OQPMlmlVdCbPtUqXWM3tLilRn90XYEEWZB8I1sOrk2WH7oEHmu
                W7BC2I3igjhUDug2bl7VwdBXzRJrWFgYdhVsjRU9rx3AbZqbD/3pC9B3PcwZxTGz
                k8wRMP/9cF49VvUFVWhp01Bol1StwgX3r6IbaamDdIJd0MvHp0ctgqL6PLRzgRRY
                adzWX8SPlgARVCixSOkXmAGNeuNWT/Ulo0W1xaNVTvOssfx58v3lwnjoaMLi7UFA
                tCPrLZtZYvScB0+0AjUwfIfKrHqRdP5OqJZi7PhahR39tTh9pQX63INQvKYKO583
                iidiNDau4HU+e+ujnXR5xJdgNWtuehKRdZFlLBH0lKKXrrnPyW9YtIjCVf1zhc+L
                VSyo/aajWKBGqyTTbM1zetGe1rah97i7/0snoh97sWHlenmSX3BQUnajLkp9ZMh0
                vY4koR1fxIlxHnOQ7SebZ23QiWUjdmJoOXW6Bub6VhWMDY96EpMr17QiGtexbUHD
                1nm2Z0xGwyWeyg2QSnNEAIZ6F2EeaZ6jmD/5ASXujcutNGyPwsSGkog4/Ir5Ol15
                +3OP4DTt75BHxzMUxB6XmbYN
                -----END CERTIFICATE-----
                """),

            // Intermediate certificate:
            X509Certificate2.CreateFromPem($"""
                -----BEGIN CERTIFICATE-----
                MIIFRDCCAyygAwIBAgIRALpTKvDtz6lGPaqNaK8aULowDQYJKoZIhvcNAQELBQAw
                EjEQMA4GA1UEAxMHUm9vdCBDQTAgFw0yNjAxMzAxNzM4NTVaGA8yMTI2MDEzMTE3
                Mzg1NVowGjEYMBYGA1UEAxMPSW50ZXJtZWRpYXRlIENBMIICIjANBgkqhkiG9w0B
                AQEFAAOCAg8AMIICCgKCAgEAvHiS4aNz7vL5mOJNjbpybcK75RhH1sXifLwKW8Zg
                nHm+KjdRENf3X9yp7c+xNrtpHhG4/gp8M++0G1Cz4Yvq8idZu8IpMiqk9/KT447b
                VocaRPCFC4NIC9U6g4s3rwHLUr2wMCAWiM9yjWcbXcvIlnSuA/i/lSAfAUPjrn8X
                LLDgqlEkInmWRvYvDmdmw7vdqfDobFTDh0YRWB/y/LuDvkPFBDg3cfY8+AyrDkha
                y3m1Ot3NTsg0O/HOL6MXMN9HRd4vX37XBV88kZtFE+vyHdYDs2NzGjAbfz4JZ6xz
                4+weUjklOc9ucAEgfAnwijH9w4KFBJEHAqtOMsbrIy74MvPTFj3LeayLo5nhLeqp
                GbqvJcEX1UM83vFt+JUaDVbXDUG2ECHMDe6W5r5eYQtZW1ErKkRYNTJu++I0vDZr
                EeZdYDYp15dbksMXUDyzhJ0WS0N23b7s57S6YAbok97UD/d+aGMtY3kJ/wIiftYY
                Sel/MO/QXrgNchnVtUbShgE2oFvAJUYRvlZarG9/egp3Jb3B4WNjwIyzaT6SFtnG
                Tg+IEXYPE2s5x4YZ8GINygWKrDbV7UuANRjKvoBlGmcrW/iz2Aaa+H5696p1HLVA
                k7gXTw7WlJxzP6JPs2ZjWu27k88oAUV8HJjzFzGUsRPIjkf8KcJuxAqwLPoqFelh
                uNECAwEAAaOBijCBhzASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIB
                BjAdBgNVHQ4EFgQUq7mtVl4BCJyLWTHEpSCqokobTCcwQgYDVR0jBDswOYAUKv1o
                4gZNED0vspeWdqb0WeS3N06hFqQUMBIxEDAOBgNVBAMTB1Jvb3QgQ0GCCQDNRQQ8
                F7il/DANBgkqhkiG9w0BAQsFAAOCAgEArlp0WSTwHgv8wgI+XT/QNxUQBiVyrHql
                SHIMCBA7rDPPsl2RURWzQDE7zqovA3r7fnrYMfVXAAdgzXhDLQwL15RdaeoZUsjH
                xN4y5Mtn0zv1yp7PPtZUc0mZ4Q0xWo4MPve82IfhiqWXretUxvcZ4NKY3sni0s8W
                hViZdHH77vVIWWcWK414cpRwvsDtaKkgS4h8yHiUOtlgKgTViyUd0ovphR0boLtF
                Ddw+jmLGM9c5keIs87RCTqCcHD4nP81kHHUaE60NDMtHH5UONSA5ecsHo11tC1am
                9U2TRs5+zwyBnwy4oOE/EZxXslcz27XyAX7MOhZppue+xtEDyex4gjiS27Nl8Va1
                R1I1vkI5A209OQQ4JXzJZcAtgWep/ez0hu8TOkdtn0l/6aGkj2l3iwVG8edjiwSz
                nVSPaBFKRtrHPuk9uEqu1xtP2klMeJEs7a5bVOyBOzZksafDwVTSPdRnDJDxo/Rx
                bGzSWWYqKNsDxyV9aVMZ1iABW2O7qh6eXbioICzWAWQyplLeihnZ1d0o0h9gk/Kt
                dPuLATo/WSXBA3oDfdEjjEWhmEdj6mR92KrOTQUF7JkOM74ZGs/lCxXsCOva7Z0N
                kZmmpiU3Dewr11+SUxGx8g/4Ba1FhW9pXI9jSYguzY1KY210nF2P5YLsz/HgIM2r
                SVA+QXhvcj0=
                -----END CERTIFICATE-----
                """),

            // End certificate:
            X509Certificate2.CreateFromPem($"""
                -----BEGIN CERTIFICATE-----
                MIIEfDCCAmSgAwIBAgIRAMrgbbME5gBGSu3XfBUTMZAwDQYJKoZIhvcNAQELBQAw
                GjEYMBYGA1UEAxMPSW50ZXJtZWRpYXRlIENBMCAXDTI2MDEzMDE3Mzg1NVoYDzIx
                MjYwMTMxMTczODU1WjAaMRgwFgYDVQQDEw9FbmQgY2VydGlmaWNhdGUwggEiMA0G
                CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDY5UyMDT2evGgOXTzuH6adZmLcjLbv
                9u1cdpfYc2jgdA+jXm0hvQmhwmQMosu0KDFtMX0okZ4xM0H5XEDbxmKBY7WwAdFF
                Morz7tu/UzRLYXUJp/SRk6/zXKb4qkvtWaEcKBujlLA7jUEDcrCmTaoyU0Zz9ZzG
                zrJc59UceXSH3gAoAkoQesNKUBsdgdk8Na3h+U8nLl4rHXWkSYi/VwKkROaDfnT2
                mgpsJfBVyQtuAJDXsLFRhtmsPnR3KoutJUh69WnlC7mRrTVI2rhUPKFny1gGxk1W
                rsI9vzkIIiLkc+tsAR76DNnoVkXhuqEQ9SMnl5CxV2GFWEX/TOLhteVVAgMBAAGj
                gbowgbcwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAww
                CgYIKwYBBQUHAwIwHQYDVR0OBBYEFCRF8sJJqhgyr/A8RnsP/JUE06dGMEoGA1Ud
                IwRDMEGAFKu5rVZeAQici1kxxKUgqqJKG0wnoRakFDASMRAwDgYDVQQDEwdSb290
                IENBghEAulMq8O3PqUY9qo1orxpQujAUBgNVHREEDTALgglsb2NhbGhvc3QwDQYJ
                KoZIhvcNAQELBQADggIBACW7bCe7KpuAVZO4jIjtMLwKJ+1QZ7551FIsvBLDCFF+
                fX2zND0ne+8hv1qemHdzDBED6WeurOQqGtgI+adj7HrXAfAXKihBaCjq2U6U3sR5
                fqyYY5of1gvJhvJK+TEY3Fb55PvA+j38GwI52hKSkRdunPpCjRI1d/+Jvb+voUOa
                kzLsARgOaMhJtYQeMebKr7uSLezFoOaRfc5rqpiVTA7xXO8dHkz2p49bxfIRj1Tq
                2Lgx9uAE4omwzxSB/cwZiG1tNgpVVvn2Tb20SgCIBGl7Oqave+LRm1Eztl0Q8e8C
                iz6bLMiCcesRRFxU8TE2mhmNOeNUsBIP730+ZOnP2rgX3Zs93gTFX/omPuQS8Kj3
                ly5+v+PZkuN3xZ56mLXURlDRmWI1gqNRgNYl1jwYyQ0ll05yk3JFIyUvxdg3klRK
                9/+MoKw8PVGbSKntzoHiqVUHnrB1lemJqZ91Dx+h8K58eaRs3/aL0lUEli7NpNXR
                5Q6Tl7cCVe5ZjtR7Z56IQLmswq/TNJVXQSBjLLwLCkaJvTXWwojkG5ETU/t/ikCG
                c2bH6ICUizzz2gdJNdcIP8wc7SsxONdpPmK3ED3KQBlTVDRUJ/w9Q4HYztXEFiyg
                xkNzboe3SYq92mqVilBTiY51SNZuOr8zRZp9gcMKoQgmxgfl7j6JiRVpZzoxb54Y
                -----END CERTIFICATE-----
                """)
        };

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() =>
            builder.EnablePublicKeyInfrastructureTlsClientAuthentication(certificates));

        Assert.Equal("certificates", exception.ParamName);
    }

    [Fact]
    public void EnablePublicKeyInfrastructureTlsClientAuthentication_PolicyIsCorrectlyConfigured()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);
        var certificates = new X509Certificate2Collection
        {
            // Root certificate:
            X509Certificate2.CreateFromPem($"""
                -----BEGIN CERTIFICATE-----
                MIIE7jCCAtagAwIBAgIJAM1FBDwXuKX8MA0GCSqGSIb3DQEBCwUAMBIxEDAOBgNV
                BAMTB1Jvb3QgQ0EwIBcNMjYwMTMwMTczODU1WhgPMjEyNjAxMzExNzM4NTVaMBIx
                EDAOBgNVBAMTB1Jvb3QgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
                AQDt/Nz3V5bKbYrJoITYrk3dL9CF+rDcMM6VyJ1pj33feXMTCcRJXkydKDc25sX+
                2C/yrx75zxcUBRoWzsg++YdHJffcZI0+6Q7XBOndNKflCL8lBihvT/EUO9MQYRWV
                495ie3deXoVGebrl6XbGAfm755Ml8KikYFryU6WOxApfQxjcKxnQLNLCTkIyn3WE
                lzce9awtECPgdQfjDzCmE32xXMQcn/0HQUDxiyGvBQbBf8ZM9h3iJz4VGGVQkE7m
                Ix15CwjAyrPc7jGAnUx00QGOCGzfT4bQaHOAZMgEJ8/KJhmx0Fmd6KR1fNJDqDvx
                JYW683y1P512QZgN16e2ZEOdg9fsuXV/PaS6NmHOh7s/hwZsoIf3CJ5dX/M1h1BA
                4buxlvRfeZdANQHJLuQFPC4DQ8SWgbxXhL8KCo0jS9rUPTaxikL7+prFK/t39YFt
                LzowUL8d+sMvUrn3v9yXb363wBB7fja1ZG1EOl7r2YO1uGleRR1ztymfRVziQ/Np
                wRjDeBb9rWL9srPPilvo+5VsJe2a/XtfZuxMoH6vNEl04W6/iyYE4cVizwRC8GTW
                hSHdhk2vT2/eyGSK3Cj5U74x+orHD+3XS6xHd63qB1oo+hJl2Ln/7pBAm9qFnNed
                u6Wn/++Oi7M7nMU/ngEkbPKUfwrR/fEKQuweJaXTgiqj3QIDAQABo0UwQzASBgNV
                HRMBAf8ECDAGAQH/AgEBMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUKv1o4gZN
                ED0vspeWdqb0WeS3N04wDQYJKoZIhvcNAQELBQADggIBACLp5z1zaemqoFPtQ5Sr
                Ii2ijs03Gc52Y/Pbg1V83xg1nMa+vI4aQYc90FZnNOv7I4VAmR6I3cI5bA3tnrzB
                /yCMOkdxiFt6W0OQPMlmlVdCbPtUqXWM3tLilRn90XYEEWZB8I1sOrk2WH7oEHmu
                W7BC2I3igjhUDug2bl7VwdBXzRJrWFgYdhVsjRU9rx3AbZqbD/3pC9B3PcwZxTGz
                k8wRMP/9cF49VvUFVWhp01Bol1StwgX3r6IbaamDdIJd0MvHp0ctgqL6PLRzgRRY
                adzWX8SPlgARVCixSOkXmAGNeuNWT/Ulo0W1xaNVTvOssfx58v3lwnjoaMLi7UFA
                tCPrLZtZYvScB0+0AjUwfIfKrHqRdP5OqJZi7PhahR39tTh9pQX63INQvKYKO583
                iidiNDau4HU+e+ujnXR5xJdgNWtuehKRdZFlLBH0lKKXrrnPyW9YtIjCVf1zhc+L
                VSyo/aajWKBGqyTTbM1zetGe1rah97i7/0snoh97sWHlenmSX3BQUnajLkp9ZMh0
                vY4koR1fxIlxHnOQ7SebZ23QiWUjdmJoOXW6Bub6VhWMDY96EpMr17QiGtexbUHD
                1nm2Z0xGwyWeyg2QSnNEAIZ6F2EeaZ6jmD/5ASXujcutNGyPwsSGkog4/Ir5Ol15
                +3OP4DTt75BHxzMUxB6XmbYN
                -----END CERTIFICATE-----
                """),

            // Intermediate certificate:
            X509Certificate2.CreateFromPem($"""
                -----BEGIN CERTIFICATE-----
                MIIFRDCCAyygAwIBAgIRALpTKvDtz6lGPaqNaK8aULowDQYJKoZIhvcNAQELBQAw
                EjEQMA4GA1UEAxMHUm9vdCBDQTAgFw0yNjAxMzAxNzM4NTVaGA8yMTI2MDEzMTE3
                Mzg1NVowGjEYMBYGA1UEAxMPSW50ZXJtZWRpYXRlIENBMIICIjANBgkqhkiG9w0B
                AQEFAAOCAg8AMIICCgKCAgEAvHiS4aNz7vL5mOJNjbpybcK75RhH1sXifLwKW8Zg
                nHm+KjdRENf3X9yp7c+xNrtpHhG4/gp8M++0G1Cz4Yvq8idZu8IpMiqk9/KT447b
                VocaRPCFC4NIC9U6g4s3rwHLUr2wMCAWiM9yjWcbXcvIlnSuA/i/lSAfAUPjrn8X
                LLDgqlEkInmWRvYvDmdmw7vdqfDobFTDh0YRWB/y/LuDvkPFBDg3cfY8+AyrDkha
                y3m1Ot3NTsg0O/HOL6MXMN9HRd4vX37XBV88kZtFE+vyHdYDs2NzGjAbfz4JZ6xz
                4+weUjklOc9ucAEgfAnwijH9w4KFBJEHAqtOMsbrIy74MvPTFj3LeayLo5nhLeqp
                GbqvJcEX1UM83vFt+JUaDVbXDUG2ECHMDe6W5r5eYQtZW1ErKkRYNTJu++I0vDZr
                EeZdYDYp15dbksMXUDyzhJ0WS0N23b7s57S6YAbok97UD/d+aGMtY3kJ/wIiftYY
                Sel/MO/QXrgNchnVtUbShgE2oFvAJUYRvlZarG9/egp3Jb3B4WNjwIyzaT6SFtnG
                Tg+IEXYPE2s5x4YZ8GINygWKrDbV7UuANRjKvoBlGmcrW/iz2Aaa+H5696p1HLVA
                k7gXTw7WlJxzP6JPs2ZjWu27k88oAUV8HJjzFzGUsRPIjkf8KcJuxAqwLPoqFelh
                uNECAwEAAaOBijCBhzASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIB
                BjAdBgNVHQ4EFgQUq7mtVl4BCJyLWTHEpSCqokobTCcwQgYDVR0jBDswOYAUKv1o
                4gZNED0vspeWdqb0WeS3N06hFqQUMBIxEDAOBgNVBAMTB1Jvb3QgQ0GCCQDNRQQ8
                F7il/DANBgkqhkiG9w0BAQsFAAOCAgEArlp0WSTwHgv8wgI+XT/QNxUQBiVyrHql
                SHIMCBA7rDPPsl2RURWzQDE7zqovA3r7fnrYMfVXAAdgzXhDLQwL15RdaeoZUsjH
                xN4y5Mtn0zv1yp7PPtZUc0mZ4Q0xWo4MPve82IfhiqWXretUxvcZ4NKY3sni0s8W
                hViZdHH77vVIWWcWK414cpRwvsDtaKkgS4h8yHiUOtlgKgTViyUd0ovphR0boLtF
                Ddw+jmLGM9c5keIs87RCTqCcHD4nP81kHHUaE60NDMtHH5UONSA5ecsHo11tC1am
                9U2TRs5+zwyBnwy4oOE/EZxXslcz27XyAX7MOhZppue+xtEDyex4gjiS27Nl8Va1
                R1I1vkI5A209OQQ4JXzJZcAtgWep/ez0hu8TOkdtn0l/6aGkj2l3iwVG8edjiwSz
                nVSPaBFKRtrHPuk9uEqu1xtP2klMeJEs7a5bVOyBOzZksafDwVTSPdRnDJDxo/Rx
                bGzSWWYqKNsDxyV9aVMZ1iABW2O7qh6eXbioICzWAWQyplLeihnZ1d0o0h9gk/Kt
                dPuLATo/WSXBA3oDfdEjjEWhmEdj6mR92KrOTQUF7JkOM74ZGs/lCxXsCOva7Z0N
                kZmmpiU3Dewr11+SUxGx8g/4Ba1FhW9pXI9jSYguzY1KY210nF2P5YLsz/HgIM2r
                SVA+QXhvcj0=
                -----END CERTIFICATE-----
                """)
        };

        // Act
        builder.EnablePublicKeyInfrastructureTlsClientAuthentication(certificates);

        var options = GetOptions(services);

        // Assert
        Assert.NotNull(options.PublicKeyInfrastructureTlsClientAuthenticationPolicy);
        Assert.Equal(X509ChainTrustMode.CustomRootTrust, options.PublicKeyInfrastructureTlsClientAuthenticationPolicy.TrustMode);
        Assert.Contains(options.PublicKeyInfrastructureTlsClientAuthenticationPolicy.ApplicationPolicy.Cast<Oid>(),
            oid => oid.Value == ObjectIdentifiers.ExtendedKeyUsages.ClientAuthentication);
    }

    [Fact]
    public void EnablePublicKeyInfrastructureTlsClientAuthentication_ThrowsAnExceptionWhenTrustModeIsChanged()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);
        var certificates = new X509Certificate2Collection
        {
            // Root certificate:
            X509Certificate2.CreateFromPem($"""
                -----BEGIN CERTIFICATE-----
                MIIE7jCCAtagAwIBAgIJAM1FBDwXuKX8MA0GCSqGSIb3DQEBCwUAMBIxEDAOBgNV
                BAMTB1Jvb3QgQ0EwIBcNMjYwMTMwMTczODU1WhgPMjEyNjAxMzExNzM4NTVaMBIx
                EDAOBgNVBAMTB1Jvb3QgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
                AQDt/Nz3V5bKbYrJoITYrk3dL9CF+rDcMM6VyJ1pj33feXMTCcRJXkydKDc25sX+
                2C/yrx75zxcUBRoWzsg++YdHJffcZI0+6Q7XBOndNKflCL8lBihvT/EUO9MQYRWV
                495ie3deXoVGebrl6XbGAfm755Ml8KikYFryU6WOxApfQxjcKxnQLNLCTkIyn3WE
                lzce9awtECPgdQfjDzCmE32xXMQcn/0HQUDxiyGvBQbBf8ZM9h3iJz4VGGVQkE7m
                Ix15CwjAyrPc7jGAnUx00QGOCGzfT4bQaHOAZMgEJ8/KJhmx0Fmd6KR1fNJDqDvx
                JYW683y1P512QZgN16e2ZEOdg9fsuXV/PaS6NmHOh7s/hwZsoIf3CJ5dX/M1h1BA
                4buxlvRfeZdANQHJLuQFPC4DQ8SWgbxXhL8KCo0jS9rUPTaxikL7+prFK/t39YFt
                LzowUL8d+sMvUrn3v9yXb363wBB7fja1ZG1EOl7r2YO1uGleRR1ztymfRVziQ/Np
                wRjDeBb9rWL9srPPilvo+5VsJe2a/XtfZuxMoH6vNEl04W6/iyYE4cVizwRC8GTW
                hSHdhk2vT2/eyGSK3Cj5U74x+orHD+3XS6xHd63qB1oo+hJl2Ln/7pBAm9qFnNed
                u6Wn/++Oi7M7nMU/ngEkbPKUfwrR/fEKQuweJaXTgiqj3QIDAQABo0UwQzASBgNV
                HRMBAf8ECDAGAQH/AgEBMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUKv1o4gZN
                ED0vspeWdqb0WeS3N04wDQYJKoZIhvcNAQELBQADggIBACLp5z1zaemqoFPtQ5Sr
                Ii2ijs03Gc52Y/Pbg1V83xg1nMa+vI4aQYc90FZnNOv7I4VAmR6I3cI5bA3tnrzB
                /yCMOkdxiFt6W0OQPMlmlVdCbPtUqXWM3tLilRn90XYEEWZB8I1sOrk2WH7oEHmu
                W7BC2I3igjhUDug2bl7VwdBXzRJrWFgYdhVsjRU9rx3AbZqbD/3pC9B3PcwZxTGz
                k8wRMP/9cF49VvUFVWhp01Bol1StwgX3r6IbaamDdIJd0MvHp0ctgqL6PLRzgRRY
                adzWX8SPlgARVCixSOkXmAGNeuNWT/Ulo0W1xaNVTvOssfx58v3lwnjoaMLi7UFA
                tCPrLZtZYvScB0+0AjUwfIfKrHqRdP5OqJZi7PhahR39tTh9pQX63INQvKYKO583
                iidiNDau4HU+e+ujnXR5xJdgNWtuehKRdZFlLBH0lKKXrrnPyW9YtIjCVf1zhc+L
                VSyo/aajWKBGqyTTbM1zetGe1rah97i7/0snoh97sWHlenmSX3BQUnajLkp9ZMh0
                vY4koR1fxIlxHnOQ7SebZ23QiWUjdmJoOXW6Bub6VhWMDY96EpMr17QiGtexbUHD
                1nm2Z0xGwyWeyg2QSnNEAIZ6F2EeaZ6jmD/5ASXujcutNGyPwsSGkog4/Ir5Ol15
                +3OP4DTt75BHxzMUxB6XmbYN
                -----END CERTIFICATE-----
                """),

            // Intermediate certificate:
            X509Certificate2.CreateFromPem($"""
                -----BEGIN CERTIFICATE-----
                MIIFRDCCAyygAwIBAgIRALpTKvDtz6lGPaqNaK8aULowDQYJKoZIhvcNAQELBQAw
                EjEQMA4GA1UEAxMHUm9vdCBDQTAgFw0yNjAxMzAxNzM4NTVaGA8yMTI2MDEzMTE3
                Mzg1NVowGjEYMBYGA1UEAxMPSW50ZXJtZWRpYXRlIENBMIICIjANBgkqhkiG9w0B
                AQEFAAOCAg8AMIICCgKCAgEAvHiS4aNz7vL5mOJNjbpybcK75RhH1sXifLwKW8Zg
                nHm+KjdRENf3X9yp7c+xNrtpHhG4/gp8M++0G1Cz4Yvq8idZu8IpMiqk9/KT447b
                VocaRPCFC4NIC9U6g4s3rwHLUr2wMCAWiM9yjWcbXcvIlnSuA/i/lSAfAUPjrn8X
                LLDgqlEkInmWRvYvDmdmw7vdqfDobFTDh0YRWB/y/LuDvkPFBDg3cfY8+AyrDkha
                y3m1Ot3NTsg0O/HOL6MXMN9HRd4vX37XBV88kZtFE+vyHdYDs2NzGjAbfz4JZ6xz
                4+weUjklOc9ucAEgfAnwijH9w4KFBJEHAqtOMsbrIy74MvPTFj3LeayLo5nhLeqp
                GbqvJcEX1UM83vFt+JUaDVbXDUG2ECHMDe6W5r5eYQtZW1ErKkRYNTJu++I0vDZr
                EeZdYDYp15dbksMXUDyzhJ0WS0N23b7s57S6YAbok97UD/d+aGMtY3kJ/wIiftYY
                Sel/MO/QXrgNchnVtUbShgE2oFvAJUYRvlZarG9/egp3Jb3B4WNjwIyzaT6SFtnG
                Tg+IEXYPE2s5x4YZ8GINygWKrDbV7UuANRjKvoBlGmcrW/iz2Aaa+H5696p1HLVA
                k7gXTw7WlJxzP6JPs2ZjWu27k88oAUV8HJjzFzGUsRPIjkf8KcJuxAqwLPoqFelh
                uNECAwEAAaOBijCBhzASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIB
                BjAdBgNVHQ4EFgQUq7mtVl4BCJyLWTHEpSCqokobTCcwQgYDVR0jBDswOYAUKv1o
                4gZNED0vspeWdqb0WeS3N06hFqQUMBIxEDAOBgNVBAMTB1Jvb3QgQ0GCCQDNRQQ8
                F7il/DANBgkqhkiG9w0BAQsFAAOCAgEArlp0WSTwHgv8wgI+XT/QNxUQBiVyrHql
                SHIMCBA7rDPPsl2RURWzQDE7zqovA3r7fnrYMfVXAAdgzXhDLQwL15RdaeoZUsjH
                xN4y5Mtn0zv1yp7PPtZUc0mZ4Q0xWo4MPve82IfhiqWXretUxvcZ4NKY3sni0s8W
                hViZdHH77vVIWWcWK414cpRwvsDtaKkgS4h8yHiUOtlgKgTViyUd0ovphR0boLtF
                Ddw+jmLGM9c5keIs87RCTqCcHD4nP81kHHUaE60NDMtHH5UONSA5ecsHo11tC1am
                9U2TRs5+zwyBnwy4oOE/EZxXslcz27XyAX7MOhZppue+xtEDyex4gjiS27Nl8Va1
                R1I1vkI5A209OQQ4JXzJZcAtgWep/ez0hu8TOkdtn0l/6aGkj2l3iwVG8edjiwSz
                nVSPaBFKRtrHPuk9uEqu1xtP2klMeJEs7a5bVOyBOzZksafDwVTSPdRnDJDxo/Rx
                bGzSWWYqKNsDxyV9aVMZ1iABW2O7qh6eXbioICzWAWQyplLeihnZ1d0o0h9gk/Kt
                dPuLATo/WSXBA3oDfdEjjEWhmEdj6mR92KrOTQUF7JkOM74ZGs/lCxXsCOva7Z0N
                kZmmpiU3Dewr11+SUxGx8g/4Ba1FhW9pXI9jSYguzY1KY210nF2P5YLsz/HgIM2r
                SVA+QXhvcj0=
                -----END CERTIFICATE-----
                """)
        };

        // Act and assert
        var exception = Assert.Throws<InvalidOperationException>(() =>
            builder.EnablePublicKeyInfrastructureTlsClientAuthentication(certificates,
                policy => policy.TrustMode = X509ChainTrustMode.System));

        Assert.Equal(SR.GetResourceString(SR.ID0509), exception.Message);
    }
#endif

    [Fact]
    public void EnableSelfSignedTlsClientAuthentication_ThrowsAnExceptionForNullConfiguration()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() =>
            builder.EnableSelfSignedTlsClientAuthentication(configuration: null!));

        Assert.Equal("configuration", exception.ParamName);
    }

#if SUPPORTS_X509_CHAIN_POLICY_CUSTOM_TRUST_STORE
    [Fact]
    public void EnableSelfSignedTlsClientAuthentication_PolicyIsCorrectlyConfigured()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.EnableSelfSignedTlsClientAuthentication();

        var options = GetOptions(services);

        // Assert
        Assert.NotNull(options.SelfSignedTlsClientAuthenticationPolicy);
        Assert.Equal(X509ChainTrustMode.CustomRootTrust, options.SelfSignedTlsClientAuthenticationPolicy.TrustMode);
        Assert.Equal(X509RevocationMode.NoCheck, options.SelfSignedTlsClientAuthenticationPolicy.RevocationMode);
        Assert.Contains(options.SelfSignedTlsClientAuthenticationPolicy.ApplicationPolicy.Cast<Oid>(),
            oid => oid.Value == ObjectIdentifiers.ExtendedKeyUsages.ClientAuthentication);
    }

    [Fact]
    public void EnableSelfSignedTlsClientAuthentication_ThrowsAnExceptionWhenTrustModeIsChanged()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<InvalidOperationException>(() =>
            builder.EnableSelfSignedTlsClientAuthentication(
                policy => policy.TrustMode = X509ChainTrustMode.System));

        Assert.Equal(SR.GetResourceString(SR.ID0509), exception.Message);
    }
#endif

    [Fact]
    public void IgnoreAudiencePermissions_AudiencePermissionsAreIgnored()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.IgnoreAudiencePermissions();

        var options = GetOptions(services);

        // Assert
        Assert.True(options.IgnoreAudiencePermissions);
    }

    [Fact]
    public void IgnoreGrantTypePermissions_GrantTypePermissionsAreIgnored()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.IgnoreGrantTypePermissions();

        var options = GetOptions(services);

        // Assert
        Assert.True(options.IgnoreGrantTypePermissions);
    }

    [Fact]
    public void IgnoreScopePermissions_ScopePermissionsAreIgnored()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.IgnoreScopePermissions();

        var options = GetOptions(services);

        // Assert
        Assert.True(options.IgnoreScopePermissions);
    }

    [Fact]
    public void IgnoreResourcePermissions_ResourcePermissionsAreIgnored()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.IgnoreResourcePermissions();

        var options = GetOptions(services);

        // Assert
        Assert.True(options.IgnoreResourcePermissions);
    }

    [Fact]
    public void IgnoreResponseTypePermissions_ResponseTypePermissionsAreIgnored()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.IgnoreResponseTypePermissions();

        var options = GetOptions(services);

        // Assert
        Assert.True(options.IgnoreResponseTypePermissions);
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
    public void SetEndSessionEndpointUris_ThrowsExceptionWhenUrisIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetEndSessionEndpointUris(uris: (null as Uri[])!));
        Assert.Equal("uris", exception.ParamName);
    }

    [Fact]
    public void SetEndSessionEndpointUris_Strings_ThrowsExceptionWhenUrisIsNull()
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
    public void SetEndSessionEndpointUris_ThrowsExceptionForMalformedUri(string uri)
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
    public void SetEndSessionEndpointUris_ThrowsExceptionForInvalidRelativeUri(string uri)
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
    public void SetEndSessionEndpointUris_ClearsUris()
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
    public void SetEndSessionEndpointUris_AddsUri()
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
    public void SetMtlsDeviceAuthorizationEndpointAliasUri_ThrowsExceptionWhenUriIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetMtlsDeviceAuthorizationEndpointAliasUri(uri: (null as Uri)!));
        Assert.Equal("uri", exception.ParamName);
    }

    [Fact]
    public void SetMtlsDeviceAuthorizationEndpointAliasUri_String_ThrowsExceptionWhenUriIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetMtlsDeviceAuthorizationEndpointAliasUri(uri: (null as string)!));
        Assert.Equal("uri", exception.ParamName);
    }

    [Theory]
    [InlineData(@"C:\")]
    public void SetMtlsDeviceAuthorizationEndpointAliasUri_ThrowsExceptionForMalformedUri(string uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetMtlsDeviceAuthorizationEndpointAliasUri(new Uri(uri)));
        Assert.Equal("uri", exception.ParamName);
        Assert.Contains(SR.GetResourceString(SR.ID0072), exception.Message);
    }

    [Theory]
    [InlineData("~/path")]
    public void SetMtlsDeviceAuthorizationEndpointAliasUri_ThrowsExceptionForInvalidRelativeUri(string uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetMtlsDeviceAuthorizationEndpointAliasUri(new Uri(uri, UriKind.RelativeOrAbsolute)));
        Assert.Equal("uri", exception.ParamName);
        Assert.Contains(SR.FormatID0081("~"), exception.Message);
    }

    [Fact]
    public void SetMtlsDeviceAuthorizationEndpointAliasUri_AddsUri()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetMtlsDeviceAuthorizationEndpointAliasUri("http://localhost/endpoint-path");

        var options = GetOptions(services);

        // Assert
        Assert.Equal(new Uri("http://localhost/endpoint-path"), options.MtlsDeviceAuthorizationEndpointAliasUri);
    }

    [Fact]
    public void SetMtlsIntrospectionEndpointAliasUri_ThrowsExceptionWhenUriIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetMtlsIntrospectionEndpointAliasUri(uri: (null as Uri)!));
        Assert.Equal("uri", exception.ParamName);
    }

    [Fact]
    public void SetMtlsIntrospectionEndpointAliasUri_String_ThrowsExceptionWhenUriIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetMtlsIntrospectionEndpointAliasUri(uri: (null as string)!));
        Assert.Equal("uri", exception.ParamName);
    }

    [Theory]
    [InlineData(@"C:\")]
    public void SetMtlsIntrospectionEndpointAliasUri_ThrowsExceptionForMalformedUri(string uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetMtlsIntrospectionEndpointAliasUri(new Uri(uri)));
        Assert.Equal("uri", exception.ParamName);
        Assert.Contains(SR.GetResourceString(SR.ID0072), exception.Message);
    }

    [Theory]
    [InlineData("~/path")]
    public void SetMtlsIntrospectionEndpointAliasUri_ThrowsExceptionForInvalidRelativeUri(string uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetMtlsIntrospectionEndpointAliasUri(new Uri(uri, UriKind.RelativeOrAbsolute)));
        Assert.Equal("uri", exception.ParamName);
        Assert.Contains(SR.FormatID0081("~"), exception.Message);
    }

    [Fact]
    public void SetMtlsIntrospectionEndpointAliasUri_AddsUri()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetMtlsIntrospectionEndpointAliasUri("http://localhost/endpoint-path");

        var options = GetOptions(services);

        // Assert
        Assert.Equal(new Uri("http://localhost/endpoint-path"), options.MtlsIntrospectionEndpointAliasUri);
    }

    [Fact]
    public void SetMtlsPushedAuthorizationEndpointAliasUri_ThrowsExceptionWhenUriIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetMtlsPushedAuthorizationEndpointAliasUri(uri: (null as Uri)!));
        Assert.Equal("uri", exception.ParamName);
    }

    [Fact]
    public void SetMtlsPushedAuthorizationEndpointAliasUri_String_ThrowsExceptionWhenUriIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetMtlsPushedAuthorizationEndpointAliasUri(uri: (null as string)!));
        Assert.Equal("uri", exception.ParamName);
    }

    [Theory]
    [InlineData(@"C:\")]
    public void SetMtlsPushedAuthorizationEndpointAliasUri_ThrowsExceptionForMalformedUri(string uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetMtlsPushedAuthorizationEndpointAliasUri(new Uri(uri)));
        Assert.Equal("uri", exception.ParamName);
        Assert.Contains(SR.GetResourceString(SR.ID0072), exception.Message);
    }

    [Theory]
    [InlineData("~/path")]
    public void SetMtlsPushedAuthorizationEndpointAliasUri_ThrowsExceptionForInvalidRelativeUri(string uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetMtlsPushedAuthorizationEndpointAliasUri(new Uri(uri, UriKind.RelativeOrAbsolute)));
        Assert.Equal("uri", exception.ParamName);
        Assert.Contains(SR.FormatID0081("~"), exception.Message);
    }

    [Fact]
    public void SetMtlsPushedAuthorizationEndpointAliasUri_AddsUri()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetMtlsPushedAuthorizationEndpointAliasUri("http://localhost/endpoint-path");

        var options = GetOptions(services);

        // Assert
        Assert.Equal(new Uri("http://localhost/endpoint-path"), options.MtlsPushedAuthorizationEndpointAliasUri);
    }

    [Fact]
    public void SetMtlsRevocationEndpointAliasUri_ThrowsExceptionWhenUriIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetMtlsRevocationEndpointAliasUri(uri: (null as Uri)!));
        Assert.Equal("uri", exception.ParamName);
    }

    [Fact]
    public void SetMtlsRevocationEndpointAliasUri_String_ThrowsExceptionWhenUriIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetMtlsRevocationEndpointAliasUri(uri: (null as string)!));
        Assert.Equal("uri", exception.ParamName);
    }

    [Theory]
    [InlineData(@"C:\")]
    public void SetMtlsRevocationEndpointAliasUri_ThrowsExceptionForMalformedUri(string uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetMtlsRevocationEndpointAliasUri(new Uri(uri)));
        Assert.Equal("uri", exception.ParamName);
        Assert.Contains(SR.GetResourceString(SR.ID0072), exception.Message);
    }

    [Theory]
    [InlineData("~/path")]
    public void SetMtlsRevocationEndpointAliasUri_ThrowsExceptionForInvalidRelativeUri(string uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetMtlsRevocationEndpointAliasUri(new Uri(uri, UriKind.RelativeOrAbsolute)));
        Assert.Equal("uri", exception.ParamName);
        Assert.Contains(SR.FormatID0081("~"), exception.Message);
    }

    [Fact]
    public void SetMtlsRevocationEndpointAliasUri_AddsUri()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetMtlsRevocationEndpointAliasUri("http://localhost/endpoint-path");

        var options = GetOptions(services);

        // Assert
        Assert.Equal(new Uri("http://localhost/endpoint-path"), options.MtlsRevocationEndpointAliasUri);
    }

    [Fact]
    public void SetMtlsTokenEndpointAliasUri_ThrowsExceptionWhenUriIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetMtlsTokenEndpointAliasUri(uri: (null as Uri)!));
        Assert.Equal("uri", exception.ParamName);
    }

    [Fact]
    public void SetMtlsTokenEndpointAliasUri_String_ThrowsExceptionWhenUriIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetMtlsTokenEndpointAliasUri(uri: (null as string)!));
        Assert.Equal("uri", exception.ParamName);
    }

    [Theory]
    [InlineData(@"C:\")]
    public void SetMtlsTokenEndpointAliasUri_ThrowsExceptionForMalformedUri(string uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetMtlsTokenEndpointAliasUri(new Uri(uri)));
        Assert.Equal("uri", exception.ParamName);
        Assert.Contains(SR.GetResourceString(SR.ID0072), exception.Message);
    }

    [Theory]
    [InlineData("~/path")]
    public void SetMtlsTokenEndpointAliasUri_ThrowsExceptionForInvalidRelativeUri(string uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetMtlsTokenEndpointAliasUri(new Uri(uri, UriKind.RelativeOrAbsolute)));
        Assert.Equal("uri", exception.ParamName);
        Assert.Contains(SR.FormatID0081("~"), exception.Message);
    }

    [Fact]
    public void SetMtlsTokenEndpointAliasUri_AddsUri()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetMtlsTokenEndpointAliasUri("http://localhost/endpoint-path");

        var options = GetOptions(services);

        // Assert
        Assert.Equal(new Uri("http://localhost/endpoint-path"), options.MtlsTokenEndpointAliasUri);
    }

    [Theory]
    [InlineData("~/path")]
    public void SetMtlsUserInfoEndpointAliasUri_ThrowsExceptionForInvalidRelativeUri(string uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetMtlsUserInfoEndpointAliasUri(new Uri(uri, UriKind.RelativeOrAbsolute)));
        Assert.Equal("uri", exception.ParamName);
        Assert.Contains(SR.FormatID0081("~"), exception.Message);
    }

    [Fact]
    public void SetMtlsUserInfoEndpointAliasUri_AddsUri()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetMtlsUserInfoEndpointAliasUri("http://localhost/endpoint-path");

        var options = GetOptions(services);

        // Assert
        Assert.Equal(new Uri("http://localhost/endpoint-path"), options.MtlsUserInfoEndpointAliasUri);
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
    public void SetIssuedTokenLifetime_DefaultIssuedTokenLifetimeIsReplaced()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetIssuedTokenLifetime(TimeSpan.FromMinutes(42));

        var options = GetOptions(services);

        // Assert
        Assert.Equal(TimeSpan.FromMinutes(42), options.IssuedTokenLifetime);
    }

    [Fact]
    public void SetIssuedTokenLifetime_IssuedTokenLifetimeCanBeSetToNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetIssuedTokenLifetime(null);

        var options = GetOptions(services);

        // Assert
        Assert.Null(options.IssuedTokenLifetime);
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
        var exception = Assert.ThrowsAny<ArgumentException>(() => builder.SetIssuer(uri!));

        Assert.Equal("uri", exception.ParamName);
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
    public void RegisterAudiences_AudiencesAreAdded()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.RegisterAudiences("custom_audience_1", "custom_audience_2");

        var options = GetOptions(services);

        // Assert
        Assert.Contains("custom_audience_1", options.Audiences);
        Assert.Contains("custom_audience_2", options.Audiences);
    }

    [Fact]
    public void RegisterAudiences_ThrowsAnExceptionForNullAudiences()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.RegisterAudiences(audiences: null!));
        Assert.Equal("audiences", exception.ParamName);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void RegisterAudiences_ThrowsAnExceptionForNullOrEmptyAudience(string? audience)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.RegisterAudiences([audience!]));

        Assert.Equal("audiences", exception.ParamName);
        Assert.Contains(SR.FormatID0457("audiences"), exception.Message);
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
    public void RegisterClaims_ThrowsAnExceptionForNullOrEmptyClaim(string? claim)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.RegisterClaims([claim!]));

        Assert.Equal("claims", exception.ParamName);
        Assert.Contains(SR.FormatID0457("claims"), exception.Message);
    }

    [Fact]
    public void RegisterPromptValues_PromptValuesAreAdded()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.RegisterPromptValues("custom_value_1", "custom_value_2");

        var options = GetOptions(services);

        // Assert
        Assert.Contains("custom_value_1", options.PromptValues);
        Assert.Contains("custom_value_2", options.PromptValues);
    }

    [Fact]
    public void RegisterPromptValues_ThrowsAnExceptionForNullPromptValues()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.RegisterPromptValues(values: null!));
        Assert.Equal("values", exception.ParamName);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void RegisterPromptValues_ThrowsAnExceptionForNullOrEmptyValue(string? value)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.RegisterPromptValues([value!]));

        Assert.Equal("values", exception.ParamName);
        Assert.Contains(SR.FormatID0457("values"), exception.Message);
    }

    [Fact]
    public void RegisterResources_ResourcesAreAdded()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.RegisterResources("urn:custom_resource_1", "urn:custom_resource_2");

        var options = GetOptions(services);

        // Assert
        Assert.Contains(new Uri("urn:custom_resource_1", UriKind.Absolute), options.Resources);
        Assert.Contains(new Uri("urn:custom_resource_2", UriKind.Absolute), options.Resources);
    }

    [Fact]
    public void RegisterResources_ThrowsAnExceptionForNullResources()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.RegisterResources((Uri[]) null!));
        Assert.Equal("resources", exception.ParamName);
    }

    [Theory]
    [InlineData("C:\\tmp\\file.xml")]
    [InlineData("http://www.fabrikam.com/path#param=value")]
    [InlineData("urn:fabrikam#param")]
    public void RegisterResources_ThrowsAnExceptionForInvalidResources(string? resource)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.RegisterResources([resource!]));

        Assert.Equal("resources", exception.ParamName);
        Assert.Contains(SR.FormatID0495("resources"), exception.Message);
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
    public void RegisterScopes_ThrowsAnExceptionForNullOrEmptyScope(string? scope)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.RegisterScopes([scope!]));

        Assert.Equal("scopes", exception.ParamName);
        Assert.Contains(SR.FormatID0457("scopes"), exception.Message);
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

    [Fact]
    public void UseClientCertificateBoundAccessTokens_CertificateBoundTokensAreEnabled()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.UseClientCertificateBoundAccessTokens();

        var options = GetOptions(services);

        // Assert
        Assert.True(options.UseClientCertificateBoundAccessTokens);
    }

    [Fact]
    public void UseClientCertificateBoundRefreshTokens_CertificateBoundTokensAreEnabled()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.UseClientCertificateBoundRefreshTokens();

        var options = GetOptions(services);

        // Assert
        Assert.True(options.UseClientCertificateBoundRefreshTokens);
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
        public ValueTask HandleAsync(CustomContext context) => ValueTask.CompletedTask;
    }
}
