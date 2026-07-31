using System.Reflection;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Xunit;
using static OpenIddict.Validation.OpenIddictValidationEvents;

namespace OpenIddict.Validation.Tests;

public class OpenIddictValidationBuilderTests
{
    [Fact]
    public void Constructor_ThrowsAnExceptionForNullServices()
    {
        // Arrange
        var services = (IServiceCollection) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => new OpenIddictValidationBuilder(services));

        Assert.Equal("services", exception.ParamName);
    }

    [Fact]
    public void ValidateOnStart_CanBeInvoked()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        Assert.Same(builder, builder.ValidateOnStart());
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
        builder.AddEventHandler<CustomContext>(x => x.UseSingletonHandler<CustomHandler>());

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
        builder.AddEventHandler<CustomContext>(x => x.UseSingletonHandler(new CustomHandler()));

        // Assert
        Assert.Contains(services, service =>
            service.ServiceType == typeof(CustomHandler) &&
            service.ImplementationInstance?.GetType() == typeof(CustomHandler) &&
            service.Lifetime is ServiceLifetime.Singleton);
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

        OpenIddictValidationHandlerDescriptor descriptor = OpenIddictValidationHandlerDescriptor
            .CreateBuilder<CustomContext>().UseSingletonHandler<CustomHandler>().Build();

        builder.AddEventHandler(descriptor);

        // Act
        builder.RemoveEventHandler(descriptor);
        var options = GetOptions(services);

        // Assert
        Assert.DoesNotContain(services, service => service.ServiceType == descriptor.ServiceDescriptor.ServiceType);
        Assert.DoesNotContain(options.Handlers, handler => handler.ServiceDescriptor.ServiceType == descriptor.ServiceDescriptor.ServiceType);
    }

    [Fact]
    public void Configure_DelegateIsCorrectlyRegistered()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);
        var configuration = new Action<OpenIddictValidationOptions>(_ => { });

        // Act
        builder.Configure(configuration);

        // Assert
        Assert.Contains(services, service => service.ServiceType == typeof(IConfigureOptions<OpenIddictValidationOptions>) &&
            service.ImplementationInstance is ConfigureNamedOptions<OpenIddictValidationOptions> options &&
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
    public void AddEncryptionCredentials_EncryptingCredentialsAreCorrectlyAdded()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        var credentials = new EncryptingCredentials(
            Mock.Of<SecurityKey>(key => key.KeySize == 256),
            SecurityAlgorithms.Aes256KW,
            SecurityAlgorithms.Aes256CbcHmacSha512);

        // Act
        builder.AddEncryptionCredentials(credentials);

        var options = GetOptions(services);

        // Assert
        Assert.Same(credentials, options.EncryptionCredentials[0]);
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

        var key = Mock.Of<SecurityKey>(mock => mock.IsSupportedAlgorithm(SecurityAlgorithms.Aes256KW));

        // Act
        builder.AddEncryptionKey(key);

        var options = GetOptions(services);

        // Assert
        Assert.Same(key, options.EncryptionCredentials[0].Key);
    }

    [Fact]
    public void AddEncryptionKey_UsesRsaOaepWhenSupported()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        var key = Mock.Of<SecurityKey>(mock => mock.IsSupportedAlgorithm(SecurityAlgorithms.RsaOAEP));

        // Act
        builder.AddEncryptionKey(key);

        var options = GetOptions(services);

        // Assert
        Assert.Equal(SecurityAlgorithms.RsaOAEP, options.EncryptionCredentials[0].Alg);
    }

    [Fact]
    public void AddEncryptionKey_ThrowsExceptionWhenNoSupportedAlgorithmIsFound()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        var key = Mock.Of<SecurityKey>(mock =>
            !mock.IsSupportedAlgorithm(SecurityAlgorithms.Aes256KW) &&
            !mock.IsSupportedAlgorithm(SecurityAlgorithms.RsaOAEP));

        // Act and assert
        var exception = Assert.Throws<InvalidOperationException>(() => builder.AddEncryptionKey(key));
        Assert.Equal(SR.GetResourceString(SR.ID0056), exception.Message);
    }

    [Fact]
    public void AddEncryptionKeys_ThrowsExceptionWhenKeysAreNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.AddEncryptionKeys(keys: null!));
        Assert.Equal("keys", exception.ParamName);
    }

    [Fact]
    public void AddEncryptionKeys_KeysAreCorrectlyAdded()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        var keys = new SecurityKey[]
        {
            Mock.Of<SecurityKey>(mock => mock.IsSupportedAlgorithm(SecurityAlgorithms.Aes256KW)),
            Mock.Of<SecurityKey>(mock => mock.IsSupportedAlgorithm(SecurityAlgorithms.RsaOAEP))
        };

        // Act
        builder.AddEncryptionKeys(keys);

        var options = GetOptions(services);

        // Assert
        Assert.Equal(2, options.EncryptionCredentials.Count);
    }

    [Fact]
    public void AddEncryptionCertificate_ThrowsAnExceptionForNullCertificate()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.AddEncryptionCertificate(certificate: null!));
        Assert.Equal("certificate", exception.ParamName);
    }

    [Fact]
    public void AddEncryptionCertificate_ThrowsExceptionWhenPrivateKeyIsMissing()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);
        using var certificate = CreateEncryptionCertificate(includePrivateKey: false);

        // Act and assert
        var exception = Assert.Throws<InvalidOperationException>(() => builder.AddEncryptionCertificate(certificate));
        Assert.Equal(SR.GetResourceString(SR.ID0061), exception.Message);
    }

    [Fact]
    public void AddEncryptionCertificate_ThrowsExceptionWhenKeyUsageIsInvalid()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);
        using var certificate = CreateCertificate(X509KeyUsageFlags.DigitalSignature, includePrivateKey: true);

        // Act and assert
        var exception = Assert.Throws<InvalidOperationException>(() => builder.AddEncryptionCertificate(certificate));
        Assert.Equal(SR.GetResourceString(SR.ID0060), exception.Message);
    }

    [Fact]
    public void AddEncryptionCertificate_Stream_ThrowsExceptionWhenStreamIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.AddEncryptionCertificate(stream: null!, password: "password"));
        Assert.Equal("stream", exception.ParamName);
    }

    [Fact]
    public void AddEncryptionCertificate_Stream_ThrowsExceptionWhenContentTypeIsInvalid()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);
        using var stream = new MemoryStream([0x01, 0x02, 0x03]);

        // Act and assert
        Assert.ThrowsAny<Exception>(() => builder.AddEncryptionCertificate(stream, "password", X509KeyStorageFlags.Exportable));
    }

    [Fact]
    public void AddEncryptionCertificate_Stream_CertificateIsCorrectlyAdded()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);
        using var certificate = CreateEncryptionCertificate(includePrivateKey: true);
        var payload = certificate.Export(X509ContentType.Pfx, "password");
        using var stream = new MemoryStream(payload);

        // Act
        builder.AddEncryptionCertificate(stream, "password", X509KeyStorageFlags.Exportable);

        var options = GetOptions(services);

        // Assert
        Assert.IsType<X509SecurityKey>(options.EncryptionCredentials[0].Key);
    }

    [Fact]
    public void AddEncryptionCertificate_Assembly_ThrowsExceptionWhenAssemblyIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.AddEncryptionCertificate(
            assembly: null!, resource: "resource", password: "password", flags: X509KeyStorageFlags.Exportable));

        Assert.Equal("assembly", exception.ParamName);
    }

    [Fact]
    public void AddEncryptionCertificate_Assembly_ThrowsExceptionWhenResourceIsNullOrEmpty()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);
        var assembly = typeof(OpenIddictValidationBuilderTests).GetTypeInfo().Assembly;

        // Act and assert
        var nullException = Assert.ThrowsAny<ArgumentException>(() => builder.AddEncryptionCertificate(
            assembly, resource: null!, password: "password", flags: X509KeyStorageFlags.Exportable));
        var emptyException = Assert.ThrowsAny<ArgumentException>(() => builder.AddEncryptionCertificate(
            assembly, resource: string.Empty, password: "password", flags: X509KeyStorageFlags.Exportable));

        Assert.Equal("resource", nullException.ParamName);
        Assert.Equal("resource", emptyException.ParamName);
    }

    [Fact]
    public void AddEncryptionCertificate_Assembly_ThrowsExceptionWhenResourceCannotBeFound()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);
        var assembly = typeof(OpenIddictValidationBuilderTests).GetTypeInfo().Assembly;

        // Act and assert
        var exception = Assert.Throws<InvalidOperationException>(() => builder.AddEncryptionCertificate(
            assembly, resource: "missing.pfx", password: "password", flags: X509KeyStorageFlags.Exportable));

        Assert.Equal(SR.GetResourceString(SR.ID0064), exception.Message);
    }

    [SkippableFact, UnsupportedOSPlatform("linux")]
    public void AddEncryptionCertificate_ThrowsExceptionWhenCertificateCannotBeFoundInStores()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<InvalidOperationException>(() => builder.AddEncryptionCertificate(Guid.NewGuid().ToString("N")));
        Assert.Equal(SR.GetResourceString(SR.ID0066), exception.Message);
    }

    [Fact]
    public void AddEncryptionCertificates_ThrowsExceptionWhenCertificatesAreNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.AddEncryptionCertificates(certificates: null!));
        Assert.Equal("certificates", exception.ParamName);
    }

    [Fact]
    public void AddSigningCredentials_ThrowsExceptionWhenCredentialsAreNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.AddSigningCredentials(credentials: null!));
        Assert.Equal("credentials", exception.ParamName);
    }

    [Fact]
    public void AddSigningCredentials_SigningCredentialsAreCorrectlyAdded()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);
        var credentials = new SigningCredentials(Mock.Of<SecurityKey>(), SecurityAlgorithms.HmacSha256);

        // Act
        builder.AddSigningCredentials(credentials);

        var options = GetOptions(services);

        // Assert
        Assert.Same(credentials, options.SigningCredentials[0]);
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
    [InlineData(SecurityAlgorithms.EcdsaSha256)]
    [InlineData(SecurityAlgorithms.EcdsaSha384)]
    [InlineData(SecurityAlgorithms.EcdsaSha512)]
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
    public void AddSigningKey_PrefersRsaOverEcdsaWhenBothAlgorithmsAreSupported()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        var key = Mock.Of<SecurityKey>(mock =>
            mock.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256) &&
            mock.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha256));

        // Act
        builder.AddSigningKey(key);

        var options = GetOptions(services);

        // Assert
        Assert.Equal(SecurityAlgorithms.RsaSha256, options.SigningCredentials[0].Algorithm);
    }

    [Fact]
    public void AddSigningKey_ThrowsExceptionWhenNoSupportedAlgorithmIsFound()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);
        var key = Mock.Of<SecurityKey>(mock =>
            !mock.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256) &&
            !mock.IsSupportedAlgorithm(SecurityAlgorithms.HmacSha256) &&
            !mock.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha256) &&
            !mock.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha384) &&
            !mock.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha512));

        // Act and assert
        var exception = Assert.Throws<InvalidOperationException>(() => builder.AddSigningKey(key));
        Assert.Equal(SR.GetResourceString(SR.ID0068), exception.Message);
    }

    [Fact]
    public void AddSigningKeys_ThrowsExceptionWhenKeysAreNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.AddSigningKeys(keys: null!));
        Assert.Equal("keys", exception.ParamName);
    }

    [Fact]
    public void AddSigningKeys_KeysAreCorrectlyAdded()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        var keys = new SecurityKey[]
        {
            Mock.Of<SecurityKey>(mock => mock.IsSupportedAlgorithm(SecurityAlgorithms.HmacSha256)),
            Mock.Of<SecurityKey>(mock => mock.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256))
        };

        // Act
        builder.AddSigningKeys(keys);

        var options = GetOptions(services);

        // Assert
        Assert.Equal(2, options.SigningCredentials.Count);
    }

    [Fact]
    public void AddSigningCertificate_ThrowsAnExceptionForNullCertificate()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.AddSigningCertificate(certificate: null!));
        Assert.Equal("certificate", exception.ParamName);
    }

    [Fact]
    public void AddSigningCertificate_ThrowsExceptionWhenPrivateKeyIsMissing()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);
        using var certificate = CreateSigningCertificate(includePrivateKey: false);

        // Act and assert
        var exception = Assert.Throws<InvalidOperationException>(() => builder.AddSigningCertificate(certificate));
        Assert.Equal(SR.GetResourceString(SR.ID0061), exception.Message);
    }

    [Fact]
    public void AddSigningCertificate_ThrowsExceptionWhenKeyUsageIsInvalid()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);
        using var certificate = CreateCertificate(X509KeyUsageFlags.KeyEncipherment, includePrivateKey: true);

        // Act and assert
        var exception = Assert.Throws<InvalidOperationException>(() => builder.AddSigningCertificate(certificate));
        Assert.Equal(SR.GetResourceString(SR.ID0070), exception.Message);
    }

    [Fact]
    public void AddSigningCertificate_Stream_ThrowsExceptionWhenStreamIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.AddSigningCertificate(stream: null!, password: "password"));
        Assert.Equal("stream", exception.ParamName);
    }

    [Fact]
    public void AddSigningCertificate_Stream_ThrowsExceptionWhenContentTypeIsInvalid()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);
        using var stream = new MemoryStream([0x01, 0x02, 0x03]);

        // Act and assert
        Assert.ThrowsAny<Exception>(() => builder.AddSigningCertificate(stream, "password", X509KeyStorageFlags.Exportable));
    }

    [Fact]
    public void AddSigningCertificate_Stream_CertificateIsCorrectlyAdded()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);
        using var certificate = CreateSigningCertificate(includePrivateKey: true);
        var payload = certificate.Export(X509ContentType.Pfx, "password");
        using var stream = new MemoryStream(payload);

        // Act
        builder.AddSigningCertificate(stream, "password", X509KeyStorageFlags.Exportable);

        var options = GetOptions(services);

        // Assert
        Assert.IsType<X509SecurityKey>(options.SigningCredentials[0].Key);
    }

    [Fact]
    public void AddSigningCertificate_Assembly_ThrowsExceptionWhenAssemblyIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.AddSigningCertificate(
            assembly: null!, resource: "resource", password: "password", flags: X509KeyStorageFlags.Exportable));

        Assert.Equal("assembly", exception.ParamName);
    }

    [Fact]
    public void AddSigningCertificate_Assembly_ThrowsExceptionWhenResourceIsNullOrEmpty()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);
        var assembly = typeof(OpenIddictValidationBuilderTests).GetTypeInfo().Assembly;

        // Act and assert
        var nullException = Assert.ThrowsAny<ArgumentException>(() => builder.AddSigningCertificate(
            assembly, resource: null!, password: "password", flags: X509KeyStorageFlags.Exportable));
        var emptyException = Assert.ThrowsAny<ArgumentException>(() => builder.AddSigningCertificate(
            assembly, resource: string.Empty, password: "password", flags: X509KeyStorageFlags.Exportable));

        Assert.Equal("resource", nullException.ParamName);
        Assert.Equal("resource", emptyException.ParamName);
    }

    [Fact]
    public void AddSigningCertificate_Assembly_ThrowsExceptionWhenResourceCannotBeFound()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);
        var assembly = typeof(OpenIddictValidationBuilderTests).GetTypeInfo().Assembly;

        // Act and assert
        var exception = Assert.Throws<InvalidOperationException>(() => builder.AddSigningCertificate(
            assembly, resource: "missing.pfx", password: "password", flags: X509KeyStorageFlags.Exportable));

        Assert.Equal(SR.GetResourceString(SR.ID0064), exception.Message);
    }

    [SkippableFact, UnsupportedOSPlatform("linux")]
    public void AddSigningCertificate_ThrowsExceptionWhenCertificateCannotBeFoundInStores()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<InvalidOperationException>(() => builder.AddSigningCertificate(Guid.NewGuid().ToString("N")));
        Assert.Equal(SR.GetResourceString(SR.ID0066), exception.Message);
    }

    [Fact]
    public void AddSigningCertificates_ThrowsExceptionWhenCertificatesAreNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.AddSigningCertificates(certificates: null!));
        Assert.Equal("certificates", exception.ParamName);
    }

    [Fact]
    public void AddAudiences_ThrowsAnExceptionForNullAudiences()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.AddAudiences(audiences: null!));
        Assert.Equal("audiences", exception.ParamName);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void AddAudiences_ThrowsAnExceptionForNullOrEmptyAudience(string? audience)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.AddAudiences(audience!));
        Assert.Equal("audiences", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0123), exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AddAudiences_AudiencesAreAdded()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.AddAudiences("audience_1", "audience_2");

        var options = GetOptions(services);

        // Assert
        Assert.Contains("audience_1", options.Audiences);
        Assert.Contains("audience_2", options.Audiences);
    }

    [Fact]
    public void EnableAuthorizationEntryValidation_IsEnabled()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.EnableAuthorizationEntryValidation();

        var options = GetOptions(services);

        // Assert
        Assert.True(options.EnableAuthorizationEntryValidation);
    }

    [Fact]
    public void EnableTokenEntryValidation_IsEnabled()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.EnableTokenEntryValidation();

        var options = GetOptions(services);

        // Assert
        Assert.True(options.EnableTokenEntryValidation);
    }

    [Fact]
    public void SetClientAssertionLifetime_ClientAssertionLifetimeCanBeSetToNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetClientAssertionLifetime(null);

        var options = GetOptions(services);

        // Assert
        Assert.Null(options.ClientAssertionLifetime);
    }

    [Fact]
    public void SetClientAssertionLifetime_DefaultClientAssertionLifetimeIsReplaced()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetClientAssertionLifetime(TimeSpan.FromMinutes(42));

        var options = GetOptions(services);

        // Assert
        Assert.Equal(TimeSpan.FromMinutes(42), options.ClientAssertionLifetime);
    }

    [Fact]
    public void SetConfiguration_ThrowsAnExceptionForNullConfiguration()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetConfiguration(configuration: null!));
        Assert.Equal("configuration", exception.ParamName);
    }

    [Fact]
    public void SetConfiguration_ConfigurationIsSet()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);
        var configuration = new OpenIddictConfiguration
        {
            Issuer = new Uri("https://www.fabrikam.com/")
        };

        // Act
        builder.SetConfiguration(configuration);

        var options = GetOptions(services);

        // Assert
        Assert.Same(configuration, options.Configuration);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void SetClaimsIssuer_ThrowsAnExceptionForNullOrEmptyIssuer(string? issuer)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.ThrowsAny<ArgumentException>(() => builder.SetClaimsIssuer(issuer!));
        Assert.Equal("issuer", exception.ParamName);
    }

    [Fact]
    public void SetClaimsIssuer_IssuerIsSet()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetClaimsIssuer("https://www.fabrikam.com/");

        var options = GetOptions(services);

        // Assert
        Assert.Equal("https://www.fabrikam.com/", options.ClaimsIssuer);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void SetClientId_ThrowsAnExceptionForNullOrEmptyIdentifier(string? identifier)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.ThrowsAny<ArgumentException>(() => builder.SetClientId(identifier!));
        Assert.Equal("identifier", exception.ParamName);
    }

    [Fact]
    public void SetClientId_ClientIdIsSet()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetClientId("client_id");

        var options = GetOptions(services);

        // Assert
        Assert.Equal("client_id", options.ClientId);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void SetClientSecret_ThrowsAnExceptionForNullOrEmptySecret(string? secret)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.ThrowsAny<ArgumentException>(() => builder.SetClientSecret(secret!));
        Assert.Equal("secret", exception.ParamName);
    }

    [Fact]
    public void SetClientSecret_ClientSecretIsSet()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetClientSecret("client_secret");

        var options = GetOptions(services);

        // Assert
        Assert.Equal("client_secret", options.ClientSecret);
    }

    [Fact]
    public void SetIssuer_Uri_ThrowsAnExceptionForNullIssuer()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetIssuer((Uri) null!));
        Assert.Equal("uri", exception.ParamName);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void SetIssuer_String_ThrowsAnExceptionForNullOrEmptyIssuer(string? uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.ThrowsAny<ArgumentException>(() => builder.SetIssuer(uri!));
        Assert.Equal("uri", exception.ParamName);
    }

    [Theory]
    [InlineData(@"C:\")]
    [InlineData("relative/path")]
    public void SetIssuer_String_ThrowsAnExceptionForInvalidIssuer(string uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetIssuer(uri));
        Assert.Equal("uri", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0023), exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void SetIssuer_Uri_IssuerIsSet()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);
        var uri = new Uri("https://www.fabrikam.com/");

        // Act
        builder.SetIssuer(uri);

        var options = GetOptions(services);

        // Assert
        Assert.Equal(uri, options.Issuer);
    }

    [Fact]
    public void SetIssuer_String_IssuerIsSet()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetIssuer("https://www.fabrikam.com/");

        var options = GetOptions(services);

        // Assert
        Assert.Equal(new Uri("https://www.fabrikam.com/"), options.Issuer);
    }

    [Fact]
    public void UseIntrospection_ValidationTypeIsSet()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.UseIntrospection();

        var options = GetOptions(services);

        // Assert
        Assert.Equal(OpenIddictValidationType.Introspection, options.ValidationType);
    }

    private static X509Certificate2 CreateCertificate(X509KeyUsageFlags usages, bool includePrivateKey)
    {
        using var algorithm = RSA.Create(keySizeInBits: 2048);

        var request = new CertificateRequest(
            subjectName: "CN=OpenIddict Validation Tests",
            key: algorithm,
            hashAlgorithm: HashAlgorithmName.SHA256,
            padding: RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(new X509KeyUsageExtension(usages, critical: true));

        var certificate = request.CreateSelfSigned(
            notBefore: DateTimeOffset.UtcNow.AddDays(-1),
            notAfter: DateTimeOffset.UtcNow.AddDays(1));

        if (includePrivateKey)
        {
            return certificate;
        }

        return X509CertificateLoader.LoadCertificate(certificate.Export(X509ContentType.Cert));
    }

    private static X509Certificate2 CreateEncryptionCertificate(bool includePrivateKey)
        => CreateCertificate(X509KeyUsageFlags.KeyEncipherment, includePrivateKey);

    private static X509Certificate2 CreateSigningCertificate(bool includePrivateKey)
        => CreateCertificate(X509KeyUsageFlags.DigitalSignature, includePrivateKey);

    private static IServiceCollection CreateServices()
        => new ServiceCollection().AddOptions();

    private static OpenIddictValidationBuilder CreateBuilder(IServiceCollection services)
        => new(services);

    private static OpenIddictValidationOptions GetOptions(IServiceCollection services)
    {
        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<OpenIddictValidationOptions>>();
        return options.Value;
    }

    private sealed class CustomContext : BaseContext
    {
        public CustomContext(OpenIddictValidationTransaction transaction) : base(transaction) { }
    }

    private sealed class CustomHandler : IOpenIddictValidationHandler<CustomContext>
    {
        public ValueTask HandleAsync(CustomContext context) => ValueTask.CompletedTask;
    }
}
