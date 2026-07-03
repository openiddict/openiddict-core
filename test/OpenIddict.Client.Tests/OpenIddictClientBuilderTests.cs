using System.Reflection;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Xunit;
using static OpenIddict.Client.OpenIddictClientEvents;

namespace OpenIddict.Client.Tests;

public class OpenIddictClientBuilderTests
{
    [Fact]
    public void Constructor_ThrowsAnExceptionForNullServices()
    {
        // Arrange
        var services = (IServiceCollection) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => new OpenIddictClientBuilder(services));

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
        builder.AddEventHandler<CustomContext>(options => options.UseSingletonHandler<CustomHandler>());

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
        builder.AddEventHandler<CustomContext>(options => options.UseSingletonHandler(new CustomHandler()));

        // Assert
        Assert.Contains(services, service =>
            service.ServiceType == typeof(CustomHandler) &&
            service.ImplementationInstance?.GetType() == typeof(CustomHandler) &&
            service.Lifetime == ServiceLifetime.Singleton);
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

        OpenIddictClientHandlerDescriptor descriptor = OpenIddictClientHandlerDescriptor
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
        var configuration = new Action<OpenIddictClientOptions>(_ => { });

        // Act
        builder.Configure(configuration);

        // Assert
        Assert.Contains(services, service => service.ServiceType == typeof(IConfigureOptions<OpenIddictClientOptions>) &&
            service.ImplementationInstance is ConfigureNamedOptions<OpenIddictClientOptions> options &&
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

        var key = Mock.Of<SecurityKey>(mock => mock.KeySize == 128 && mock.IsSupportedAlgorithm(SecurityAlgorithms.Aes256KW));

        // Act and assert
        var exception = Assert.Throws<InvalidOperationException>(() => builder.AddEncryptionKey(key));
        Assert.Equal(SR.FormatID0283(256, 128), exception.Message);
    }

    [Fact]
    public void AddEncryptionKey_ThrowsExceptionWhenSymmetricKeyIsTooLong()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        var key = Mock.Of<SecurityKey>(mock => mock.KeySize == 384 && mock.IsSupportedAlgorithm(SecurityAlgorithms.Aes256KW));

        // Act and assert
        var exception = Assert.Throws<InvalidOperationException>(() => builder.AddEncryptionKey(key));
        Assert.Equal(SR.FormatID0283(256, 384), exception.Message);
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
            Mock.Of<SecurityKey>(mock => mock.KeySize == 256 && mock.IsSupportedAlgorithm(SecurityAlgorithms.Aes256KW)),
            Mock.Of<SecurityKey>(mock => mock.IsSupportedAlgorithm(SecurityAlgorithms.RsaOAEP))
        };

        // Act
        builder.AddEncryptionKeys(keys);

        var options = GetOptions(services);

        // Assert
        Assert.Equal(2, options.EncryptionCredentials.Count);
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

    [Fact]
    public void AddEphemeralEncryptionKey_ThrowsAnExceptionForNullOrEmptyAlgorithm()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var nullException = Assert.ThrowsAny<ArgumentException>(() => builder.AddEphemeralEncryptionKey(algorithm: null!));
        var emptyException = Assert.ThrowsAny<ArgumentException>(() => builder.AddEphemeralEncryptionKey(string.Empty));

        Assert.Equal("algorithm", nullException.ParamName);
        Assert.Equal("algorithm", emptyException.ParamName);
    }

    [Fact]
    public void AddEphemeralEncryptionKey_DefaultAlgorithmIsRsaOaep()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.AddEphemeralEncryptionKey();

        var options = GetOptions(services);

        // Assert
        Assert.Equal(SecurityAlgorithms.RsaOAEP, options.EncryptionCredentials[0].Alg);
    }

    [Theory]
    [InlineData(SecurityAlgorithms.Aes256KW)]
    [InlineData(SecurityAlgorithms.RsaOAEP)]
    [InlineData(SecurityAlgorithms.RsaOaepKeyWrap)]
    public void AddEphemeralEncryptionKey_EncryptionCredentialsUseSpecifiedAlgorithm(string algorithm)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.AddEphemeralEncryptionKey(algorithm);

        var options = GetOptions(services);

        // Assert
        Assert.Equal(algorithm, options.EncryptionCredentials[0].Alg);
    }

    [Fact]
    public void AddEphemeralEncryptionKey_ThrowsExceptionForUnsupportedAlgorithm()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<InvalidOperationException>(() => builder.AddEphemeralEncryptionKey("unsupported"));
        Assert.Equal(SR.GetResourceString(SR.ID0058), exception.Message);
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
        var assembly = typeof(OpenIddictClientBuilderTests).GetTypeInfo().Assembly;

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
        var assembly = typeof(OpenIddictClientBuilderTests).GetTypeInfo().Assembly;

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
    [InlineData(SecurityAlgorithms.MlDsa44)]
    [InlineData(SecurityAlgorithms.MlDsa65)]
    [InlineData(SecurityAlgorithms.MlDsa87)]
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
    public void AddSigningKey_ThrowsExceptionWhenNoSupportedAlgorithmIsFound()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);
        var key = Mock.Of<SecurityKey>(mock =>
            !mock.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha256) &&
            !mock.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha384) &&
            !mock.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha512) &&
            !mock.IsSupportedAlgorithm(SecurityAlgorithms.HmacSha256) &&
            !mock.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256));

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
    public void AddDevelopmentSigningCertificate_ThrowsAnExceptionForNullSubject()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.AddDevelopmentSigningCertificate(subject: null!));
        Assert.Equal("subject", exception.ParamName);
    }

    [Fact]
    public void AddEphemeralSigningKey_ThrowsAnExceptionForNullOrEmptyAlgorithm()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var nullException = Assert.ThrowsAny<ArgumentException>(() => builder.AddEphemeralSigningKey(algorithm: null!));
        var emptyException = Assert.ThrowsAny<ArgumentException>(() => builder.AddEphemeralSigningKey(string.Empty));

        Assert.Equal("algorithm", nullException.ParamName);
        Assert.Equal("algorithm", emptyException.ParamName);
    }

    [Fact]
    public void AddEphemeralSigningKey_DefaultSigningKeyIsCorrectlyAdded()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.AddEphemeralSigningKey();

        var options = GetOptions(services);

        // Assert
        Assert.Single(options.SigningCredentials);
        Assert.Equal(SecurityAlgorithms.RsaSha256, options.SigningCredentials[0].Algorithm);
    }

    [SkippableTheory(typeof(PlatformNotSupportedException))]
    [InlineData(SecurityAlgorithms.RsaSha256)]
    [InlineData(SecurityAlgorithms.RsaSha384)]
    [InlineData(SecurityAlgorithms.RsaSha512)]
    [InlineData(SecurityAlgorithms.EcdsaSha256)]
    [InlineData(SecurityAlgorithms.EcdsaSha384)]
    [InlineData(SecurityAlgorithms.EcdsaSha512)]
    [InlineData(SecurityAlgorithms.MlDsa44)]
    [InlineData(SecurityAlgorithms.MlDsa65)]
    [InlineData(SecurityAlgorithms.MlDsa87)]
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
    public void AddEphemeralSigningKey_ThrowsExceptionForUnsupportedAlgorithm()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<InvalidOperationException>(() => builder.AddEphemeralSigningKey("unsupported"));
        Assert.Equal(SR.GetResourceString(SR.ID0058), exception.Message);
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
        var assembly = typeof(OpenIddictClientBuilderTests).GetTypeInfo().Assembly;

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
        var assembly = typeof(OpenIddictClientBuilderTests).GetTypeInfo().Assembly;

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
    public void AddRegistration_ThrowsAnExceptionForNullRegistration()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.AddRegistration(registration: null!));
        Assert.Equal("registration", exception.ParamName);
    }

    [Fact]
    public void AddRegistration_RegistrationIsCorrectlyAdded()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);
        var registration = new OpenIddictClientRegistration
        {
            Issuer = new Uri("https://fabrikam.com/")
        };

        // Act
        builder.AddRegistration(registration);

        var options = GetOptions(services);

        // Assert
        Assert.Contains(registration, options.Registrations);
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
    public void DisableWebServicesFederationClaimMapping_IsDisabled()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.DisableWebServicesFederationClaimMapping();

        var options = GetOptions(services);

        // Assert
        Assert.True(options.DisableWebServicesFederationClaimMapping);
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
    public void AllowDeviceAuthorizationFlow_DeviceFlowIsAdded()
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
    public void AllowImplicitFlow_ImplicitFlowIsAddedWithoutUnsafeTokenResponseType()
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
        Assert.DoesNotContain(ResponseTypes.Token, options.ResponseTypes);
    }

    [Fact]
    public void AllowNoneFlow_NoneFlowIsAdded()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.AllowNoneFlow();

        var options = GetOptions(services);

        // Assert
        Assert.Contains(ResponseTypes.None, options.ResponseTypes);
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
    public void SetPostLogoutRedirectionEndpointUris_ThrowsExceptionWhenUrisIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetPostLogoutRedirectionEndpointUris(uris: (Uri[]) null!));
        Assert.Equal("uris", exception.ParamName);
    }

    [Fact]
    public void SetPostLogoutRedirectionEndpointUris_Strings_ThrowsExceptionWhenUrisIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetPostLogoutRedirectionEndpointUris(uris: (string[]) null!));
        Assert.Equal("uris", exception.ParamName);
    }

    [Theory]
    [InlineData(@"C:\")]
    public void SetPostLogoutRedirectionEndpointUris_ThrowsExceptionForMalformedUri(string uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetPostLogoutRedirectionEndpointUris(new Uri(uri)));
        Assert.Equal("uris", exception.ParamName);
        Assert.Contains(SR.GetResourceString(SR.ID0072), exception.Message);
    }

    [Theory]
    [InlineData("~/path")]
    public void SetPostLogoutRedirectionEndpointUris_ThrowsExceptionForInvalidRelativeUri(string uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetPostLogoutRedirectionEndpointUris(new Uri(uri, UriKind.RelativeOrAbsolute)));
        Assert.Equal("uris", exception.ParamName);
        Assert.Contains(SR.FormatID0081("~"), exception.Message);
    }

    [Fact]
    public void SetPostLogoutRedirectionEndpointUris_ClearsUris()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetPostLogoutRedirectionEndpointUris(Array.Empty<Uri>());

        var options = GetOptions(services);

        // Assert
        Assert.Empty(options.PostLogoutRedirectionEndpointUris);
    }

    [Fact]
    public void SetPostLogoutRedirectionEndpointUris_AddsUri()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetPostLogoutRedirectionEndpointUris("http://localhost/postlogout");

        var options = GetOptions(services);

        // Assert
        Assert.Contains(new Uri("http://localhost/postlogout"), options.PostLogoutRedirectionEndpointUris);
    }

    [Fact]
    public void SetRedirectionEndpointUris_ThrowsExceptionWhenUrisIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetRedirectionEndpointUris(uris: (Uri[]) null!));
        Assert.Equal("uris", exception.ParamName);
    }

    [Fact]
    public void SetRedirectionEndpointUris_Strings_ThrowsExceptionWhenUrisIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetRedirectionEndpointUris(uris: (string[]) null!));
        Assert.Equal("uris", exception.ParamName);
    }

    [Theory]
    [InlineData(@"C:\")]
    public void SetRedirectionEndpointUris_ThrowsExceptionForMalformedUri(string uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetRedirectionEndpointUris(new Uri(uri)));
        Assert.Equal("uris", exception.ParamName);
        Assert.Contains(SR.GetResourceString(SR.ID0072), exception.Message);
    }

    [Theory]
    [InlineData("~/path")]
    public void SetRedirectionEndpointUris_ThrowsExceptionForInvalidRelativeUri(string uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetRedirectionEndpointUris(new Uri(uri, UriKind.RelativeOrAbsolute)));
        Assert.Equal("uris", exception.ParamName);
        Assert.Contains(SR.FormatID0081("~"), exception.Message);
    }

    [Fact]
    public void SetRedirectionEndpointUris_ClearsUris()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetRedirectionEndpointUris(Array.Empty<Uri>());

        var options = GetOptions(services);

        // Assert
        Assert.Empty(options.RedirectionEndpointUris);
    }

    [Fact]
    public void SetRedirectionEndpointUris_AddsUri()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetRedirectionEndpointUris("http://localhost/callback");

        var options = GetOptions(services);

        // Assert
        Assert.Contains(new Uri("http://localhost/callback"), options.RedirectionEndpointUris);
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
    public void SetStateTokenLifetime_StateTokenLifetimeCanBeSetToNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetStateTokenLifetime(null);

        var options = GetOptions(services);

        // Assert
        Assert.Null(options.StateTokenLifetime);
    }

    [Fact]
    public void SetStateTokenLifetime_DefaultStateTokenLifetimeIsReplaced()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetStateTokenLifetime(TimeSpan.FromMinutes(42));

        var options = GetOptions(services);

        // Assert
        Assert.Equal(TimeSpan.FromMinutes(42), options.StateTokenLifetime);
    }

    [Fact]
    public void SetClientUri_Uri_ThrowsAnExceptionForNullUri()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.SetClientUri(uri: (Uri) null!));
        Assert.Equal("uri", exception.ParamName);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void SetClientUri_String_ThrowsAnExceptionForNullOrEmptyUri(string? uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.ThrowsAny<ArgumentException>(() => builder.SetClientUri(uri!));
        Assert.Equal("uri", exception.ParamName);
    }

    [Theory]
    [InlineData("relative/path")]
    [InlineData(@"C:\")]
    public void SetClientUri_String_ThrowsAnExceptionForInvalidUri(string uri)
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => builder.SetClientUri(uri));
        Assert.Equal("uri", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0144), exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void SetClientUri_Uri_ClientUriIsSet()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);
        var uri = new Uri("https://www.fabrikam.com/client");

        // Act
        builder.SetClientUri(uri);

        var options = GetOptions(services);

        // Assert
        Assert.Equal(uri, options.ClientUri);
    }

    [Fact]
    public void SetClientUri_String_ClientUriIsSet()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetClientUri("https://www.fabrikam.com/client");

        var options = GetOptions(services);

        // Assert
        Assert.Equal(new Uri("https://www.fabrikam.com/client"), options.ClientUri);
    }

    private static X509Certificate2 CreateCertificate(X509KeyUsageFlags usages, bool includePrivateKey)
    {
        using var algorithm = RSA.Create(keySizeInBits: 2048);

        var request = new CertificateRequest(
            subjectName: "CN=OpenIddict Client Tests",
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

    private static OpenIddictClientBuilder CreateBuilder(IServiceCollection services)
        => new(services);

    private static OpenIddictClientOptions GetOptions(IServiceCollection services)
    {
        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<OpenIddictClientOptions>>();
        return options.Value;
    }

    private class CustomContext : BaseContext
    {
        public CustomContext(OpenIddictClientTransaction transaction) : base(transaction) { }
    }

    private class CustomHandler : IOpenIddictClientHandler<CustomContext>
    {
        public ValueTask HandleAsync(CustomContext context) => ValueTask.CompletedTask;
    }
}
