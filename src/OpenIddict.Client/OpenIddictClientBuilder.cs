/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Client;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes the necessary methods required to configure the OpenIddict client services.
/// </summary>
public class OpenIddictClientBuilder
{
    /// <summary>
    /// Initializes a new instance of <see cref="OpenIddictClientBuilder"/>.
    /// </summary>
    /// <param name="services">The services collection.</param>
    public OpenIddictClientBuilder(IServiceCollection services)
        => Services = services ?? throw new ArgumentNullException(nameof(services));

    /// <summary>
    /// Gets the services collection.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public IServiceCollection Services { get; }

    /// <summary>
    /// Registers an event handler using the specified configuration delegate.
    /// </summary>
    /// <typeparam name="TContext">The event context type.</typeparam>
    /// <param name="configuration">The configuration delegate.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictClientBuilder AddEventHandler<TContext>(
        Action<OpenIddictClientHandlerDescriptor.Builder<TContext>> configuration)
        where TContext : OpenIddictClientEvents.BaseContext
    {
        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        // Note: handlers registered using this API are assumed to be custom handlers by default.
        var builder = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
            .SetType(OpenIddictClientHandlerType.Custom);

        configuration(builder);

        return AddEventHandler(builder.Build());
    }

    /// <summary>
    /// Registers an event handler using the specified descriptor.
    /// </summary>
    /// <param name="descriptor">The handler descriptor.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictClientBuilder AddEventHandler(OpenIddictClientHandlerDescriptor descriptor)
    {
        if (descriptor is null)
        {
            throw new ArgumentNullException(nameof(descriptor));
        }

        // Register the handler in the services collection.
        Services.Add(descriptor.ServiceDescriptor);

        return Configure(options => options.Handlers.Add(descriptor));
    }

    /// <summary>
    /// Removes the event handler that matches the specified descriptor.
    /// </summary>
    /// <param name="descriptor">The descriptor corresponding to the handler to remove.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictClientBuilder RemoveEventHandler(OpenIddictClientHandlerDescriptor descriptor)
    {
        if (descriptor is null)
        {
            throw new ArgumentNullException(nameof(descriptor));
        }

        Services.RemoveAll(descriptor.ServiceDescriptor.ServiceType);

        Services.PostConfigure<OpenIddictClientOptions>(options =>
        {
            for (var index = options.Handlers.Count - 1; index >= 0; index--)
            {
                if (options.Handlers[index].ServiceDescriptor.ServiceType == descriptor.ServiceDescriptor.ServiceType)
                {
                    options.Handlers.RemoveAt(index);
                }
            }
        });

        return this;
    }

    /// <summary>
    /// Amends the default OpenIddict client configuration.
    /// </summary>
    /// <param name="configuration">The delegate used to configure the OpenIddict options.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    public OpenIddictClientBuilder Configure(Action<OpenIddictClientOptions> configuration)
    {
        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        Services.Configure(configuration);

        return this;
    }

    /// <summary>
    /// Registers encryption credentials.
    /// </summary>
    /// <param name="credentials">The encrypting credentials.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    public OpenIddictClientBuilder AddEncryptionCredentials(EncryptingCredentials credentials)
    {
        if (credentials is null)
        {
            throw new ArgumentNullException(nameof(credentials));
        }

        return Configure(options => options.EncryptionCredentials.Add(credentials));
    }

    /// <summary>
    /// Registers an encryption key.
    /// </summary>
    /// <param name="key">The security key.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    public OpenIddictClientBuilder AddEncryptionKey(SecurityKey key)
    {
        if (key is null)
        {
            throw new ArgumentNullException(nameof(key));
        }

        // If the encryption key is an asymmetric security key, ensure it has a private key.
        if (key is AsymmetricSecurityKey asymmetricSecurityKey &&
            asymmetricSecurityKey.PrivateKeyStatus is PrivateKeyStatus.DoesNotExist)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0055));
        }

        if (key.IsSupportedAlgorithm(SecurityAlgorithms.Aes256KW))
        {
            if (key.KeySize != 256)
            {
                throw new InvalidOperationException(SR.FormatID0283(256, key.KeySize));
            }

            return AddEncryptionCredentials(new EncryptingCredentials(key,
                SecurityAlgorithms.Aes256KW, SecurityAlgorithms.Aes256CbcHmacSha512));
        }

        if (key.IsSupportedAlgorithm(SecurityAlgorithms.RsaOAEP))
        {
            return AddEncryptionCredentials(new EncryptingCredentials(key,
                SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes256CbcHmacSha512));
        }

        throw new InvalidOperationException(SR.GetResourceString(SR.ID0056));
    }

    /// <summary>
    /// Registers (and generates if necessary) a user-specific development encryption certificate.
    /// </summary>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    public OpenIddictClientBuilder AddDevelopmentEncryptionCertificate()
        => AddDevelopmentEncryptionCertificate(new X500DistinguishedName("CN=OpenIddict Client Encryption Certificate"));

    /// <summary>
    /// Registers (and generates if necessary) a user-specific development encryption certificate.
    /// </summary>
    /// <param name="subject">The subject name associated with the certificate.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The X.509 certificate is attached to the client options.")]
    public OpenIddictClientBuilder AddDevelopmentEncryptionCertificate(X500DistinguishedName subject)
    {
        if (subject is null)
        {
            throw new ArgumentNullException(nameof(subject));
        }

        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);

        // Try to retrieve the existing development certificates from the specified store.
        // If no valid existing certificate was found, create a new encryption certificate.
        var certificates = store.Certificates.Find(X509FindType.FindBySubjectDistinguishedName, subject.Name, validOnly: false)
            .OfType<X509Certificate2>()
            .ToList();

        if (!certificates.Any(certificate => certificate.NotBefore < DateTime.Now && certificate.NotAfter > DateTime.Now))
        {
#if SUPPORTS_CERTIFICATE_GENERATION
            using var algorithm = RSA.Create(keySizeInBits: 2048);

            var request = new CertificateRequest(subject, algorithm, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyEncipherment, critical: true));

            var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(2));

            // Note: setting the friendly name is not supported on Unix machines (including Linux and macOS).
            // To ensure an exception is not thrown by the property setter, an OS runtime check is used here.
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                certificate.FriendlyName = "OpenIddict Client Development Encryption Certificate";
            }

            // Note: CertificateRequest.CreateSelfSigned() doesn't mark the key set associated with the certificate
            // as "persisted", which eventually prevents X509Store.Add() from correctly storing the private key.
            // To work around this issue, the certificate payload is manually exported and imported back
            // into a new X509Certificate2 instance specifying the X509KeyStorageFlags.PersistKeySet flag.
            var data = certificate.Export(X509ContentType.Pfx, string.Empty);

            try
            {
                var flags = X509KeyStorageFlags.PersistKeySet;

                // Note: macOS requires marking the certificate private key as exportable.
                // If this flag is not set, a CryptographicException is thrown at runtime.
                if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    flags |= X509KeyStorageFlags.Exportable;
                }

                certificates.Insert(0, certificate = new X509Certificate2(data, string.Empty, flags));
            }

            finally
            {
                Array.Clear(data, 0, data.Length);
            }

            store.Add(certificate);
#else
            throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0264));
#endif
        }

        return Configure(options => options.EncryptionCredentials.AddRange(
            from certificate in certificates
            let key = new X509SecurityKey(certificate)
            select new EncryptingCredentials(key, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes256CbcHmacSha512)));
    }

    /// <summary>
    /// Registers a new ephemeral encryption key. Ephemeral encryption keys are automatically
    /// discarded when the application shuts down and payloads encrypted using this key are
    /// automatically invalidated. This method should only be used during development.
    /// On production, using a X.509 certificate stored in the machine store is recommended.
    /// </summary>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    public OpenIddictClientBuilder AddEphemeralEncryptionKey()
        => AddEphemeralEncryptionKey(SecurityAlgorithms.RsaOAEP);

    /// <summary>
    /// Registers a new ephemeral encryption key. Ephemeral encryption keys are automatically
    /// discarded when the application shuts down and payloads encrypted using this key are
    /// automatically invalidated. This method should only be used during development.
    /// On production, using a X.509 certificate stored in the machine store is recommended.
    /// </summary>
    /// <param name="algorithm">The algorithm associated with the encryption key.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    public OpenIddictClientBuilder AddEphemeralEncryptionKey(string algorithm)
    {
        if (string.IsNullOrEmpty(algorithm))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0057), nameof(algorithm));
        }

        return algorithm switch
        {
            SecurityAlgorithms.Aes256KW
                => AddEncryptionCredentials(new EncryptingCredentials(CreateSymmetricSecurityKey(256),
                    algorithm, SecurityAlgorithms.Aes256CbcHmacSha512)),

            SecurityAlgorithms.RsaOAEP or
            SecurityAlgorithms.RsaOaepKeyWrap
                => AddEncryptionCredentials(new EncryptingCredentials(CreateRsaSecurityKey(2048),
                    algorithm, SecurityAlgorithms.Aes256CbcHmacSha512)),

            _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0058))
        };

        static SymmetricSecurityKey CreateSymmetricSecurityKey(int size)
        {
            var data = new byte[size / 8];

#if SUPPORTS_STATIC_RANDOM_NUMBER_GENERATOR_METHODS
            RandomNumberGenerator.Fill(data);
#else
            using var generator = RandomNumberGenerator.Create();
            generator.GetBytes(data);
#endif

            return new SymmetricSecurityKey(data);
        }

        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
            Justification = "The generated RSA key is attached to the client options.")]
        static RsaSecurityKey CreateRsaSecurityKey(int size)
        {
#if SUPPORTS_DIRECT_KEY_CREATION_WITH_SPECIFIED_SIZE
            return new RsaSecurityKey(RSA.Create(size));
#else
            // Note: a 1024-bit key might be returned by RSA.Create() on .NET Desktop/Mono,
            // where RSACryptoServiceProvider is still the default implementation and
            // where custom implementations can be registered via CryptoConfig.
            // To ensure the key size is always acceptable, replace it if necessary.
            var algorithm = RSA.Create();
            if (algorithm.KeySize < size)
            {
                algorithm.KeySize = size;
            }

            if (algorithm.KeySize < size && algorithm is RSACryptoServiceProvider)
            {
                algorithm.Dispose();
                algorithm = new RSACryptoServiceProvider(size);
            }

            if (algorithm.KeySize < size)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0059));
            }

            return new RsaSecurityKey(algorithm);
#endif
        }
    }

    /// <summary>
    /// Registers an encryption certificate.
    /// </summary>
    /// <param name="certificate">The encryption certificate.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    public OpenIddictClientBuilder AddEncryptionCertificate(X509Certificate2 certificate)
    {
        if (certificate is null)
        {
            throw new ArgumentNullException(nameof(certificate));
        }

        // If the certificate is a X.509v3 certificate that specifies at least one
        // key usage, ensure that the certificate key can be used for key encryption.
        if (certificate.Version >= 3)
        {
            var extensions = certificate.Extensions.OfType<X509KeyUsageExtension>().ToList();
            if (extensions.Count is not 0 && !extensions.Any(extension => extension.KeyUsages.HasFlag(X509KeyUsageFlags.KeyEncipherment)))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0060));
            }
        }

        if (!certificate.HasPrivateKey)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0061));
        }

        return AddEncryptionKey(new X509SecurityKey(certificate));
    }

    /// <summary>
    /// Registers an encryption certificate retrieved from an embedded resource.
    /// </summary>
    /// <param name="assembly">The assembly containing the certificate.</param>
    /// <param name="resource">The name of the embedded resource.</param>
    /// <param name="password">The password used to open the certificate.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    public OpenIddictClientBuilder AddEncryptionCertificate(Assembly assembly, string resource, string? password)
#if SUPPORTS_EPHEMERAL_KEY_SETS
        // Note: ephemeral key sets are currently not supported on macOS.
        => AddEncryptionCertificate(assembly, resource, password, RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ?
            X509KeyStorageFlags.MachineKeySet :
            X509KeyStorageFlags.EphemeralKeySet);
#else
        => AddEncryptionCertificate(assembly, resource, password, X509KeyStorageFlags.MachineKeySet);
#endif

    /// <summary>
    /// Registers an encryption certificate retrieved from an embedded resource.
    /// </summary>
    /// <param name="assembly">The assembly containing the certificate.</param>
    /// <param name="resource">The name of the embedded resource.</param>
    /// <param name="password">The password used to open the certificate.</param>
    /// <param name="flags">An enumeration of flags indicating how and where to store the private key of the certificate.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    public OpenIddictClientBuilder AddEncryptionCertificate(
        Assembly assembly, string resource,
        string? password, X509KeyStorageFlags flags)
    {
        if (assembly is null)
        {
            throw new ArgumentNullException(nameof(assembly));
        }

        if (string.IsNullOrEmpty(resource))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0062), nameof(resource));
        }

        using var stream = assembly.GetManifestResourceStream(resource) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0064));

        return AddEncryptionCertificate(stream, password, flags);
    }

    /// <summary>
    /// Registers an encryption certificate extracted from a stream.
    /// </summary>
    /// <param name="stream">The stream containing the certificate.</param>
    /// <param name="password">The password used to open the certificate.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    public OpenIddictClientBuilder AddEncryptionCertificate(Stream stream, string? password)
#if SUPPORTS_EPHEMERAL_KEY_SETS
        // Note: ephemeral key sets are currently not supported on macOS.
        => AddEncryptionCertificate(stream, password, RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ?
            X509KeyStorageFlags.MachineKeySet :
            X509KeyStorageFlags.EphemeralKeySet);
#else
        => AddEncryptionCertificate(stream, password, X509KeyStorageFlags.MachineKeySet);
#endif

    /// <summary>
    /// Registers an encryption certificate extracted from a stream.
    /// </summary>
    /// <param name="stream">The stream containing the certificate.</param>
    /// <param name="password">The password used to open the certificate.</param>
    /// <param name="flags">
    /// An enumeration of flags indicating how and where
    /// to store the private key of the certificate.
    /// </param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The X.509 certificate is attached to the client options.")]
    public OpenIddictClientBuilder AddEncryptionCertificate(Stream stream, string? password, X509KeyStorageFlags flags)
    {
        if (stream is null)
        {
            throw new ArgumentNullException(nameof(stream));
        }

        using var buffer = new MemoryStream();
        stream.CopyTo(buffer);

        return AddEncryptionCertificate(new X509Certificate2(buffer.ToArray(), password, flags));
    }

    /// <summary>
    /// Registers an encryption certificate retrieved from the X.509 user or machine store.
    /// </summary>
    /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X.509 store.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    public OpenIddictClientBuilder AddEncryptionCertificate(string thumbprint)
    {
        if (string.IsNullOrEmpty(thumbprint))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0065), nameof(thumbprint));
        }

        return AddEncryptionCertificate(
            GetCertificate(StoreLocation.CurrentUser, thumbprint)  ??
            GetCertificate(StoreLocation.LocalMachine, thumbprint) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0066)));

        static X509Certificate2? GetCertificate(StoreLocation location, string thumbprint)
        {
            using var store = new X509Store(StoreName.My, location);
            store.Open(OpenFlags.ReadOnly);

            return store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false)
                .OfType<X509Certificate2>()
                .SingleOrDefault();
        }
    }

    /// <summary>
    /// Registers an encryption certificate retrieved from the specified X.509 store.
    /// </summary>
    /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X.509 store.</param>
    /// <param name="name">The name of the X.509 store.</param>
    /// <param name="location">The location of the X.509 store.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    public OpenIddictClientBuilder AddEncryptionCertificate(string thumbprint, StoreName name, StoreLocation location)
    {
        if (string.IsNullOrEmpty(thumbprint))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0065), nameof(thumbprint));
        }

        using var store = new X509Store(name, location);
        store.Open(OpenFlags.ReadOnly);

        return AddEncryptionCertificate(
            store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false)
                .OfType<X509Certificate2>()
                .SingleOrDefault() ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0066)));
    }

    /// <summary>
    /// Registers signing credentials.
    /// </summary>
    /// <param name="credentials">The signing credentials.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    public OpenIddictClientBuilder AddSigningCredentials(SigningCredentials credentials)
    {
        if (credentials is null)
        {
            throw new ArgumentNullException(nameof(credentials));
        }

        return Configure(options => options.SigningCredentials.Add(credentials));
    }

    /// <summary>
    /// Registers a signing key.
    /// </summary>
    /// <param name="key">The security key.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    public OpenIddictClientBuilder AddSigningKey(SecurityKey key)
    {
        if (key is null)
        {
            throw new ArgumentNullException(nameof(key));
        }

        // If the signing key is an asymmetric security key, ensure it has a private key.
        if (key is AsymmetricSecurityKey asymmetricSecurityKey &&
            asymmetricSecurityKey.PrivateKeyStatus is PrivateKeyStatus.DoesNotExist)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0067));
        }

        if (key.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256))
        {
            return AddSigningCredentials(new SigningCredentials(key, SecurityAlgorithms.RsaSha256));
        }

        if (key.IsSupportedAlgorithm(SecurityAlgorithms.HmacSha256))
        {
            return AddSigningCredentials(new SigningCredentials(key, SecurityAlgorithms.HmacSha256));
        }

#if SUPPORTS_ECDSA
        // Note: ECDSA algorithms are bound to specific curves and must be treated separately.
        if (key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha256))
        {
            return AddSigningCredentials(new SigningCredentials(key, SecurityAlgorithms.EcdsaSha256));
        }

        if (key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha384))
        {
            return AddSigningCredentials(new SigningCredentials(key, SecurityAlgorithms.EcdsaSha384));
        }

        if (key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha512))
        {
            return AddSigningCredentials(new SigningCredentials(key, SecurityAlgorithms.EcdsaSha512));
        }
#else
        if (key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha256) ||
            key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha384) ||
            key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha512))
        {
            throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0069));
        }
#endif

        throw new InvalidOperationException(SR.GetResourceString(SR.ID0068));
    }

    /// <summary>
    /// Registers (and generates if necessary) a user-specific development signing certificate.
    /// </summary>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    public OpenIddictClientBuilder AddDevelopmentSigningCertificate()
        => AddDevelopmentSigningCertificate(new X500DistinguishedName("CN=OpenIddict Client Signing Certificate"));

    /// <summary>
    /// Registers (and generates if necessary) a user-specific development signing certificate.
    /// </summary>
    /// <param name="subject">The subject name associated with the certificate.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The X.509 certificate is attached to the client options.")]
    public OpenIddictClientBuilder AddDevelopmentSigningCertificate(X500DistinguishedName subject)
    {
        if (subject is null)
        {
            throw new ArgumentNullException(nameof(subject));
        }

        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);

        // Try to retrieve the existing development certificates from the specified store.
        // If no valid existing certificate was found, create a new signing certificate.
        var certificates = store.Certificates.Find(X509FindType.FindBySubjectDistinguishedName, subject.Name, validOnly: false)
            .OfType<X509Certificate2>()
            .ToList();

        if (!certificates.Any(certificate => certificate.NotBefore < DateTime.Now && certificate.NotAfter > DateTime.Now))
        {
#if SUPPORTS_CERTIFICATE_GENERATION
            using var algorithm = RSA.Create(keySizeInBits: 2048);

            var request = new CertificateRequest(subject, algorithm, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));

            var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(2));

            // Note: setting the friendly name is not supported on Unix machines (including Linux and macOS).
            // To ensure an exception is not thrown by the property setter, an OS runtime check is used here.
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                certificate.FriendlyName = "OpenIddict Client Development Signing Certificate";
            }

            // Note: CertificateRequest.CreateSelfSigned() doesn't mark the key set associated with the certificate
            // as "persisted", which eventually prevents X509Store.Add() from correctly storing the private key.
            // To work around this issue, the certificate payload is manually exported and imported back
            // into a new X509Certificate2 instance specifying the X509KeyStorageFlags.PersistKeySet flag.
            var data = certificate.Export(X509ContentType.Pfx, string.Empty);

            try
            {
                var flags = X509KeyStorageFlags.PersistKeySet;

                // Note: macOS requires marking the certificate private key as exportable.
                // If this flag is not set, a CryptographicException is thrown at runtime.
                if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    flags |= X509KeyStorageFlags.Exportable;
                }

                certificates.Insert(0, certificate = new X509Certificate2(data, string.Empty, flags));
            }

            finally
            {
                Array.Clear(data, 0, data.Length);
            }

            store.Add(certificate);
#else
            throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0264));
#endif
        }

        return Configure(options => options.SigningCredentials.AddRange(
            from certificate in certificates
            let key = new X509SecurityKey(certificate)
            select new SigningCredentials(key, SecurityAlgorithms.RsaSha256)));
    }

    /// <summary>
    /// Registers a new ephemeral signing key. Ephemeral signing keys are automatically
    /// discarded when the application shuts down and payloads signed using this key are
    /// automatically invalidated. This method should only be used during development.
    /// On production, using a X.509 certificate stored in the machine store is recommended.
    /// </summary>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    public OpenIddictClientBuilder AddEphemeralSigningKey()
        => AddEphemeralSigningKey(SecurityAlgorithms.RsaSha256);

    /// <summary>
    /// Registers a new ephemeral signing key. Ephemeral signing keys are automatically
    /// discarded when the application shuts down and payloads signed using this key are
    /// automatically invalidated. This method should only be used during development.
    /// On production, using a X.509 certificate stored in the machine store is recommended.
    /// </summary>
    /// <param name="algorithm">The algorithm associated with the signing key.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The X.509 certificate is attached to the client options.")]
    public OpenIddictClientBuilder AddEphemeralSigningKey(string algorithm)
    {
        if (string.IsNullOrEmpty(algorithm))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0057), nameof(algorithm));
        }

        return algorithm switch
        {
            SecurityAlgorithms.RsaSha256 or
            SecurityAlgorithms.RsaSha384 or
            SecurityAlgorithms.RsaSha512 or
            SecurityAlgorithms.RsaSha256Signature or
            SecurityAlgorithms.RsaSha384Signature or
            SecurityAlgorithms.RsaSha512Signature or
            SecurityAlgorithms.RsaSsaPssSha256 or
            SecurityAlgorithms.RsaSsaPssSha384 or
            SecurityAlgorithms.RsaSsaPssSha512 or
            SecurityAlgorithms.RsaSsaPssSha256Signature or
            SecurityAlgorithms.RsaSsaPssSha384Signature or
            SecurityAlgorithms.RsaSsaPssSha512Signature
                => AddSigningCredentials(new SigningCredentials(CreateRsaSecurityKey(2048), algorithm)),

#if SUPPORTS_ECDSA
            SecurityAlgorithms.EcdsaSha256 or
            SecurityAlgorithms.EcdsaSha256Signature
                => AddSigningCredentials(new SigningCredentials(new ECDsaSecurityKey(
                    ECDsa.Create(ECCurve.NamedCurves.nistP256)), algorithm)),

            SecurityAlgorithms.EcdsaSha384 or
            SecurityAlgorithms.EcdsaSha384Signature
                => AddSigningCredentials(new SigningCredentials(new ECDsaSecurityKey(
                    ECDsa.Create(ECCurve.NamedCurves.nistP384)), algorithm)),

            SecurityAlgorithms.EcdsaSha512 or
            SecurityAlgorithms.EcdsaSha512Signature
                => AddSigningCredentials(new SigningCredentials(new ECDsaSecurityKey(
                    ECDsa.Create(ECCurve.NamedCurves.nistP521)), algorithm)),
#else
            SecurityAlgorithms.EcdsaSha256 or
            SecurityAlgorithms.EcdsaSha384 or
            SecurityAlgorithms.EcdsaSha512 or
            SecurityAlgorithms.EcdsaSha256Signature or
            SecurityAlgorithms.EcdsaSha384Signature or
            SecurityAlgorithms.EcdsaSha512Signature
                => throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0069)),
#endif

            _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0058))
        };

        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
            Justification = "The generated RSA key is attached to the client options.")]
        static RsaSecurityKey CreateRsaSecurityKey(int size)
        {
#if SUPPORTS_DIRECT_KEY_CREATION_WITH_SPECIFIED_SIZE
            return new RsaSecurityKey(RSA.Create(size));
#else
            // Note: a 1024-bit key might be returned by RSA.Create() on .NET Desktop/Mono,
            // where RSACryptoServiceProvider is still the default implementation and
            // where custom implementations can be registered via CryptoConfig.
            // To ensure the key size is always acceptable, replace it if necessary.
            var algorithm = RSA.Create();
            if (algorithm.KeySize < size)
            {
                algorithm.KeySize = size;
            }

            if (algorithm.KeySize < size && algorithm is RSACryptoServiceProvider)
            {
                algorithm.Dispose();
                algorithm = new RSACryptoServiceProvider(size);
            }

            if (algorithm.KeySize < size)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0059));
            }

            return new RsaSecurityKey(algorithm);
#endif
        }
    }

    /// <summary>
    /// Registers a signing certificate.
    /// </summary>
    /// <param name="certificate">The signing certificate.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    public OpenIddictClientBuilder AddSigningCertificate(X509Certificate2 certificate)
    {
        if (certificate is null)
        {
            throw new ArgumentNullException(nameof(certificate));
        }

        // If the certificate is a X.509v3 certificate that specifies at least
        // one key usage, ensure that the certificate key can be used for signing.
        if (certificate.Version >= 3)
        {
            var extensions = certificate.Extensions.OfType<X509KeyUsageExtension>().ToList();
            if (extensions.Count is not 0 && !extensions.Any(extension => extension.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature)))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0070));
            }
        }

        if (!certificate.HasPrivateKey)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0061));
        }

        return AddSigningKey(new X509SecurityKey(certificate));
    }

    /// <summary>
    /// Registers a signing certificate retrieved from an embedded resource.
    /// </summary>
    /// <param name="assembly">The assembly containing the certificate.</param>
    /// <param name="resource">The name of the embedded resource.</param>
    /// <param name="password">The password used to open the certificate.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    public OpenIddictClientBuilder AddSigningCertificate(Assembly assembly, string resource, string? password)
#if SUPPORTS_EPHEMERAL_KEY_SETS
        // Note: ephemeral key sets are currently not supported on macOS.
        => AddSigningCertificate(assembly, resource, password, RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ?
            X509KeyStorageFlags.MachineKeySet :
            X509KeyStorageFlags.EphemeralKeySet);
#else
        => AddSigningCertificate(assembly, resource, password, X509KeyStorageFlags.MachineKeySet);
#endif

    /// <summary>
    /// Registers a signing certificate retrieved from an embedded resource.
    /// </summary>
    /// <param name="assembly">The assembly containing the certificate.</param>
    /// <param name="resource">The name of the embedded resource.</param>
    /// <param name="password">The password used to open the certificate.</param>
    /// <param name="flags">An enumeration of flags indicating how and where to store the private key of the certificate.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    public OpenIddictClientBuilder AddSigningCertificate(
        Assembly assembly, string resource,
        string? password, X509KeyStorageFlags flags)
    {
        if (assembly is null)
        {
            throw new ArgumentNullException(nameof(assembly));
        }

        if (string.IsNullOrEmpty(resource))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0062), nameof(resource));
        }

        using var stream = assembly.GetManifestResourceStream(resource) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0064));

        return AddSigningCertificate(stream, password, flags);
    }

    /// <summary>
    /// Registers a signing certificate extracted from a stream.
    /// </summary>
    /// <param name="stream">The stream containing the certificate.</param>
    /// <param name="password">The password used to open the certificate.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    public OpenIddictClientBuilder AddSigningCertificate(Stream stream, string? password)
#if SUPPORTS_EPHEMERAL_KEY_SETS
        // Note: ephemeral key sets are currently not supported on macOS.
        => AddSigningCertificate(stream, password, RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ?
            X509KeyStorageFlags.MachineKeySet :
            X509KeyStorageFlags.EphemeralKeySet);
#else
        => AddSigningCertificate(stream, password, X509KeyStorageFlags.MachineKeySet);
#endif

    /// <summary>
    /// Registers a signing certificate extracted from a stream.
    /// </summary>
    /// <param name="stream">The stream containing the certificate.</param>
    /// <param name="password">The password used to open the certificate.</param>
    /// <param name="flags">
    /// An enumeration of flags indicating how and where
    /// to store the private key of the certificate.
    /// </param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The X.509 certificate is attached to the client options.")]
    public OpenIddictClientBuilder AddSigningCertificate(Stream stream, string? password, X509KeyStorageFlags flags)
    {
        if (stream is null)
        {
            throw new ArgumentNullException(nameof(stream));
        }

        using var buffer = new MemoryStream();
        stream.CopyTo(buffer);

        return AddSigningCertificate(new X509Certificate2(buffer.ToArray(), password, flags));
    }

    /// <summary>
    /// Registers a signing certificate retrieved from the X.509 user or machine store.
    /// </summary>
    /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X.509 store.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    public OpenIddictClientBuilder AddSigningCertificate(string thumbprint)
    {
        if (string.IsNullOrEmpty(thumbprint))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0065), nameof(thumbprint));
        }

        return AddSigningCertificate(
            GetCertificate(StoreLocation.CurrentUser, thumbprint)  ??
            GetCertificate(StoreLocation.LocalMachine, thumbprint) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0066)));

        static X509Certificate2? GetCertificate(StoreLocation location, string thumbprint)
        {
            using var store = new X509Store(StoreName.My, location);
            store.Open(OpenFlags.ReadOnly);

            return store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false)
                .OfType<X509Certificate2>()
                .SingleOrDefault();
        }
    }

    /// <summary>
    /// Registers a signing certificate retrieved from the specified X.509 store.
    /// </summary>
    /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X.509 store.</param>
    /// <param name="name">The name of the X.509 store.</param>
    /// <param name="location">The location of the X.509 store.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    public OpenIddictClientBuilder AddSigningCertificate(string thumbprint, StoreName name, StoreLocation location)
    {
        if (string.IsNullOrEmpty(thumbprint))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0065), nameof(thumbprint));
        }

        using var store = new X509Store(name, location);
        store.Open(OpenFlags.ReadOnly);

        return AddSigningCertificate(
            store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false)
                .OfType<X509Certificate2>()
                .SingleOrDefault() ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0066)));
    }

    /// <summary>
    /// Adds a new client registration.
    /// </summary>
    /// <param name="registration">The client registration.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    public OpenIddictClientBuilder AddRegistration(OpenIddictClientRegistration registration)
    {
        if (registration is null)
        {
            throw new ArgumentNullException(nameof(registration));
        }

        return Configure(options => options.Registrations.Add(registration));
    }

    /// <summary>
    /// Disables token storage, so that no database entry is created
    /// for the tokens and codes returned by the OpenIddict client.
    /// Using this option is generally NOT recommended as it prevents
    /// the tokens from being revoked (if needed).
    /// </summary>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    public OpenIddictClientBuilder DisableTokenStorage()
        => Configure(options => options.DisableTokenStorage = true);

    /// <summary>
    /// Sets the relative or absolute URLs associated to the redirection endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// </summary>
    /// <remarks>
    /// Note: to mitigate mix-up attacks, it's recommended to use a unique redirection endpoint
    /// address per provider, unless all the registered providers support returning an "iss"
    /// parameter containing their URL as part of authorization responses. For more information,
    /// see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.4.
    /// </remarks>
    /// <param name="addresses">The addresses associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    public OpenIddictClientBuilder SetRedirectionEndpointUris(params string[] addresses)
    {
        if (addresses is null)
        {
            throw new ArgumentNullException(nameof(addresses));
        }

        return SetRedirectionEndpointUris(addresses.Select(address => new Uri(address, UriKind.RelativeOrAbsolute)).ToArray());
    }

    /// <summary>
    /// Sets the relative or absolute URLs associated to the redirection endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// </summary>
    /// <remarks>
    /// Note: to mitigate mix-up attacks, it's recommended to use a unique redirection endpoint
    /// address per provider, unless all the registered providers support returning an "iss"
    /// parameter containing their URL as part of authorization responses. For more information,
    /// see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.4.
    /// </remarks>
    /// <param name="addresses">The addresses associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    public OpenIddictClientBuilder SetRedirectionEndpointUris(params Uri[] addresses)
    {
        if (addresses is null)
        {
            throw new ArgumentNullException(nameof(addresses));
        }

        if (addresses.Any(address => !address.IsWellFormedOriginalString()))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0072), nameof(addresses));
        }

        if (addresses.Any(address => address.OriginalString.StartsWith("~", StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException(SR.FormatID0081("~"), nameof(addresses));
        }

        return Configure(options =>
        {
            options.RedirectionEndpointUris.Clear();
            options.RedirectionEndpointUris.AddRange(addresses);
        });
    }

    /// <summary>
    /// Sets the relative or absolute URLs associated to the post-logout redirection endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// </summary>
    /// <param name="addresses">The addresses associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    public OpenIddictClientBuilder SetPostLogoutRedirectionEndpointUris(params string[] addresses)
    {
        if (addresses is null)
        {
            throw new ArgumentNullException(nameof(addresses));
        }

        return SetPostLogoutRedirectionEndpointUris(addresses.Select(address => new Uri(address, UriKind.RelativeOrAbsolute)).ToArray());
    }

    /// <summary>
    /// Sets the relative or absolute URLs associated to the post-logout redirection endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// </summary>
    /// <param name="addresses">The addresses associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    public OpenIddictClientBuilder SetPostLogoutRedirectionEndpointUris(params Uri[] addresses)
    {
        if (addresses is null)
        {
            throw new ArgumentNullException(nameof(addresses));
        }

        if (addresses.Any(address => !address.IsWellFormedOriginalString()))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0072), nameof(addresses));
        }

        if (addresses.Any(address => address.OriginalString.StartsWith("~", StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException(SR.FormatID0081("~"), nameof(addresses));
        }

        return Configure(options =>
        {
            options.PostLogoutRedirectionEndpointUris.Clear();
            options.PostLogoutRedirectionEndpointUris.AddRange(addresses);
        });
    }

    /// <summary>
    /// Sets the client assertion token lifetime, after which backchannel requests
    /// using an expired state token should be automatically rejected by the server.
    /// Using long-lived state tokens or tokens that never expire is not recommended.
    /// While discouraged, <see langword="null"/> can be specified to issue tokens that never expire.
    /// </summary>
    /// <param name="lifetime">The access token lifetime.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    public OpenIddictClientBuilder SetClientAssertionTokenLifetime(TimeSpan? lifetime)
        => Configure(options => options.ClientAssertionTokenLifetime = lifetime);

    /// <summary>
    /// Sets the state token lifetime, after which authorization callbacks
    /// using an expired state token will be automatically rejected by OpenIddict.
    /// Using long-lived state tokens or tokens that never expire is not recommended.
    /// While discouraged, <see langword="null"/> can be specified to issue tokens that never expire.
    /// </summary>
    /// <param name="lifetime">The access token lifetime.</param>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    public OpenIddictClientBuilder SetStateTokenLifetime(TimeSpan? lifetime)
        => Configure(options => options.StateTokenLifetime = lifetime);

    /// <summary>
    /// Determines whether the specified object is equal to the current object.
    /// </summary>
    /// <param name="obj">The object to compare with the current object.</param>
    /// <returns><see langword="true"/> if the specified object is equal to the current object; otherwise, false.</returns>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals(object? obj) => base.Equals(obj);

    /// <summary>
    /// Serves as the default hash function.
    /// </summary>
    /// <returns>A hash code for the current object.</returns>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => base.GetHashCode();

    /// <summary>
    /// Returns a string that represents the current object.
    /// </summary>
    /// <returns>A string that represents the current object.</returns>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override string? ToString() => base.ToString();
}
