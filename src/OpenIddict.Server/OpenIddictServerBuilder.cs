/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Reflection;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes the necessary methods required to configure the OpenIddict server services.
/// </summary>
public sealed class OpenIddictServerBuilder
{
    /// <summary>
    /// Initializes a new instance of <see cref="OpenIddictServerBuilder"/>.
    /// </summary>
    /// <param name="services">The services collection.</param>
    public OpenIddictServerBuilder(IServiceCollection services)
        => Services = services ?? throw new ArgumentNullException(nameof(services));

    /// <summary>
    /// Gets the services collection.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public IServiceCollection Services { get; }

    /// <summary>
    /// Enables validation of options during application startup.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder ValidateOnStart()
    {
        Services.AddOptionsWithValidateOnStart<OpenIddictServerOptions>();

        return this;
    }

    /// <summary>
    /// Registers an event handler using the specified configuration delegate.
    /// </summary>
    /// <typeparam name="TContext">The event context type.</typeparam>
    /// <param name="configuration">The configuration delegate.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictServerBuilder AddEventHandler<TContext>(
        Action<OpenIddictServerHandlerDescriptor.Builder<TContext>> configuration)
        where TContext : BaseContext
    {
        ArgumentNullException.ThrowIfNull(configuration);

        // Note: handlers registered using this API are assumed to be custom handlers by default.
        var builder = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
            .SetType(OpenIddictServerHandlerType.Custom);

        configuration(builder);

        return AddEventHandler(builder.Build());
    }

    /// <summary>
    /// Registers an event handler using the specified descriptor.
    /// </summary>
    /// <param name="descriptor">The handler descriptor.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictServerBuilder AddEventHandler(OpenIddictServerHandlerDescriptor descriptor)
    {
        ArgumentNullException.ThrowIfNull(descriptor);

        // Register the handler in the services collection.
        Services.Add(descriptor.ServiceDescriptor);

        return Configure(options => options.Handlers.Add(descriptor));
    }

    /// <summary>
    /// Removes the event handler that matches the specified descriptor.
    /// </summary>
    /// <param name="descriptor">The descriptor corresponding to the handler to remove.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictServerBuilder RemoveEventHandler(OpenIddictServerHandlerDescriptor descriptor)
    {
        ArgumentNullException.ThrowIfNull(descriptor);

        Services.RemoveAll(descriptor.ServiceDescriptor.ServiceType);

        Services.PostConfigure<OpenIddictServerOptions>(options =>
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
    /// Amends the default OpenIddict server configuration.
    /// </summary>
    /// <param name="configuration">The delegate used to configure the OpenIddict options.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictServerBuilder Configure(Action<OpenIddictServerOptions> configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        Services.Configure(configuration);

        return this;
    }

    /// <summary>
    /// Makes client identification optional so that token, introspection and revocation
    /// requests that don't specify a client_id are not automatically rejected.
    /// </summary>
    /// <remarks>
    /// Enabling this option is NOT recommended and should only be used for
    /// backward compatibility with legacy authorization server deployments.
    /// </remarks>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AcceptAnonymousClients()
        => Configure(options => options.AcceptAnonymousClients = true);

    /// <summary>
    /// Registers encryption credentials.
    /// </summary>
    /// <param name="credentials">The encrypting credentials.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddEncryptionCredentials(EncryptingCredentials credentials)
    {
        ArgumentNullException.ThrowIfNull(credentials);

        return Configure(options => options.EncryptionCredentials.Add(credentials));
    }

    /// <summary>
    /// Registers an encryption key.
    /// </summary>
    /// <param name="key">The security key.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddEncryptionKey(SecurityKey key)
    {
        ArgumentNullException.ThrowIfNull(key);

        // If the encryption key is an asymmetric security key, ensure it has a private key.
        if (key is AsymmetricSecurityKey { PrivateKeyStatus: PrivateKeyStatus.DoesNotExist })
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0055));
        }

        if (key.IsSupportedAlgorithm(SecurityAlgorithms.Aes256KW))
        {
            if (key.KeySize is not 256)
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
    /// Registers multiple encryption keys.
    /// </summary>
    /// <param name="keys">The security keys.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddEncryptionKeys(IEnumerable<SecurityKey> keys)
    {
        ArgumentNullException.ThrowIfNull(keys);

        return keys.Aggregate(this, static (builder, key) => builder.AddEncryptionKey(key));
    }

    /// <summary>
    /// Registers (and generates if necessary) a user-specific development encryption certificate.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddDevelopmentEncryptionCertificate()
        => AddDevelopmentEncryptionCertificate(new X500DistinguishedName("CN=OpenIddict Server Encryption Certificate"));

    /// <summary>
    /// Registers (and generates if necessary) a user-specific development encryption certificate.
    /// </summary>
    /// <param name="subject">The subject name associated with the certificate.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddDevelopmentEncryptionCertificate(X500DistinguishedName subject)
    {
        ArgumentNullException.ThrowIfNull(subject);

        Services.AddOptions<OpenIddictServerOptions>().Configure<IServiceProvider>((options, provider) =>
        {
            // Important: the time provider might not be set yet when this configuration delegate is called.
            // In that case, resolve the provider from the service provider or use the default time provider.
            var now = (options.TimeProvider ?? provider.GetService<TimeProvider>() ?? TimeProvider.System).GetUtcNow();

            using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);

            // Try to retrieve the existing development certificates from the specified store.
            // If no valid existing certificate was found, create a new encryption certificate.
            var certificates = store.Certificates
                .Find(X509FindType.FindBySubjectDistinguishedName, subject.Name, validOnly: false)
                .Cast<X509Certificate2>()
                .ToList();

            if (!certificates.Exists(certificate => certificate.NotBefore < now.LocalDateTime && certificate.NotAfter > now.LocalDateTime))
            {
                using var algorithm = RSA.Create(keySizeInBits: 4096);

                var request = new CertificateRequest(subject, algorithm, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyEncipherment, critical: true));

                var certificate = request.CreateSelfSigned(now, now.AddYears(2));

                // Note: setting the friendly name is not supported on Unix machines (including Linux and macOS).
                // To ensure an exception is not thrown by the property setter, an OS runtime check is used here.
                if (OperatingSystem.IsWindows())
                {
                    certificate.FriendlyName = "OpenIddict Server Development Encryption Certificate";
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
                    if (OperatingSystem.IsMacOS())
                    {
                        flags |= X509KeyStorageFlags.Exportable;
                    }

                    certificate = X509CertificateLoader.LoadPkcs12(data, string.Empty, flags);
                    certificates.Insert(0, certificate);
                }

                finally
                {
                    Array.Clear(data, 0, data.Length);
                }

                store.Add(certificate);
            }

            options.EncryptionCredentials.AddRange(
                from certificate in certificates
                let key = new X509SecurityKey(certificate)
                select new EncryptingCredentials(key, SecurityAlgorithms.RsaOAEP,
                    SecurityAlgorithms.Aes256CbcHmacSha512));
        });

        return this;
    }

    /// <summary>
    /// Registers a new ephemeral encryption key. Ephemeral encryption keys are automatically
    /// discarded when the application shuts down and payloads encrypted using this key are
    /// automatically invalidated. This method should only be used during development.
    /// On production, using a X.509 certificate stored in the machine store is recommended.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddEphemeralEncryptionKey()
        => AddEphemeralEncryptionKey(SecurityAlgorithms.RsaOAEP);

    /// <summary>
    /// Registers a new ephemeral encryption key. Ephemeral encryption keys are automatically
    /// discarded when the application shuts down and payloads encrypted using this key are
    /// automatically invalidated. This method should only be used during development.
    /// On production, using a X.509 certificate stored in the machine store is recommended.
    /// </summary>
    /// <param name="algorithm">The algorithm associated with the encryption key.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddEphemeralEncryptionKey(string algorithm)
    {
        ArgumentException.ThrowIfNullOrEmpty(algorithm);

        return algorithm switch
        {
            SecurityAlgorithms.Aes256KW
                => AddEncryptionCredentials(new EncryptingCredentials(
                    new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(count: 256 / 8)),
                    algorithm, SecurityAlgorithms.Aes256CbcHmacSha512)),

            SecurityAlgorithms.RsaOAEP or
            SecurityAlgorithms.RsaOaepKeyWrap
                => AddEncryptionCredentials(new EncryptingCredentials(
                    new RsaSecurityKey(RSA.Create(keySizeInBits: 4096)),
                    algorithm, SecurityAlgorithms.Aes256CbcHmacSha512)),

            _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0058))
        };
    }

    /// <summary>
    /// Registers an encryption certificate.
    /// </summary>
    /// <param name="certificate">The encryption certificate.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddEncryptionCertificate(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        // If the certificate is a X.509v3 certificate that specifies at least one
        // key usage, ensure that the certificate key can be used for key encryption.
        if (certificate.Version is >= 3)
        {
            var extensions = certificate.Extensions.OfType<X509KeyUsageExtension>().ToList();
            if (extensions.Count is not 0 && !extensions.Exists(static extension =>
                extension.KeyUsages.HasFlag(X509KeyUsageFlags.KeyEncipherment)))
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
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddEncryptionCertificate(Assembly assembly, string resource, string? password)
        // Note: ephemeral key sets are currently not supported on macOS.
        => AddEncryptionCertificate(assembly, resource, password, OperatingSystem.IsMacOS()
            ? X509KeyStorageFlags.MachineKeySet
            : X509KeyStorageFlags.EphemeralKeySet);

    /// <summary>
    /// Registers an encryption certificate retrieved from an embedded resource.
    /// </summary>
    /// <param name="assembly">The assembly containing the certificate.</param>
    /// <param name="resource">The name of the embedded resource.</param>
    /// <param name="password">The password used to open the certificate.</param>
    /// <param name="flags">An enumeration of flags indicating how and where to store the private key of the certificate.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddEncryptionCertificate(
        Assembly assembly, string resource,
        string? password, X509KeyStorageFlags flags)
    {
        ArgumentNullException.ThrowIfNull(assembly);
        ArgumentException.ThrowIfNullOrEmpty(resource);

        using var stream = assembly.GetManifestResourceStream(resource)
            ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0064));

        return AddEncryptionCertificate(stream, password, flags);
    }

    /// <summary>
    /// Registers an encryption certificate extracted from a stream.
    /// </summary>
    /// <param name="stream">The stream containing the certificate.</param>
    /// <param name="password">The password used to open the certificate.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddEncryptionCertificate(Stream stream, string? password)
        // Note: ephemeral key sets are currently not supported on macOS.
        => AddEncryptionCertificate(stream, password, OperatingSystem.IsMacOS()
            ? X509KeyStorageFlags.MachineKeySet
            : X509KeyStorageFlags.EphemeralKeySet);

    /// <summary>
    /// Registers an encryption certificate extracted from a stream.
    /// </summary>
    /// <param name="stream">The stream containing the certificate.</param>
    /// <param name="password">The password used to open the certificate.</param>
    /// <param name="flags">An enumeration of flags indicating how and where to store the private key of the certificate.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddEncryptionCertificate(Stream stream, string? password, X509KeyStorageFlags flags)
    {
        ArgumentNullException.ThrowIfNull(stream);

        using var buffer = new MemoryStream();
        stream.CopyTo(buffer);

        var certificate = X509Certificate2.GetCertContentType(buffer.ToArray()) switch
        {
            X509ContentType.Pkcs12 => X509CertificateLoader.LoadPkcs12(buffer.ToArray(), password, flags),

            _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0454))
        };

        return AddEncryptionCertificate(certificate);
    }

    /// <summary>
    /// Registers an encryption certificate retrieved from the X.509 user or machine store.
    /// </summary>
    /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X.509 store.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    [UnsupportedOSPlatform("linux")]
    public OpenIddictServerBuilder AddEncryptionCertificate(string thumbprint)
    {
        ArgumentException.ThrowIfNullOrEmpty(thumbprint);

        return AddEncryptionCertificate(
            GetCertificate(StoreLocation.CurrentUser, thumbprint)
            ?? GetCertificate(StoreLocation.LocalMachine, thumbprint)
            ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0066)));

        static X509Certificate2? GetCertificate(StoreLocation location, string thumbprint)
        {
            using var store = new X509Store(StoreName.My, location);
            store.Open(OpenFlags.ReadOnly);

            return store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false)
                .Cast<X509Certificate2>()
                .SingleOrDefault();
        }
    }

    /// <summary>
    /// Registers an encryption certificate retrieved from the specified X.509 store.
    /// </summary>
    /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X.509 store.</param>
    /// <param name="name">The name of the X.509 store.</param>
    /// <param name="location">The location of the X.509 store.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddEncryptionCertificate(string thumbprint, StoreName name, StoreLocation location)
    {
        ArgumentException.ThrowIfNullOrEmpty(thumbprint);

        using var store = new X509Store(name, location);
        store.Open(OpenFlags.ReadOnly);

        return AddEncryptionCertificate(
            store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false)
                .Cast<X509Certificate2>()
                .SingleOrDefault() ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0066)));
    }
    
    /// <summary>
    /// Registers multiple encryption certificates.
    /// </summary>
    /// <param name="certificates">The encryption certificates.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddEncryptionCertificates(IEnumerable<X509Certificate2> certificates)
    {
        ArgumentNullException.ThrowIfNull(certificates);

        return certificates.Aggregate(this, static (builder, certificate) => builder.AddEncryptionCertificate(certificate));
    }

    /// <summary>
    /// Registers signing credentials.
    /// </summary>
    /// <param name="credentials">The signing credentials.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddSigningCredentials(SigningCredentials credentials)
    {
        ArgumentNullException.ThrowIfNull(credentials);

        return Configure(options => options.SigningCredentials.Add(credentials));
    }

    /// <summary>
    /// Registers a signing key.
    /// </summary>
    /// <param name="key">The security key.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddSigningKey(SecurityKey key)
    {
        ArgumentNullException.ThrowIfNull(key);

        // If the signing key is an asymmetric security key, ensure it has a private key.
        if (key is AsymmetricSecurityKey { PrivateKeyStatus: PrivateKeyStatus.DoesNotExist })
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0067));
        }

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

        if (key.IsSupportedAlgorithm(SecurityAlgorithms.HmacSha256))
        {
            return AddSigningCredentials(new SigningCredentials(key, SecurityAlgorithms.HmacSha256));
        }

        if (key.IsSupportedAlgorithm(SecurityAlgorithms.MlDsa44))
        {
            return AddSigningCredentials(new SigningCredentials(key, SecurityAlgorithms.MlDsa44));
        }

        if (key.IsSupportedAlgorithm(SecurityAlgorithms.MlDsa65))
        {
            return AddSigningCredentials(new SigningCredentials(key, SecurityAlgorithms.MlDsa65));
        }

        if (key.IsSupportedAlgorithm(SecurityAlgorithms.MlDsa87))
        {
            return AddSigningCredentials(new SigningCredentials(key, SecurityAlgorithms.MlDsa87));
        }

        if (key.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256))
        {
            return AddSigningCredentials(new SigningCredentials(key, SecurityAlgorithms.RsaSha256));
        }

        throw new InvalidOperationException(SR.GetResourceString(SR.ID0068));
    }
    
    /// <summary>
    /// Registers multiple signing keys.
    /// </summary>
    /// <param name="keys">The signing keys.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddSigningKeys(IEnumerable<SecurityKey> keys)
    {
        ArgumentNullException.ThrowIfNull(keys);

        return keys.Aggregate(this, static (builder, key) => builder.AddSigningKey(key));
    }

    /// <summary>
    /// Registers (and generates if necessary) a user-specific development signing certificate.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddDevelopmentSigningCertificate()
        => AddDevelopmentSigningCertificate(new X500DistinguishedName("CN=OpenIddict Server Signing Certificate"));

    /// <summary>
    /// Registers (and generates if necessary) a user-specific development signing certificate.
    /// </summary>
    /// <param name="subject">The subject name associated with the certificate.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddDevelopmentSigningCertificate(X500DistinguishedName subject)
    {
        ArgumentNullException.ThrowIfNull(subject);

        Services.AddOptions<OpenIddictServerOptions>().Configure<IServiceProvider>((options, provider) =>
        {
            // Important: the time provider might not be set yet when this configuration delegate is called.
            // In that case, resolve the provider from the service provider or use the default time provider.
            var now = (options.TimeProvider ?? provider.GetService<TimeProvider>() ?? TimeProvider.System).GetUtcNow();

            using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);

            // Try to retrieve the existing development certificates from the specified store.
            // If no valid existing certificate was found, create a new signing certificate.
            var certificates = store.Certificates
                .Find(X509FindType.FindBySubjectDistinguishedName, subject.Name, validOnly: false)
                .Cast<X509Certificate2>()
                .ToList();

            if (!certificates.Exists(certificate => certificate.NotBefore < now.LocalDateTime && certificate.NotAfter > now.LocalDateTime))
            {
                using var algorithm = RSA.Create(keySizeInBits: 4096);

                var request = new CertificateRequest(subject, algorithm, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));

                var certificate = request.CreateSelfSigned(now, now.AddYears(2));

                // Note: setting the friendly name is not supported on Unix machines (including Linux and macOS).
                // To ensure an exception is not thrown by the property setter, an OS runtime check is used here.
                if (OperatingSystem.IsWindows())
                {
                    certificate.FriendlyName = "OpenIddict Server Development Signing Certificate";
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
                    if (OperatingSystem.IsMacOS())
                    {
                        flags |= X509KeyStorageFlags.Exportable;
                    }

                    certificate = X509CertificateLoader.LoadPkcs12(data, string.Empty, flags);
                    certificates.Insert(0, certificate);
                }

                finally
                {
                    Array.Clear(data, 0, data.Length);
                }

                store.Add(certificate);
            }

            options.SigningCredentials.AddRange(
                from certificate in certificates
                let key = new X509SecurityKey(certificate)
                select new SigningCredentials(key, SecurityAlgorithms.RsaSha256));
        });

        return this;
    }

    /// <summary>
    /// Registers a new ephemeral signing key. Ephemeral signing keys are automatically
    /// discarded when the application shuts down and payloads signed using this key are
    /// automatically invalidated. This method should only be used during development.
    /// On production, using a X.509 certificate stored in the machine store is recommended.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddEphemeralSigningKey()
        => AddEphemeralSigningKey(SecurityAlgorithms.RsaSha256);

    /// <summary>
    /// Registers a new ephemeral signing key. Ephemeral signing keys are automatically
    /// discarded when the application shuts down and payloads signed using this key are
    /// automatically invalidated. This method should only be used during development.
    /// On production, using a X.509 certificate stored in the machine store is recommended.
    /// </summary>
    /// <param name="algorithm">The algorithm associated with the signing key.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddEphemeralSigningKey(string algorithm)
    {
        ArgumentException.ThrowIfNullOrEmpty(algorithm);

        return algorithm switch
        {
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

            SecurityAlgorithms.MlDsa44
                => AddSigningCredentials(new SigningCredentials(new MlDsaSecurityKey(
                    MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa44)), algorithm)),

            SecurityAlgorithms.MlDsa65
                => AddSigningCredentials(new SigningCredentials(new MlDsaSecurityKey(
                    MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65)), algorithm)),

            SecurityAlgorithms.MlDsa87
                => AddSigningCredentials(new SigningCredentials(new MlDsaSecurityKey(
                    MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa87)), algorithm)),

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
                => AddSigningCredentials(new SigningCredentials(new RsaSecurityKey(
                    RSA.Create(keySizeInBits: 4096)), algorithm)),

            _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0058))
        };
    }

    /// <summary>
    /// Registers a signing certificate.
    /// </summary>
    /// <param name="certificate">The signing certificate.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddSigningCertificate(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        // If the certificate is a X.509v3 certificate that specifies at least
        // one key usage, ensure that the certificate key can be used for signing.
        if (certificate.Version is >= 3)
        {
            var extensions = certificate.Extensions.OfType<X509KeyUsageExtension>().ToList();
            if (extensions.Count is not 0 && !extensions.Exists(static extension =>
                extension.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature)))
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
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddSigningCertificate(Assembly assembly, string resource, string? password)
        // Note: ephemeral key sets are currently not supported on macOS.
        => AddSigningCertificate(assembly, resource, password, OperatingSystem.IsMacOS()
            ? X509KeyStorageFlags.MachineKeySet
            : X509KeyStorageFlags.EphemeralKeySet);

    /// <summary>
    /// Registers a signing certificate retrieved from an embedded resource.
    /// </summary>
    /// <param name="assembly">The assembly containing the certificate.</param>
    /// <param name="resource">The name of the embedded resource.</param>
    /// <param name="password">The password used to open the certificate.</param>
    /// <param name="flags">An enumeration of flags indicating how and where to store the private key of the certificate.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddSigningCertificate(
        Assembly assembly, string resource,
        string? password, X509KeyStorageFlags flags)
    {
        ArgumentNullException.ThrowIfNull(assembly);
        ArgumentException.ThrowIfNullOrEmpty(resource);

        using var stream = assembly.GetManifestResourceStream(resource)
            ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0064));

        return AddSigningCertificate(stream, password, flags);
    }

    /// <summary>
    /// Registers a signing certificate extracted from a stream.
    /// </summary>
    /// <param name="stream">The stream containing the certificate.</param>
    /// <param name="password">The password used to open the certificate.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddSigningCertificate(Stream stream, string? password)
        // Note: ephemeral key sets are currently not supported on macOS.
        => AddSigningCertificate(stream, password, OperatingSystem.IsMacOS()
            ? X509KeyStorageFlags.MachineKeySet
            : X509KeyStorageFlags.EphemeralKeySet);

    /// <summary>
    /// Registers a signing certificate extracted from a stream.
    /// </summary>
    /// <param name="stream">The stream containing the certificate.</param>
    /// <param name="password">The password used to open the certificate.</param>
    /// <param name="flags">An enumeration of flags indicating how and where to store the private key of the certificate.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddSigningCertificate(Stream stream, string? password, X509KeyStorageFlags flags)
    {
        ArgumentNullException.ThrowIfNull(stream);

        using var buffer = new MemoryStream();
        stream.CopyTo(buffer);

        var certificate = X509Certificate2.GetCertContentType(buffer.ToArray()) switch
        {
            X509ContentType.Pkcs12 => X509CertificateLoader.LoadPkcs12(buffer.ToArray(), password, flags),

            _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0454))
        };

        return AddSigningCertificate(certificate);
    }

    /// <summary>
    /// Registers a signing certificate retrieved from the X.509 user or machine store.
    /// </summary>
    /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X.509 store.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    [UnsupportedOSPlatform("linux")]
    public OpenIddictServerBuilder AddSigningCertificate(string thumbprint)
    {
        ArgumentException.ThrowIfNullOrEmpty(thumbprint);

        return AddSigningCertificate(
            GetCertificate(StoreLocation.CurrentUser, thumbprint)
            ?? GetCertificate(StoreLocation.LocalMachine, thumbprint)
            ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0066)));

        static X509Certificate2? GetCertificate(StoreLocation location, string thumbprint)
        {
            using var store = new X509Store(StoreName.My, location);
            store.Open(OpenFlags.ReadOnly);

            return store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false)
                .Cast<X509Certificate2>()
                .SingleOrDefault();
        }
    }

    /// <summary>
    /// Registers a signing certificate retrieved from the specified X.509 store.
    /// </summary>
    /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X.509 store.</param>
    /// <param name="name">The name of the X.509 store.</param>
    /// <param name="location">The location of the X.509 store.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddSigningCertificate(string thumbprint, StoreName name, StoreLocation location)
    {
        ArgumentException.ThrowIfNullOrEmpty(thumbprint);

        using var store = new X509Store(name, location);
        store.Open(OpenFlags.ReadOnly);

        return AddSigningCertificate(
            store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false)
                .Cast<X509Certificate2>()
                .SingleOrDefault() ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0066)));
    }
    
    /// <summary>
    /// Registers multiple signing certificates.
    /// </summary>
    /// <param name="certificates">The signing certificates.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AddSigningCertificates(IEnumerable<X509Certificate2> certificates)
    {
        ArgumentNullException.ThrowIfNull(certificates);

        return certificates.Aggregate(this, static (builder, certificate) => builder.AddSigningCertificate(certificate));
    }

    /// <summary>
    /// Enables authorization code flow support. For more information
    /// about this specific OAuth 2.0/OpenID Connect flow, visit
    /// https://tools.ietf.org/html/rfc6749#section-4.1 and
    /// http://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AllowAuthorizationCodeFlow()
        => Configure(options =>
        {
            options.GrantTypes.Add(GrantTypes.AuthorizationCode);

            options.ResponseTypes.Add(ResponseTypes.Code);
        });

    /// <summary>
    /// Enables client credentials flow support. For more information about this
    /// specific OAuth 2.0 flow, visit https://tools.ietf.org/html/rfc6749#section-4.4.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AllowClientCredentialsFlow()
        => Configure(options => options.GrantTypes.Add(GrantTypes.ClientCredentials));

    /// <summary>
    /// Enables custom grant type support.
    /// </summary>
    /// <param name="type">The grant type associated with the flow.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictServerBuilder AllowCustomFlow(string type)
    {
        ArgumentException.ThrowIfNullOrEmpty(type);

        return type switch
        {
            GrantTypes.AuthorizationCode or GrantTypes.ClientCredentials or
            GrantTypes.DeviceCode        or GrantTypes.Implicit          or
            GrantTypes.Password          or GrantTypes.RefreshToken      or
            GrantTypes.TokenExchange
                => throw new ArgumentException(SR.FormatID0517(type), nameof(type)),

            _ => Configure(options => options.GrantTypes.Add(type))
        };
    }

    /// <summary>
    /// Enables device authorization flow support. For more information about this
    /// specific OAuth 2.0 flow, visit https://tools.ietf.org/html/rfc8628.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AllowDeviceAuthorizationFlow()
        => Configure(options => options.GrantTypes.Add(GrantTypes.DeviceCode));

    /// <summary>
    /// Enables hybrid flow support. For more information
    /// about this specific OpenID Connect flow, visit
    /// http://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AllowHybridFlow()
        => Configure(options =>
        {
            options.GrantTypes.Add(GrantTypes.AuthorizationCode);
            options.GrantTypes.Add(GrantTypes.Implicit);

            options.ResponseTypes.Add(ResponseTypes.Code + ' ' + ResponseTypes.IdToken);
            options.ResponseTypes.Add(ResponseTypes.Code + ' ' + ResponseTypes.IdToken + ' ' + ResponseTypes.Token);
            options.ResponseTypes.Add(ResponseTypes.Code + ' ' + ResponseTypes.Token);
        });

    /// <summary>
    /// Enables implicit flow support. For more information
    /// about this specific OAuth 2.0/OpenID Connect flow, visit
    /// https://tools.ietf.org/html/rfc6749#section-4.2 and
    /// http://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth.
    /// </summary>
    /// <remarks>
    /// Note: the implicit flow is not recommended for new applications due to
    /// its inherent limitations and should only be used in legacy scenarios.
    /// When possible, consider using the authorization code flow instead.
    /// </remarks>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AllowImplicitFlow()
        => Configure(options =>
        {
            options.GrantTypes.Add(GrantTypes.Implicit);

            options.ResponseTypes.Add(ResponseTypes.IdToken);
            options.ResponseTypes.Add(ResponseTypes.IdToken + ' ' + ResponseTypes.Token);
            options.ResponseTypes.Add(ResponseTypes.Token);
        });

    /// <summary>
    /// Enables none flow support. For more information about this specific OAuth 2.0 flow,
    /// visit https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#none.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AllowNoneFlow()
        => Configure(options => options.ResponseTypes.Add(ResponseTypes.None));

    /// <summary>
    /// Enables password flow support. For more information about this specific
    /// OAuth 2.0 flow, visit https://tools.ietf.org/html/rfc6749#section-4.3.
    /// </summary>
    /// <remarks>
    /// Note: the password flow is not recommended for new applications due to its
    /// inherent limitations and should only be used in legacy scenarios. When possible,
    /// consider using an interactive user flow like the authorization code flow instead.
    /// </remarks>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AllowPasswordFlow()
        => Configure(options => options.GrantTypes.Add(GrantTypes.Password));

    /// <summary>
    /// Enables refresh token flow support. For more information about this
    /// specific OAuth 2.0 flow, visit https://tools.ietf.org/html/rfc6749#section-6.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder AllowRefreshTokenFlow()
        => Configure(options =>
        {
            options.GrantTypes.Add(GrantTypes.RefreshToken);

            options.Scopes.Add(Scopes.OfflineAccess);
        });

    /// <summary>
    /// Enables token exchange flow support. For more information about this
    /// specific OAuth 2.0 flow, visit https://datatracker.ietf.org/doc/html/rfc8693.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictServerBuilder AllowTokenExchangeFlow()
        => Configure(options => options.GrantTypes.Add(GrantTypes.TokenExchange));

    /// <summary>
    /// Sets the relative or absolute URIs associated to the authorization endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetAuthorizationEndpointUris(
        [StringSyntax(StringSyntaxAttribute.Uri)] params string[] uris)
    {
        ArgumentNullException.ThrowIfNull(uris);

        return SetAuthorizationEndpointUris([.. uris.Select(uri => new Uri(uri, UriKind.RelativeOrAbsolute))]);
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the authorization endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetAuthorizationEndpointUris(params Uri[] uris)
    {
        ArgumentNullException.ThrowIfNull(uris);

        if (Array.Exists(uris, OpenIddictHelpers.IsImplicitFileUri))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0072), nameof(uris));
        }

        if (Array.Exists(uris, static uri => uri.OriginalString.StartsWith("~", StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException(SR.FormatID0081("~"), nameof(uris));
        }

        return Configure(options =>
        {
            options.AuthorizationEndpointUris.Clear();
            options.AuthorizationEndpointUris.AddRange(uris);
        });
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the configuration endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetConfigurationEndpointUris(
        [StringSyntax(StringSyntaxAttribute.Uri)] params string[] uris)
    {
        ArgumentNullException.ThrowIfNull(uris);

        return SetConfigurationEndpointUris([.. uris.Select(uri => new Uri(uri, UriKind.RelativeOrAbsolute))]);
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the configuration endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetConfigurationEndpointUris(params Uri[] uris)
    {
        ArgumentNullException.ThrowIfNull(uris);

        if (Array.Exists(uris, OpenIddictHelpers.IsImplicitFileUri))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0072), nameof(uris));
        }

        if (Array.Exists(uris, static uri => uri.OriginalString.StartsWith("~", StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException(SR.FormatID0081("~"), nameof(uris));
        }

        return Configure(options =>
        {
            options.ConfigurationEndpointUris.Clear();
            options.ConfigurationEndpointUris.AddRange(uris);
        });
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the device authorization endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetDeviceAuthorizationEndpointUris(
        [StringSyntax(StringSyntaxAttribute.Uri)] params string[] uris)
    {
        ArgumentNullException.ThrowIfNull(uris);

        return SetDeviceAuthorizationEndpointUris([.. uris.Select(uri => new Uri(uri, UriKind.RelativeOrAbsolute))]);
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the device authorization endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetDeviceAuthorizationEndpointUris(params Uri[] uris)
    {
        ArgumentNullException.ThrowIfNull(uris);

        if (Array.Exists(uris, OpenIddictHelpers.IsImplicitFileUri))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0072), nameof(uris));
        }

        if (Array.Exists(uris, static uri => uri.OriginalString.StartsWith("~", StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException(SR.FormatID0081("~"), nameof(uris));
        }

        return Configure(options =>
        {
            options.DeviceAuthorizationEndpointUris.Clear();
            options.DeviceAuthorizationEndpointUris.AddRange(uris);
        });
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the end session endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetEndSessionEndpointUris(
        [StringSyntax(StringSyntaxAttribute.Uri)] params string[] uris)
    {
        ArgumentNullException.ThrowIfNull(uris);

        return SetEndSessionEndpointUris([.. uris.Select(uri => new Uri(uri, UriKind.RelativeOrAbsolute))]);
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the end session endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetEndSessionEndpointUris(params Uri[] uris)
    {
        ArgumentNullException.ThrowIfNull(uris);

        if (Array.Exists(uris, OpenIddictHelpers.IsImplicitFileUri))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0072), nameof(uris));
        }

        if (Array.Exists(uris, static uri => uri.OriginalString.StartsWith("~", StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException(SR.FormatID0081("~"), nameof(uris));
        }

        return Configure(options =>
        {
            options.EndSessionEndpointUris.Clear();
            options.EndSessionEndpointUris.AddRange(uris);
        });
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the introspection endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetIntrospectionEndpointUris(
        [StringSyntax(StringSyntaxAttribute.Uri)] params string[] uris)
    {
        ArgumentNullException.ThrowIfNull(uris);

        return SetIntrospectionEndpointUris([.. uris.Select(uri => new Uri(uri, UriKind.RelativeOrAbsolute))]);
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the introspection endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetIntrospectionEndpointUris(params Uri[] uris)
    {
        ArgumentNullException.ThrowIfNull(uris);

        if (Array.Exists(uris, OpenIddictHelpers.IsImplicitFileUri))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0072), nameof(uris));
        }

        if (Array.Exists(uris, static uri => uri.OriginalString.StartsWith("~", StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException(SR.FormatID0081("~"), nameof(uris));
        }

        return Configure(options =>
        {
            options.IntrospectionEndpointUris.Clear();
            options.IntrospectionEndpointUris.AddRange(uris);
        });
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the JSON Web Key Set endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetJsonWebKeySetEndpointUris(
        [StringSyntax(StringSyntaxAttribute.Uri)] params string[] uris)
    {
        ArgumentNullException.ThrowIfNull(uris);

        return SetJsonWebKeySetEndpointUris([.. uris.Select(uri => new Uri(uri, UriKind.RelativeOrAbsolute))]);
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the JSON Web Key Set endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetJsonWebKeySetEndpointUris(params Uri[] uris)
    {
        ArgumentNullException.ThrowIfNull(uris);

        if (Array.Exists(uris, OpenIddictHelpers.IsImplicitFileUri))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0072), nameof(uris));
        }

        if (Array.Exists(uris, static uri => uri.OriginalString.StartsWith("~", StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException(SR.FormatID0081("~"), nameof(uris));
        }

        return Configure(options =>
        {
            options.JsonWebKeySetEndpointUris.Clear();
            options.JsonWebKeySetEndpointUris.AddRange(uris);
        });
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the pushed authorization endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetPushedAuthorizationEndpointUris(
        [StringSyntax(StringSyntaxAttribute.Uri)] params string[] uris)
    {
        ArgumentNullException.ThrowIfNull(uris);

        return SetPushedAuthorizationEndpointUris([.. uris.Select(uri => new Uri(uri, UriKind.RelativeOrAbsolute))]);
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the pushed authorization endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetPushedAuthorizationEndpointUris(params Uri[] uris)
    {
        ArgumentNullException.ThrowIfNull(uris);

        if (Array.Exists(uris, OpenIddictHelpers.IsImplicitFileUri))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0072), nameof(uris));
        }

        if (Array.Exists(uris, static uri => uri.OriginalString.StartsWith("~", StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException(SR.FormatID0081("~"), nameof(uris));
        }

        return Configure(options =>
        {
            options.PushedAuthorizationEndpointUris.Clear();
            options.PushedAuthorizationEndpointUris.AddRange(uris);
        });
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the revocation endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetRevocationEndpointUris(
        [StringSyntax(StringSyntaxAttribute.Uri)] params string[] uris)
    {
        ArgumentNullException.ThrowIfNull(uris);

        return SetRevocationEndpointUris([.. uris.Select(uri => new Uri(uri, UriKind.RelativeOrAbsolute))]);
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the revocation endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetRevocationEndpointUris(params Uri[] uris)
    {
        ArgumentNullException.ThrowIfNull(uris);

        if (Array.Exists(uris, OpenIddictHelpers.IsImplicitFileUri))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0072), nameof(uris));
        }

        if (Array.Exists(uris, static uri => uri.OriginalString.StartsWith("~", StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException(SR.FormatID0081("~"), nameof(uris));
        }

        return Configure(options =>
        {
            options.RevocationEndpointUris.Clear();
            options.RevocationEndpointUris.AddRange(uris);
        });
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the token endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetTokenEndpointUris(
        [StringSyntax(StringSyntaxAttribute.Uri)] params string[] uris)
    {
        ArgumentNullException.ThrowIfNull(uris);

        return SetTokenEndpointUris([.. uris.Select(uri => new Uri(uri, UriKind.RelativeOrAbsolute))]);
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the token endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetTokenEndpointUris(params Uri[] uris)
    {
        ArgumentNullException.ThrowIfNull(uris);

        if (Array.Exists(uris, OpenIddictHelpers.IsImplicitFileUri))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0072), nameof(uris));
        }

        if (Array.Exists(uris, static uri => uri.OriginalString.StartsWith("~", StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException(SR.FormatID0081("~"), nameof(uris));
        }

        return Configure(options =>
        {
            options.TokenEndpointUris.Clear();
            options.TokenEndpointUris.AddRange(uris);
        });
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the userinfo endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetUserInfoEndpointUris(
        [StringSyntax(StringSyntaxAttribute.Uri)] params string[] uris)
    {
        ArgumentNullException.ThrowIfNull(uris);

        return SetUserInfoEndpointUris([.. uris.Select(uri => new Uri(uri, UriKind.RelativeOrAbsolute))]);
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the userinfo endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned as part of the discovery document.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetUserInfoEndpointUris(params Uri[] uris)
    {
        ArgumentNullException.ThrowIfNull(uris);

        if (Array.Exists(uris, OpenIddictHelpers.IsImplicitFileUri))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0072), nameof(uris));
        }

        if (Array.Exists(uris, static uri => uri.OriginalString.StartsWith("~", StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException(SR.FormatID0081("~"), nameof(uris));
        }

        return Configure(options =>
        {
            options.UserInfoEndpointUris.Clear();
            options.UserInfoEndpointUris.AddRange(uris);
        });
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the end-user verification endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned by the device authorization endpoint.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetEndUserVerificationEndpointUris(
        [StringSyntax(StringSyntaxAttribute.Uri)] params string[] uris)
    {
        ArgumentNullException.ThrowIfNull(uris);

        return SetEndUserVerificationEndpointUris([.. uris.Select(uri => new Uri(uri, UriKind.RelativeOrAbsolute))]);
    }

    /// <summary>
    /// Sets the relative or absolute URIs associated to the end-user verification endpoint.
    /// If an empty array is specified, the endpoint will be considered disabled.
    /// Note: only the first URI will be returned by the device authorization endpoint.
    /// </summary>
    /// <param name="uris">The URIs associated to the endpoint.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetEndUserVerificationEndpointUris(params Uri[] uris)
    {
        ArgumentNullException.ThrowIfNull(uris);

        if (Array.Exists(uris, OpenIddictHelpers.IsImplicitFileUri))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0072), nameof(uris));
        }

        if (Array.Exists(uris, static uri => uri.OriginalString.StartsWith("~", StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException(SR.FormatID0081("~"), nameof(uris));
        }

        return Configure(options =>
        {
            options.EndUserVerificationEndpointUris.Clear();
            options.EndUserVerificationEndpointUris.AddRange(uris);
        });
    }

    /// <summary>
    /// Disables JWT access token encryption (this option doesn't affect Data Protection tokens).
    /// Disabling encryption is NOT recommended and SHOULD only be done when issuing tokens
    /// to third-party resource servers/APIs you don't control and don't fully trust.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder DisableAccessTokenEncryption()
        => Configure(options => options.DisableAccessTokenEncryption = true);

    /// <summary>
    /// Allows processing authorization and token requests that specify audiences that
    /// have not been registered using <see cref="RegisterAudiences(string[])"/>.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder DisableAudienceValidation()
        => Configure(options => options.DisableAudienceValidation = true);

    /// <summary>
    /// Disables authorization storage so that ad-hoc authorizations are
    /// not created when an authorization code or refresh token is issued
    /// and can't be revoked to prevent associated tokens from being used.
    /// Using this option is generally NOT recommended.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder DisableAuthorizationStorage()
        => Configure(options => options.DisableAuthorizationStorage = true);

    /// <summary>
    /// Allows processing authorization and token requests that specify resources that
    /// have not been registered using <see cref="RegisterResources(string[])"/>.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder DisableResourceValidation()
        => Configure(options => options.DisableResourceValidation = true);

    /// <summary>
    /// Configures OpenIddict to disable rolling refresh tokens so
    /// that refresh tokens used in a token request are not marked
    /// as redeemed and can still be used until they expire. Disabling
    /// rolling refresh tokens is NOT recommended, for security reasons.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder DisableRollingRefreshTokens()
        => Configure(options => options.DisableRollingRefreshTokens = true);

    /// <summary>
    /// Allows processing authorization and token requests that specify scopes that have not
    /// been registered using <see cref="RegisterScopes(string[])"/> or the scope manager.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder DisableScopeValidation()
        => Configure(options => options.DisableScopeValidation = true);

    /// <summary>
    /// Disables sliding expiration. When using this option, refresh tokens
    /// are issued with a fixed expiration date: when they expire, a complete
    /// authorization flow must be started to retrieve a new refresh token.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder DisableSlidingRefreshTokenExpiration()
        => Configure(options => options.DisableSlidingRefreshTokenExpiration = true);

    /// <summary>
    /// Disables token storage, so that no database entry is created
    /// for the tokens and codes returned by the OpenIddict server.
    /// Using this option is generally NOT recommended as it prevents
    /// the tokens and codes from being revoked (if needed).
    /// </summary>
    /// <remarks>
    /// Note: disabling token storage prevents the device authorization flow
    /// from being used and automatically turns sliding expiration off.
    /// </remarks>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder DisableTokenStorage()
        => Configure(options => options.DisableTokenStorage = true);

    /// <summary>
    /// Enables the degraded mode. When the degraded mode is enabled, all the security checks that
    /// depend on the OpenIddict core managers are disabled. This option MUST be enabled with extreme
    /// caution and custom handlers MUST be registered to properly validate OpenID Connect requests.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictServerBuilder EnableDegradedMode()
        => Configure(options => options.EnableDegradedMode = true);

    /// <summary>
    /// Disables audience permissions enforcement. Calling this method is NOT recommended.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder IgnoreAudiencePermissions()
        => Configure(options => options.IgnoreAudiencePermissions = true);

    /// <summary>
    /// Disables endpoint permissions enforcement. Calling this method is NOT recommended.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder IgnoreEndpointPermissions()
        => Configure(options => options.IgnoreEndpointPermissions = true);

    /// <summary>
    /// Disables grant type permissions enforcement. Calling this method is NOT recommended.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder IgnoreGrantTypePermissions()
        => Configure(options => options.IgnoreGrantTypePermissions = true);

    /// <summary>
    /// Disables resource permissions enforcement. Calling this method is NOT recommended.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder IgnoreResourcePermissions()
        => Configure(options => options.IgnoreResourcePermissions = true);

    /// <summary>
    /// Disables response type permissions enforcement. Calling this method is NOT recommended.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder IgnoreResponseTypePermissions()
        => Configure(options => options.IgnoreResponseTypePermissions = true);

    /// <summary>
    /// Disables scope permissions enforcement. Calling this method is NOT recommended.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder IgnoreScopePermissions()
        => Configure(options => options.IgnoreScopePermissions = true);

    /// <summary>
    /// Registers the specified audiences as supported audiences
    /// (exclusively used with the OAuth 2.0 Token Exchange flow).
    /// </summary>
    /// <param name="audiences">The supported audiences.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder RegisterAudiences(params string[] audiences)
    {
        ArgumentNullException.ThrowIfNull(audiences);

        if (Array.Exists(audiences, string.IsNullOrEmpty))
        {
            throw new ArgumentException(SR.FormatID0457(nameof(audiences)), nameof(audiences));
        }

        return Configure(options => options.Audiences.UnionWith(audiences));
    }

    /// <summary>
    /// Registers the specified claims as supported claims so
    /// they can be returned as part of the discovery document.
    /// </summary>
    /// <param name="claims">The supported claims.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder RegisterClaims(params string[] claims)
    {
        ArgumentNullException.ThrowIfNull(claims);

        if (Array.Exists(claims, string.IsNullOrEmpty))
        {
            throw new ArgumentException(SR.FormatID0457(nameof(claims)), nameof(claims));
        }

        return Configure(options => options.Claims.UnionWith(claims));
    }

    /// <summary>
    /// Registers the specified prompt values as supported scopes so
    /// they can be returned as part of the discovery document.
    /// </summary>
    /// <param name="values">The supported prompt values.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder RegisterPromptValues(params string[] values)
    {
        ArgumentNullException.ThrowIfNull(values);

        if (Array.Exists(values, string.IsNullOrEmpty))
        {
            throw new ArgumentException(SR.FormatID0457(nameof(values)), nameof(values));
        }

        return Configure(options => options.PromptValues.UnionWith(values));
    }

    /// <summary>
    /// Registers the specified resources as supported resources (typically used
    /// with the OAuth 2.0 Token Exchange flow and with authorization or pushed
    /// authorization requests that include one or more resource indicators).
    /// </summary>
    /// <param name="resources">The supported resources.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder RegisterResources(params string[] resources)
    {
        ArgumentNullException.ThrowIfNull(resources);

        return RegisterResources([.. resources.Select(resource => new Uri(resource, UriKind.Absolute))]);
    }

    /// <summary>
    /// Registers the specified resources as supported resources (typically used
    /// with the OAuth 2.0 Token Exchange flow and with authorization or pushed
    /// authorization requests that include one or more resource indicators).
    /// </summary>
    /// <param name="resources">The supported resources.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder RegisterResources(params Uri[] resources)
    {
        ArgumentNullException.ThrowIfNull(resources);

        if (Array.Exists(resources, static resource => OpenIddictHelpers.IsImplicitFileUri(resource) ||
            !string.IsNullOrEmpty(resource.Fragment)))
        {
            throw new ArgumentException(SR.FormatID0495(nameof(resources)), nameof(resources));
        }

        return Configure(options => options.Resources.UnionWith(resources));
    }

    /// <summary>
    /// Registers the specified scopes as supported scopes so
    /// they can be returned as part of the discovery document.
    /// </summary>
    /// <param name="scopes">The supported scopes.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder RegisterScopes(params string[] scopes)
    {
        ArgumentNullException.ThrowIfNull(scopes);

        if (Array.Exists(scopes, string.IsNullOrEmpty))
        {
            throw new ArgumentException(SR.FormatID0457(nameof(scopes)), nameof(scopes));
        }

        return Configure(options => options.Scopes.UnionWith(scopes));
    }

    /// <summary>
    /// Configures OpenIddict to force client applications to use Proof Key for Code Exchange
    /// (PKCE) when requesting an authorization code (e.g when using the code or hybrid flows).
    /// When enforced, authorization requests that lack the code_challenge parameter will be rejected.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder RequireProofKeyForCodeExchange()
        => Configure(options => options.RequireProofKeyForCodeExchange = true);

    /// <summary>
    /// Configures OpenIddict to force client applications to use pushed authorization requests
    /// when using an interactive flow like the authorization code or implicit flows.
    /// When enforced, authorization requests that lack the request_id parameter will be rejected.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder RequirePushedAuthorizationRequests()
        => Configure(options => options.RequirePushedAuthorizationRequests = true);

    /// <summary>
    /// Sets the access token lifetime, after which client applications must retrieve
    /// a new access token by making a grant_type=refresh_token token request
    /// or a prompt=none authorization request, depending on the selected flow.
    /// Using long-lived access tokens or tokens that never expire is not recommended.
    /// While discouraged, <see langword="null"/> can be specified to issue tokens that never expire.
    /// </summary>
    /// <param name="lifetime">The access token lifetime.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetAccessTokenLifetime(TimeSpan? lifetime)
        => Configure(options => options.AccessTokenLifetime = lifetime);

    /// <summary>
    /// Sets the authorization code lifetime, after which client applications
    /// are unable to send a grant_type=authorization_code token request.
    /// Using short-lived authorization codes is strongly recommended.
    /// While discouraged, <see langword="null"/> can be specified to issue codes that never expire.
    /// </summary>
    /// <param name="lifetime">The authorization code lifetime.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetAuthorizationCodeLifetime(TimeSpan? lifetime)
        => Configure(options => options.AuthorizationCodeLifetime = lifetime);

    /// <summary>
    /// Sets the device code lifetime, after which client applications are unable to
    /// send a grant_type=urn:ietf:params:oauth:grant-type:device_code token request.
    /// Using short-lived device codes is strongly recommended.
    /// While discouraged, <see langword="null"/> can be specified to issue codes that never expire.
    /// </summary>
    /// <param name="lifetime">The authorization code lifetime.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetDeviceCodeLifetime(TimeSpan? lifetime)
        => Configure(options => options.DeviceCodeLifetime = lifetime);

    /// <summary>
    /// Sets the identity token lifetime, after which client
    /// applications should refuse processing identity tokens.
    /// While discouraged, <see langword="null"/> can be specified to issue tokens that never expire.
    /// </summary>
    /// <param name="lifetime">The identity token lifetime.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetIdentityTokenLifetime(TimeSpan? lifetime)
        => Configure(options => options.IdentityTokenLifetime = lifetime);

    /// <summary>
    /// Sets the issued token lifetime, which is used as a fallback value when the
    /// issued token type isn't natively supported by OpenIddict (e.g an access token).
    /// While discouraged, <see langword="null"/> can be specified to issue tokens that never expire.
    /// </summary>
    /// <param name="lifetime">The issued token lifetime.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetIssuedTokenLifetime(TimeSpan? lifetime)
        => Configure(options => options.IssuedTokenLifetime = lifetime);

    /// <summary>
    /// Sets the refresh token lifetime, after which client applications must get
    /// a new authorization from the user. When sliding expiration is enabled,
    /// a new refresh token is always issued to the client application,
    /// which prolongs the validity period of the refresh token.
    /// While discouraged, <see langword="null"/> can be specified to issue tokens that never expire.
    /// </summary>
    /// <param name="lifetime">The refresh token lifetime.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetRefreshTokenLifetime(TimeSpan? lifetime)
        => Configure(options => options.RefreshTokenLifetime = lifetime);

    /// <summary>
    /// Sets the refresh token reuse leeway, during which rolling refresh tokens marked
    /// as redeemed can still be used to make concurrent refresh token requests.
    /// </summary>
    /// <param name="leeway">The refresh token reuse interval.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetRefreshTokenReuseLeeway(TimeSpan? leeway)
        => Configure(options => options.RefreshTokenReuseLeeway = leeway);

    /// <summary>
    /// Sets the charset used by OpenIddict to generate random user codes.
    /// </summary>
    /// <remarks>
    /// Note: user codes are meant to be entered manually by users. To ensure
    /// they remain easy enough to type even by users with non-Latin keyboards,
    /// user codes generated by OpenIddict only include ASCII digits by default.
    /// </remarks>
    /// <param name="charset">The charset used by OpenIddict to generate random user codes.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetUserCodeCharset(params string[] charset)
    {
        ArgumentNullException.ThrowIfNull(charset);
        ArgumentOutOfRangeException.ThrowIfLessThan(charset.Length, 9, nameof(charset));

        if (charset.Length != charset.Distinct(StringComparer.Ordinal).Count())
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0436), nameof(charset));
        }

        foreach (var character in charset)
        {
#if NET
            // On supported platforms, ensure each character added to the
            // charset represents exactly one grapheme cluster/text element.
            var enumerator = StringInfo.GetTextElementEnumerator(character);
            if (!enumerator.MoveNext() || enumerator.MoveNext())
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0437), nameof(charset));
            }
#else
            // On unsupported platforms, prevent non-ASCII characters from being used.
            if (character.Any(static character => (uint) character > '\x007f'))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0438), nameof(charset));
            }
#endif
        }

        return Configure(options =>
        {
            options.UserCodeCharset.Clear();
            options.UserCodeCharset.UnionWith(charset);
        });
    }

    /// <summary>
    /// Sets the format string used by OpenIddict to display user codes. While not recommended,
    /// a <see langword="null"/> value can be used to disable the user code formatting logic.
    /// </summary>
    /// <remarks>
    /// Note: if no value is explicitly set, a default format using dash separators
    /// is used to make user codes easier to read by the end users.
    /// </remarks>
    /// <param name="format">The string used by OpenIddict to format user codes.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictServerBuilder SetUserCodeDisplayFormat(string? format)
        => Configure(options => options.UserCodeDisplayFormat = format);

    /// <summary>
    /// Sets the length of the user codes generated by OpenIddict (by default, 12 characters).
    /// </summary>
    /// <param name="length">The length of the user codes generated by OpenIddict.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetUserCodeLength(int length)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(length, 6);

        return Configure(options => options.UserCodeLength = length);
    }

    /// <summary>
    /// Sets the user code lifetime, after which they'll no longer be considered valid.
    /// Using short-lived device codes is strongly recommended.
    /// While discouraged, <see langword="null"/> can be specified to issue codes that never expire.
    /// </summary>
    /// <param name="lifetime">The authorization code lifetime.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetUserCodeLifetime(TimeSpan? lifetime)
        => Configure(options => options.UserCodeLifetime = lifetime);

    /// <summary>
    /// Sets the issuer URI, which is used as the value of the "issuer" claim and
    /// is returned from the discovery endpoint to identify the authorization server.
    /// </summary>
    /// <param name="uri">The issuer URI.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetIssuer(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);

        return Configure(options => options.Issuer = uri);
    }

    /// <summary>
    /// Sets the issuer URI, which is used as the value of the "issuer" claim and
    /// is returned from the discovery endpoint to identify the authorization server.
    /// </summary>
    /// <param name="uri">The issuer URI.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetIssuer(
        [StringSyntax(StringSyntaxAttribute.Uri, UriKind.Absolute)] string uri)
    {
        ArgumentException.ThrowIfNullOrEmpty(uri);

        if (!Uri.TryCreate(uri, UriKind.Absolute, out Uri? value) || OpenIddictHelpers.IsImplicitFileUri(value))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0144), nameof(uri));
        }

        return SetIssuer(value);
    }

    /// <summary>
    /// Sets the URI listed as the mTLS device authorization
    /// endpoint alias in the server configuration metadata.
    /// </summary>
    /// <remarks>
    /// Note: this URI MUST be absolute and MUST point to a domain for
    /// which TLS client authentication is enforced by the web server.
    /// </remarks>
    /// <param name="uri">The endpoint URI.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetMtlsDeviceAuthorizationEndpointAliasUri(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);

        if (OpenIddictHelpers.IsImplicitFileUri(uri))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0072), nameof(uri));
        }

        if (uri.OriginalString.StartsWith("~", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(SR.FormatID0081("~"), nameof(uri));
        }

        return Configure(options => options.MtlsDeviceAuthorizationEndpointAliasUri = uri);
    }

    /// <summary>
    /// Sets the URI listed as the mTLS device authorization
    /// endpoint alias in the server configuration metadata.
    /// </summary>
    /// <remarks>
    /// Note: this URI MUST be absolute and MUST point to a domain for
    /// which TLS client authentication is enforced by the web server.
    /// </remarks>
    /// <param name="uri">The endpoint URI.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetMtlsDeviceAuthorizationEndpointAliasUri(
        [StringSyntax(StringSyntaxAttribute.Uri, UriKind.Absolute)] string uri)
    {
        ArgumentException.ThrowIfNullOrEmpty(uri);

        if (!Uri.TryCreate(uri, UriKind.Absolute, out Uri? value) || OpenIddictHelpers.IsImplicitFileUri(value))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0072), nameof(uri));
        }

        return SetMtlsDeviceAuthorizationEndpointAliasUri(value);
    }

    /// <summary>
    /// Sets the URI listed as the mTLS introspection
    /// endpoint alias in the server configuration metadata.
    /// </summary>
    /// <remarks>
    /// Note: this URI MUST be absolute and MUST point to a domain for
    /// which TLS client authentication is enforced by the web server.
    /// </remarks>
    /// <param name="uri">The endpoint URI.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetMtlsIntrospectionEndpointAliasUri(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);

        if (OpenIddictHelpers.IsImplicitFileUri(uri))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0072), nameof(uri));
        }

        if (uri.OriginalString.StartsWith("~", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(SR.FormatID0081("~"), nameof(uri));
        }

        return Configure(options => options.MtlsIntrospectionEndpointAliasUri = uri);
    }

    /// <summary>
    /// Sets the URI listed as the mTLS introspection endpoint
    /// alias in the server configuration metadata.
    /// </summary>
    /// <remarks>
    /// Note: this URI MUST be absolute and MUST point to a domain for
    /// which TLS client authentication is enforced by the web server.
    /// </remarks>
    /// <param name="uri">The endpoint URI.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetMtlsIntrospectionEndpointAliasUri(
        [StringSyntax(StringSyntaxAttribute.Uri, UriKind.Absolute)] string uri)
    {
        ArgumentException.ThrowIfNullOrEmpty(uri);

        if (!Uri.TryCreate(uri, UriKind.Absolute, out Uri? value) || OpenIddictHelpers.IsImplicitFileUri(value))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0072), nameof(uri));
        }

        return SetMtlsIntrospectionEndpointAliasUri(value);
    }

    /// <summary>
    /// Sets the URI listed as the mTLS pushed authorization
    /// endpoint alias in the server configuration metadata.
    /// </summary>
    /// <remarks>
    /// Note: this URI MUST be absolute and MUST point to a domain for
    /// which TLS client authentication is enforced by the web server.
    /// </remarks>
    /// <param name="uri">The endpoint URI.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetMtlsPushedAuthorizationEndpointAliasUri(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);

        if (OpenIddictHelpers.IsImplicitFileUri(uri))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0072), nameof(uri));
        }

        if (uri.OriginalString.StartsWith("~", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(SR.FormatID0081("~"), nameof(uri));
        }

        return Configure(options => options.MtlsPushedAuthorizationEndpointAliasUri = uri);
    }

    /// <summary>
    /// Sets the URI listed as the mTLS pushed authorization
    /// endpoint alias in the server configuration metadata.
    /// </summary>
    /// <remarks>
    /// Note: this URI MUST be absolute and MUST point to a domain for
    /// which TLS client authentication is enforced by the web server.
    /// </remarks>
    /// <param name="uri">The endpoint URI.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetMtlsPushedAuthorizationEndpointAliasUri(
        [StringSyntax(StringSyntaxAttribute.Uri, UriKind.Absolute)] string uri)
    {
        ArgumentException.ThrowIfNullOrEmpty(uri);

        if (!Uri.TryCreate(uri, UriKind.Absolute, out Uri? value) || OpenIddictHelpers.IsImplicitFileUri(value))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0072), nameof(uri));
        }

        return SetMtlsPushedAuthorizationEndpointAliasUri(value);
    }

    /// <summary>
    /// Sets the URI listed as the mTLS revocation endpoint
    /// alias in the server configuration metadata.
    /// </summary>
    /// <remarks>
    /// Note: this URI MUST be absolute and MUST point to a domain for
    /// which TLS client authentication is enforced by the web server.
    /// </remarks>
    /// <param name="uri">The endpoint URI.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetMtlsRevocationEndpointAliasUri(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);

        if (OpenIddictHelpers.IsImplicitFileUri(uri))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0072), nameof(uri));
        }

        if (uri.OriginalString.StartsWith("~", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(SR.FormatID0081("~"), nameof(uri));
        }

        return Configure(options => options.MtlsRevocationEndpointAliasUri = uri);
    }

    /// <summary>
    /// Sets the URI listed as the mTLS revocation endpoint
    /// alias in the server configuration metadata.
    /// </summary>
    /// <remarks>
    /// Note: this URI MUST be absolute and MUST point to a domain for
    /// which TLS client authentication is enforced by the web server.
    /// </remarks>
    /// <param name="uri">The endpoint URI.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetMtlsRevocationEndpointAliasUri(
        [StringSyntax(StringSyntaxAttribute.Uri, UriKind.Absolute)] string uri)
    {
        ArgumentException.ThrowIfNullOrEmpty(uri);

        if (!Uri.TryCreate(uri, UriKind.Absolute, out Uri? value) || OpenIddictHelpers.IsImplicitFileUri(value))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0072), nameof(uri));
        }

        return SetMtlsRevocationEndpointAliasUri(value);
    }

    /// <summary>
    /// Sets the URI listed as the mTLS token endpoint
    /// alias in the server configuration metadata.
    /// </summary>
    /// <remarks>
    /// Note: this URI MUST be absolute and MUST point to a domain for
    /// which TLS client authentication is enforced by the web server.
    /// </remarks>
    /// <param name="uri">The endpoint URI.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetMtlsTokenEndpointAliasUri(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);

        if (OpenIddictHelpers.IsImplicitFileUri(uri))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0072), nameof(uri));
        }

        if (uri.OriginalString.StartsWith("~", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(SR.FormatID0081("~"), nameof(uri));
        }

        return Configure(options => options.MtlsTokenEndpointAliasUri = uri);
    }

    /// <summary>
    /// Sets the URI listed as the mTLS token endpoint
    /// alias in the server configuration metadata.
    /// </summary>
    /// <remarks>
    /// Note: this URI MUST be absolute and MUST point to a domain for
    /// which TLS client authentication is enforced by the web server.
    /// </remarks>
    /// <param name="uri">The endpoint URI.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetMtlsTokenEndpointAliasUri(
        [StringSyntax(StringSyntaxAttribute.Uri, UriKind.Absolute)] string uri)
    {
        ArgumentException.ThrowIfNullOrEmpty(uri);

        if (!Uri.TryCreate(uri, UriKind.Absolute, out Uri? value) || OpenIddictHelpers.IsImplicitFileUri(value))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0072), nameof(uri));
        }

        return SetMtlsTokenEndpointAliasUri(value);
    }

    /// <summary>
    /// Sets the URI listed as the mTLS userinfo endpoint
    /// alias in the server configuration metadata.
    /// </summary>
    /// <remarks>
    /// Note: this URI MUST be absolute and MUST point to a domain for
    /// which TLS client authentication is enforced by the web server.
    /// </remarks>
    /// <param name="uri">The endpoint URI.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetMtlsUserInfoEndpointAliasUri(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);

        if (OpenIddictHelpers.IsImplicitFileUri(uri))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0072), nameof(uri));
        }

        if (uri.OriginalString.StartsWith("~", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(SR.FormatID0081("~"), nameof(uri));
        }

        return Configure(options => options.MtlsUserInfoEndpointAliasUri = uri);
    }

    /// <summary>
    /// Sets the URI listed as the mTLS userinfo endpoint
    /// alias in the server configuration metadata.
    /// </summary>
    /// <remarks>
    /// Note: this URI MUST be absolute and MUST point to a domain for
    /// which TLS client authentication is enforced by the web server.
    /// </remarks>
    /// <param name="uri">The endpoint URI.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder SetMtlsUserInfoEndpointAliasUri(
        [StringSyntax(StringSyntaxAttribute.Uri, UriKind.Absolute)] string uri)
    {
        ArgumentException.ThrowIfNullOrEmpty(uri);

        if (!Uri.TryCreate(uri, UriKind.Absolute, out Uri? value) || OpenIddictHelpers.IsImplicitFileUri(value))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0072), nameof(uri));
        }

        return SetMtlsUserInfoEndpointAliasUri(value);
    }

    /// <summary>
    /// Configures OpenIddict to use reference tokens, so that the access token payloads
    /// are stored in the database (only an identifier is returned to the client application).
    /// Enabling this option is useful when storing a very large number of claims in the tokens,
    /// but it is RECOMMENDED to enable column encryption in the database or use the ASP.NET Core
    /// Data Protection integration, that provides additional protection against token leakage.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder UseReferenceAccessTokens()
        => Configure(options => options.UseReferenceAccessTokens = true);

    /// <summary>
    /// Configures OpenIddict to use reference tokens, so that the refresh token payloads
    /// are stored in the database (only an identifier is returned to the client application).
    /// Enabling this option is useful when storing a very large number of claims in the tokens,
    /// but it is RECOMMENDED to enable column encryption in the database or use the ASP.NET Core
    /// Data Protection integration, that provides additional protection against token leakage.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder UseReferenceRefreshTokens()
        => Configure(options => options.UseReferenceRefreshTokens = true);

    /// <summary>
    /// Configures OpenIddict to bind access tokens to the client certificates client certificate
    /// sent by public or confidential clients in the TLS handshake of token requests.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder UseClientCertificateBoundAccessTokens()
        => Configure(options => options.UseClientCertificateBoundAccessTokens = true);

    /// <summary>
    /// Configures OpenIddict to bind refresh tokens to the client certificates client
    /// certificate sent by public clients in the TLS handshake of token requests.
    /// </summary>
    /// <remarks>
    /// Note: refresh tokens are only bound to the client certificate when the client
    /// is a public application, as refresh tokens issued to confidential applications
    /// are already sender-constrained via standard client authentication.
    /// </remarks>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder UseClientCertificateBoundRefreshTokens()
        => Configure(options => options.UseClientCertificateBoundRefreshTokens = true);

    /// <summary>
    /// Enables authorization request storage, so that authorization requests
    /// are automatically stored in the token store, which allows flowing
    /// large payloads across requests. Enabling this option can be useful
    /// for clients that do not supported pushed authorization requests.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder EnableAuthorizationRequestCaching()
        => Configure(options => options.EnableAuthorizationRequestCaching = true);

    /// <summary>
    /// Enables end session request storage, so that end session requests
    /// are automatically stored in the token store, which allows flowing
    /// large payloads across requests.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder EnableEndSessionRequestCaching()
        => Configure(options => options.EnableEndSessionRequestCaching = true);

    /// <summary>
    /// Configures OpenIddict to enable PKI client certificate authentication (mTLS) and trust
    /// the specified root and intermediate certificates when validating client certificates.
    /// </summary>
    /// <param name="certificates">The store containing the root and intermediate certificates to trust.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictServerBuilder EnablePublicKeyInfrastructureTlsClientAuthentication(X509Certificate2Collection certificates)
        => EnablePublicKeyInfrastructureTlsClientAuthentication(certificates, static policy => { });

    /// <summary>
    /// Configures OpenIddict to enable PKI client certificate authentication (mTLS) and trust
    /// the specified root and intermediate certificates when validating client certificates.
    /// </summary>
    /// <param name="certificates">The store containing the root and intermediate certificates to trust.</param>
    /// <param name="configuration">The delegate used to amend the created X.509 chain policy.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictServerBuilder EnablePublicKeyInfrastructureTlsClientAuthentication(
        X509Certificate2Collection certificates, Action<X509ChainPolicy> configuration)
    {
        ArgumentNullException.ThrowIfNull(certificates);
        ArgumentNullException.ThrowIfNull(configuration);

#if NET
        // Ensure at least one root certificate authority was included in the certificate collection.
        if (!certificates.Cast<X509Certificate2>().Any(static certificate =>
            OpenIddictHelpers.IsCertificateAuthority(certificate) &&
            OpenIddictHelpers.HasKeyUsage(certificate, X509KeyUsageFlags.KeyCertSign) &&
            OpenIddictHelpers.IsSelfIssuedCertificate(certificate)))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0507), nameof(certificates));
        }

        // Ensure no end certificate was included in the certificate collection.
        if (certificates.Cast<X509Certificate2>().Any(static certificate =>
            !OpenIddictHelpers.IsCertificateAuthority(certificate) ||
            !OpenIddictHelpers.HasKeyUsage(certificate, X509KeyUsageFlags.KeyCertSign)))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0501), nameof(certificates));
        }

        // Ensure none of the certificates contains a private key.
        if (certificates.Cast<X509Certificate2>().Any(static certificate => certificate.HasPrivateKey))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0511), nameof(certificates));
        }

        var policy = new X509ChainPolicy
        {
            // Note: by default, OpenIddict requires that end certificates used for TLS client
            // authentication explicitly list client authentication as an allowed extended key usage.
            ApplicationPolicy = { new Oid(ObjectIdentifiers.ExtendedKeyUsages.ClientAuthentication) },
            TrustMode = X509ChainTrustMode.CustomRootTrust
        };

        policy.CustomTrustStore.AddRange(certificates);

        // If one of the root certificates doesn't include a CRL or AIA
        // extension, ignore root revocation unknown status errors by default.
        if (certificates.Cast<X509Certificate2>()
            .Where(static certificate =>
                OpenIddictHelpers.IsCertificateAuthority(certificate) &&
                OpenIddictHelpers.HasKeyUsage(certificate, X509KeyUsageFlags.KeyCertSign) &&
                OpenIddictHelpers.IsSelfIssuedCertificate(certificate))
            .Any(static certificate =>
                certificate.Extensions[ObjectIdentifiers.CertificateExtensions.CrlDistributionPoints] is null &&
                certificate.Extensions[ObjectIdentifiers.CertificateExtensions.AuthorityInfoAccess]   is null))
        {
            policy.VerificationFlags |= X509VerificationFlags.IgnoreRootRevocationUnknown;
        }

        // If one of the intermediate certificates doesn't include a CRL or AIA
        // extension, ignore root revocation unknown status errors by default.
        if (certificates.Cast<X509Certificate2>()
            .Where(static certificate =>
                OpenIddictHelpers.IsCertificateAuthority(certificate) &&
                OpenIddictHelpers.HasKeyUsage(certificate, X509KeyUsageFlags.KeyCertSign) &&
               !OpenIddictHelpers.IsSelfIssuedCertificate(certificate))
            .Any(static certificate =>
                certificate.Extensions[ObjectIdentifiers.CertificateExtensions.CrlDistributionPoints] is null &&
                certificate.Extensions[ObjectIdentifiers.CertificateExtensions.AuthorityInfoAccess]   is null))
        {
            policy.VerificationFlags |= X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown;
        }

        // If the root or intermediate certificates doesn't include a CRL or AIA, assume
        // by default that the end certificates won't have a CRL or AIA extension either.
        if (certificates.Cast<X509Certificate2>()
            .Where(static certificate =>
                OpenIddictHelpers.IsCertificateAuthority(certificate) &&
                OpenIddictHelpers.HasKeyUsage(certificate, X509KeyUsageFlags.KeyCertSign))
            .Any(static certificate =>
                certificate.Extensions[ObjectIdentifiers.CertificateExtensions.CrlDistributionPoints] is null &&
                certificate.Extensions[ObjectIdentifiers.CertificateExtensions.AuthorityInfoAccess]   is null))
        {
            policy.VerificationFlags |= X509VerificationFlags.IgnoreEndRevocationUnknown;
        }

        // Run the user-provided configuration delegate and ensure the trust mode wasn't accidentally changed to
        // prevent spoofing attacks (i.e attacks that consist in using a client certificate issued by a certificate
        // authority trusted by the operating system but that isn't the one expected by the authorization server
        // for client authentication). While discouraged, applications that need to use the system root store
        // (e.g applications running on .NET Framework) can manually attach a custom policy to the server options.
        configuration(policy);

        if (policy.TrustMode is not X509ChainTrustMode.CustomRootTrust)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0509));
        }

        return Configure(options => options.PublicKeyInfrastructureTlsClientAuthenticationPolicy = policy);
#else
        throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0508));
#endif
    }

    /// <summary>
    /// Configures OpenIddict to enable self-signed TLS client authentication (mTLS).
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictServerBuilder EnableSelfSignedTlsClientAuthentication()
        => EnableSelfSignedTlsClientAuthentication(static policy => { });

    /// <summary>
    /// Configures OpenIddict to enable self-signed TLS client authentication (mTLS).
    /// </summary>
    /// <param name="configuration">The delegate used to amend the created X.509 chain policy.</param>
    /// <returns>The <see cref="OpenIddictServerBuilder"/> instance.</returns>
    public OpenIddictServerBuilder EnableSelfSignedTlsClientAuthentication(Action<X509ChainPolicy> configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

#if NET
        var policy = new X509ChainPolicy
        {
            // Note: by default, OpenIddict requires that end certificates used for TLS client
            // authentication explicitly list client authentication as an allowed extended key usage.
            ApplicationPolicy = { new Oid(ObjectIdentifiers.ExtendedKeyUsages.ClientAuthentication) },
            // Note: self-signed TLS client certificates typically do not include revocation information
            // (CRL or AIA) and are "revoked" by simply being removed from the JSON Web Key Set.
            RevocationMode = X509RevocationMode.NoCheck,
            TrustMode = X509ChainTrustMode.CustomRootTrust
        };

        // Run the user-provided configuration delegate and ensure the trust mode wasn't accidentally changed to
        // prevent spoofing attacks (i.e attacks that consist in using a client certificate issued by a certificate
        // authority trusted by the operating system but that isn't the one expected by the authorization server
        // for client authentication). While discouraged, applications that need to use the system root store
        // (e.g applications running on .NET Framework) can manually attach a custom policy to the server options.
        configuration(policy);

        if (policy.TrustMode is not X509ChainTrustMode.CustomRootTrust)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0509));
        }

        return Configure(options => options.SelfSignedTlsClientAuthenticationPolicy = policy);
#else
        throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0508));
#endif
    }

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals(object? obj) => base.Equals(obj);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => base.GetHashCode();

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override string? ToString() => base.ToString();
}
