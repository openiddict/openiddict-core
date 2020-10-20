/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;
using static OpenIddict.Abstractions.OpenIddictConstants;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Exposes the necessary methods required to configure the OpenIddict server services.
    /// </summary>
    public class OpenIddictServerBuilder
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
        /// Registers an event handler using the specified configuration delegate.
        /// </summary>
        /// <typeparam name="TContext">The event context type.</typeparam>
        /// <param name="configuration">The configuration delegate.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public OpenIddictServerBuilder AddEventHandler<TContext>(
            Action<OpenIddictServerHandlerDescriptor.Builder<TContext>> configuration)
            where TContext : OpenIddictServerEvents.BaseContext
        {
            if (configuration is null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

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
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public OpenIddictServerBuilder AddEventHandler(OpenIddictServerHandlerDescriptor descriptor)
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
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public OpenIddictServerBuilder RemoveEventHandler(OpenIddictServerHandlerDescriptor descriptor)
        {
            if (descriptor is null)
            {
                throw new ArgumentNullException(nameof(descriptor));
            }

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
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder Configure(Action<OpenIddictServerOptions> configuration)
        {
            if (configuration is null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            Services.Configure(configuration);

            return this;
        }

        /// <summary>
        /// Makes client identification optional so that token, introspection and revocation
        /// requests that don't specify a client_id are not automatically rejected.
        /// Enabling this option is NOT recommended.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AcceptAnonymousClients()
            => Configure(options => options.AcceptAnonymousClients = true);

        /// <summary>
        /// Registers encryption credentials.
        /// </summary>
        /// <param name="credentials">The encrypting credentials.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AddEncryptionCredentials(EncryptingCredentials credentials)
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
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AddEncryptionKey(SecurityKey key)
        {
            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            // If the encryption key is an asymmetric security key, ensure it has a private key.
            if (key is AsymmetricSecurityKey asymmetricSecurityKey &&
                asymmetricSecurityKey.PrivateKeyStatus == PrivateKeyStatus.DoesNotExist)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0055));
            }

            if (key.IsSupportedAlgorithm(SecurityAlgorithms.Aes256KW))
            {
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
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AddDevelopmentEncryptionCertificate()
            => AddDevelopmentEncryptionCertificate(new X500DistinguishedName("CN=OpenIddict Server Encryption Certificate"));

        /// <summary>
        /// Registers (and generates if necessary) a user-specific development encryption certificate.
        /// </summary>
        /// <param name="subject">The subject name associated with the certificate.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
            Justification = "The X.509 certificate is attached to the server options.")]
        public OpenIddictServerBuilder AddDevelopmentEncryptionCertificate(X500DistinguishedName subject)
        {
            if (subject is null)
            {
                throw new ArgumentNullException(nameof(subject));
            }

            using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);

            // Try to retrieve the development certificate from the specified store.
            // If a certificate was found but is not yet or no longer valid, remove it
            // from the store before creating and persisting a new encryption certificate.
            var certificate = store.Certificates.Find(X509FindType.FindBySubjectDistinguishedName, subject.Name, validOnly: false)
                .OfType<X509Certificate2>()
                .SingleOrDefault();

            if (certificate is not null && (certificate.NotBefore > DateTime.Now || certificate.NotAfter < DateTime.Now))
            {
                store.Remove(certificate);
                certificate = null;
            }

#if SUPPORTS_CERTIFICATE_GENERATION
            // If no appropriate certificate can be found, generate and persist a new certificate in the specified store.
            if (certificate is null)
            {
                using var algorithm = RSA.Create(keySizeInBits: 2048);

                var request = new CertificateRequest(subject, algorithm, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyEncipherment, critical: true));

                certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(2));

                // Note: setting the friendly name is not supported on Unix machines (including Linux and macOS).
                // To ensure an exception is not thrown by the property setter, an OS runtime check is used here.
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
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
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                    {
                        flags |= X509KeyStorageFlags.Exportable;
                    }

                    certificate = new X509Certificate2(data, string.Empty, flags);
                }

                finally
                {
                    Array.Clear(data, 0, data.Length);
                }

                store.Add(certificate);
            }

            return AddEncryptionCertificate(certificate);
#else
            throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0264));
#endif
        }

        /// <summary>
        /// Registers a new ephemeral encryption key. Ephemeral encryption keys are automatically
        /// discarded when the application shuts down and payloads encrypted using this key are
        /// automatically invalidated. This method should only be used during development.
        /// On production, using a X.509 certificate stored in the machine store is recommended.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AddEphemeralEncryptionKey()
            => AddEphemeralEncryptionKey(SecurityAlgorithms.RsaOAEP);

        /// <summary>
        /// Registers a new ephemeral encryption key. Ephemeral encryption keys are automatically
        /// discarded when the application shuts down and payloads encrypted using this key are
        /// automatically invalidated. This method should only be used during development.
        /// On production, using a X.509 certificate stored in the machine store is recommended.
        /// </summary>
        /// <param name="algorithm">The algorithm associated with the encryption key.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AddEphemeralEncryptionKey(string algorithm)
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

                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0058)),
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
                Justification = "The generated RSA key is attached to the server options.")]
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
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AddEncryptionCertificate(X509Certificate2 certificate)
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
                if (extensions.Count != 0 && !extensions.Any(extension => extension.KeyUsages.HasFlag(X509KeyUsageFlags.KeyEncipherment)))
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
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AddEncryptionCertificate(Assembly assembly, string resource, string password)
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
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AddEncryptionCertificate(
            Assembly assembly, string resource,
            string password, X509KeyStorageFlags flags)
        {
            if (assembly is null)
            {
                throw new ArgumentNullException(nameof(assembly));
            }

            if (string.IsNullOrEmpty(resource))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0062), nameof(resource));
            }

            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0063), nameof(password));
            }

            using var stream = assembly.GetManifestResourceStream(resource);
            if (stream is null)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0064));
            }

            return AddEncryptionCertificate(stream, password, flags);
        }

        /// <summary>
        /// Registers an encryption certificate extracted from a stream.
        /// </summary>
        /// <param name="stream">The stream containing the certificate.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AddEncryptionCertificate(Stream stream, string password)
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
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
            Justification = "The X.509 certificate is attached to the server options.")]
        public OpenIddictServerBuilder AddEncryptionCertificate(Stream stream, string password, X509KeyStorageFlags flags)
        {
            if (stream is null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0063), nameof(password));
            }

            using var buffer = new MemoryStream();
            stream.CopyTo(buffer);

            return AddEncryptionCertificate(new X509Certificate2(buffer.ToArray(), password, flags));
        }

        /// <summary>
        /// Registers an encryption certificate retrieved from the X.509 user or machine store.
        /// </summary>
        /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X.509 store.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AddEncryptionCertificate(string thumbprint)
        {
            if (string.IsNullOrEmpty(thumbprint))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0065), nameof(thumbprint));
            }

            var certificate = GetCertificate(StoreLocation.CurrentUser, thumbprint) ?? GetCertificate(StoreLocation.LocalMachine, thumbprint);
            if (certificate is null)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0066));
            }

            return AddEncryptionCertificate(certificate);

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
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AddEncryptionCertificate(string thumbprint, StoreName name, StoreLocation location)
        {
            if (string.IsNullOrEmpty(thumbprint))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0065), nameof(thumbprint));
            }

            using var store = new X509Store(name, location);
            store.Open(OpenFlags.ReadOnly);

            var certificate = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false)
                .OfType<X509Certificate2>()
                .SingleOrDefault();

            if (certificate is null)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0066));
            }

            return AddEncryptionCertificate(certificate);
        }

        /// <summary>
        /// Registers signing credentials.
        /// </summary>
        /// <param name="credentials">The signing credentials.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AddSigningCredentials(SigningCredentials credentials)
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
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AddSigningKey(SecurityKey key)
        {
            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            // If the signing key is an asymmetric security key, ensure it has a private key.
            if (key is AsymmetricSecurityKey asymmetricSecurityKey &&
                asymmetricSecurityKey.PrivateKeyStatus == PrivateKeyStatus.DoesNotExist)
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
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AddDevelopmentSigningCertificate()
            => AddDevelopmentSigningCertificate(new X500DistinguishedName("CN=OpenIddict Server Signing Certificate"));

        /// <summary>
        /// Registers (and generates if necessary) a user-specific development signing certificate.
        /// </summary>
        /// <param name="subject">The subject name associated with the certificate.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
            Justification = "The X.509 certificate is attached to the server options.")]
        public OpenIddictServerBuilder AddDevelopmentSigningCertificate(X500DistinguishedName subject)
        {
            if (subject is null)
            {
                throw new ArgumentNullException(nameof(subject));
            }

            using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);

            // Try to retrieve the development certificate from the specified store.
            // If a certificate was found but is not yet or no longer valid, remove it
            // from the store before creating and persisting a new signing certificate.
            var certificate = store.Certificates.Find(X509FindType.FindBySubjectDistinguishedName, subject.Name, validOnly: false)
                .OfType<X509Certificate2>()
                .SingleOrDefault();

            if (certificate is not null && (certificate.NotBefore > DateTime.Now || certificate.NotAfter < DateTime.Now))
            {
                store.Remove(certificate);
                certificate = null;
            }

#if SUPPORTS_CERTIFICATE_GENERATION
            // If no appropriate certificate can be found, generate and persist a new certificate in the specified store.
            if (certificate is null)
            {
                using var algorithm = RSA.Create(keySizeInBits: 2048);

                var request = new CertificateRequest(subject, algorithm, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));

                certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(2));

                // Note: setting the friendly name is not supported on Unix machines (including Linux and macOS).
                // To ensure an exception is not thrown by the property setter, an OS runtime check is used here.
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
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
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                    {
                        flags |= X509KeyStorageFlags.Exportable;
                    }

                    certificate = new X509Certificate2(data, string.Empty, flags);
                }

                finally
                {
                    Array.Clear(data, 0, data.Length);
                }

                store.Add(certificate);
            }

            return AddSigningCertificate(certificate);
#else
            throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0264));
#endif
        }

        /// <summary>
        /// Registers a new ephemeral signing key. Ephemeral signing keys are automatically
        /// discarded when the application shuts down and payloads signed using this key are
        /// automatically invalidated. This method should only be used during development.
        /// On production, using a X.509 certificate stored in the machine store is recommended.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AddEphemeralSigningKey()
            => AddEphemeralSigningKey(SecurityAlgorithms.RsaSha256);

        /// <summary>
        /// Registers a new ephemeral signing key. Ephemeral signing keys are automatically
        /// discarded when the application shuts down and payloads signed using this key are
        /// automatically invalidated. This method should only be used during development.
        /// On production, using a X.509 certificate stored in the machine store is recommended.
        /// </summary>
        /// <param name="algorithm">The algorithm associated with the signing key.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
            Justification = "The X.509 certificate is attached to the server options.")]
        public OpenIddictServerBuilder AddEphemeralSigningKey(string algorithm)
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

                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0058)),
            };

            [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
                Justification = "The generated RSA key is attached to the server options.")]
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
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AddSigningCertificate(X509Certificate2 certificate)
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
                if (extensions.Count != 0 && !extensions.Any(extension => extension.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature)))
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
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AddSigningCertificate(Assembly assembly, string resource, string password)
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
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AddSigningCertificate(
            Assembly assembly, string resource,
            string password, X509KeyStorageFlags flags)
        {
            if (assembly is null)
            {
                throw new ArgumentNullException(nameof(assembly));
            }

            if (string.IsNullOrEmpty(resource))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0062), nameof(resource));
            }

            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0063), nameof(password));
            }

            using var stream = assembly.GetManifestResourceStream(resource);
            if (stream is null)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0064));
            }

            return AddSigningCertificate(stream, password, flags);
        }

        /// <summary>
        /// Registers a signing certificate extracted from a stream.
        /// </summary>
        /// <param name="stream">The stream containing the certificate.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AddSigningCertificate(Stream stream, string password)
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
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
            Justification = "The X.509 certificate is attached to the server options.")]
        public OpenIddictServerBuilder AddSigningCertificate(Stream stream, string password, X509KeyStorageFlags flags)
        {
            if (stream is null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0063), nameof(password));
            }

            using var buffer = new MemoryStream();
            stream.CopyTo(buffer);

            return AddSigningCertificate(new X509Certificate2(buffer.ToArray(), password, flags));
        }

        /// <summary>
        /// Registers a signing certificate retrieved from the X.509 user or machine store.
        /// </summary>
        /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X.509 store.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AddSigningCertificate(string thumbprint)
        {
            if (string.IsNullOrEmpty(thumbprint))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0065), nameof(thumbprint));
            }

            var certificate = GetCertificate(StoreLocation.CurrentUser, thumbprint) ?? GetCertificate(StoreLocation.LocalMachine, thumbprint);
            if (certificate is null)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0066));
            }

            return AddSigningCertificate(certificate);

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
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AddSigningCertificate(string thumbprint, StoreName name, StoreLocation location)
        {
            if (string.IsNullOrEmpty(thumbprint))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0065), nameof(thumbprint));
            }

            using var store = new X509Store(name, location);
            store.Open(OpenFlags.ReadOnly);

            var certificate = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false)
                .OfType<X509Certificate2>()
                .SingleOrDefault();

            if (certificate is null)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0066));
            }

            return AddSigningCertificate(certificate);
        }

        /// <summary>
        /// Enables authorization code flow support. For more information
        /// about this specific OAuth 2.0/OpenID Connect flow, visit
        /// https://tools.ietf.org/html/rfc6749#section-4.1 and
        /// http://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AllowAuthorizationCodeFlow()
            => Configure(options =>
            {
                options.CodeChallengeMethods.Add(CodeChallengeMethods.Sha256);

                options.GrantTypes.Add(GrantTypes.AuthorizationCode);

                options.ResponseModes.Add(ResponseModes.FormPost);
                options.ResponseModes.Add(ResponseModes.Fragment);
                options.ResponseModes.Add(ResponseModes.Query);

                options.ResponseTypes.Add(ResponseTypes.Code);
            });

        /// <summary>
        /// Enables client credentials flow support. For more information about this
        /// specific OAuth 2.0 flow, visit https://tools.ietf.org/html/rfc6749#section-4.4.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AllowClientCredentialsFlow()
            => Configure(options => options.GrantTypes.Add(GrantTypes.ClientCredentials));

        /// <summary>
        /// Enables custom grant type support.
        /// </summary>
        /// <param name="type">The grant type associated with the flow.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AllowCustomFlow(string type)
        {
            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0071), nameof(type));
            }

            return Configure(options => options.GrantTypes.Add(type));
        }

        /// <summary>
        /// Enables device code flow support. For more information about this
        /// specific OAuth 2.0 flow, visit https://tools.ietf.org/html/rfc8628.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AllowDeviceCodeFlow()
            => Configure(options => options.GrantTypes.Add(GrantTypes.DeviceCode));

        /// <summary>
        /// Enables hybrid flow support. For more information
        /// about this specific OpenID Connect flow, visit
        /// http://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AllowHybridFlow()
            => Configure(options =>
            {
                options.CodeChallengeMethods.Add(CodeChallengeMethods.Sha256);

                options.GrantTypes.Add(GrantTypes.AuthorizationCode);
                options.GrantTypes.Add(GrantTypes.Implicit);

                options.ResponseModes.Add(ResponseModes.FormPost);
                options.ResponseModes.Add(ResponseModes.Fragment);

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
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AllowImplicitFlow()
            => Configure(options =>
            {
                options.GrantTypes.Add(GrantTypes.Implicit);

                options.ResponseModes.Add(ResponseModes.FormPost);
                options.ResponseModes.Add(ResponseModes.Fragment);

                options.ResponseTypes.Add(ResponseTypes.IdToken);
                options.ResponseTypes.Add(ResponseTypes.IdToken + ' ' + ResponseTypes.Token);
                options.ResponseTypes.Add(ResponseTypes.Token);
            });

        /// <summary>
        /// Enables none flow support. For more information about this specific OAuth 2.0 flow,
        /// visit https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#none.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AllowNoneFlow()
            => Configure(options => options.ResponseTypes.Add(ResponseTypes.None));

        /// <summary>
        /// Enables password flow support. For more information about this specific
        /// OAuth 2.0 flow, visit https://tools.ietf.org/html/rfc6749#section-4.3.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AllowPasswordFlow()
            => Configure(options => options.GrantTypes.Add(GrantTypes.Password));

        /// <summary>
        /// Enables refresh token flow support. For more information about this
        /// specific OAuth 2.0 flow, visit https://tools.ietf.org/html/rfc6749#section-6.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AllowRefreshTokenFlow()
            => Configure(options =>
            {
                options.GrantTypes.Add(GrantTypes.RefreshToken);

                options.Scopes.Add(Scopes.OfflineAccess);
            });

        /// <summary>
        /// Sets the relative or absolute URLs associated to the authorization endpoint.
        /// If an empty array is specified, the endpoint will be considered disabled.
        /// Note: only the first address will be returned as part of the discovery document.
        /// </summary>
        /// <param name="addresses">The addresses associated to the endpoint.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder SetAuthorizationEndpointUris(params string[] addresses)
        {
            if (addresses is null)
            {
                throw new ArgumentNullException(nameof(addresses));
            }

            return SetAuthorizationEndpointUris(addresses.Select(address => new Uri(address, UriKind.RelativeOrAbsolute)).ToArray());
        }

        /// <summary>
        /// Sets the relative or absolute URLs associated to the authorization endpoint.
        /// If an empty array is specified, the endpoint will be considered disabled.
        /// Note: only the first address will be returned as part of the discovery document.
        /// </summary>
        /// <param name="addresses">The addresses associated to the endpoint.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder SetAuthorizationEndpointUris(params Uri[] addresses)
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
                options.AuthorizationEndpointUris.Clear();
                options.AuthorizationEndpointUris.AddRange(addresses);
            });
        }

        /// <summary>
        /// Sets the relative or absolute URLs associated to the configuration endpoint.
        /// If an empty array is specified, the endpoint will be considered disabled.
        /// Note: only the first address will be returned as part of the discovery document.
        /// </summary>
        /// <param name="addresses">The addresses associated to the endpoint.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder SetConfigurationEndpointUris(params string[] addresses)
        {
            if (addresses is null)
            {
                throw new ArgumentNullException(nameof(addresses));
            }

            return SetConfigurationEndpointUris(addresses.Select(address => new Uri(address, UriKind.RelativeOrAbsolute)).ToArray());
        }

        /// <summary>
        /// Sets the relative or absolute URLs associated to the configuration endpoint.
        /// If an empty array is specified, the endpoint will be considered disabled.
        /// Note: only the first address will be returned as part of the discovery document.
        /// </summary>
        /// <param name="addresses">The addresses associated to the endpoint.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder SetConfigurationEndpointUris(params Uri[] addresses)
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
                options.ConfigurationEndpointUris.Clear();
                options.ConfigurationEndpointUris.AddRange(addresses);
            });
        }

        /// <summary>
        /// Sets the relative or absolute URLs associated to the cryptography endpoint.
        /// If an empty array is specified, the endpoint will be considered disabled.
        /// Note: only the first address will be returned as part of the discovery document.
        /// </summary>
        /// <param name="addresses">The addresses associated to the endpoint.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder SetCryptographyEndpointUris(params string[] addresses)
        {
            if (addresses is null)
            {
                throw new ArgumentNullException(nameof(addresses));
            }

            return SetCryptographyEndpointUris(addresses.Select(address => new Uri(address, UriKind.RelativeOrAbsolute)).ToArray());
        }

        /// <summary>
        /// Sets the relative or absolute URLs associated to the cryptography endpoint.
        /// If an empty array is specified, the endpoint will be considered disabled.
        /// Note: only the first address will be returned as part of the discovery document.
        /// </summary>
        /// <param name="addresses">The addresses associated to the endpoint.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder SetCryptographyEndpointUris(params Uri[] addresses)
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
                options.CryptographyEndpointUris.Clear();
                options.CryptographyEndpointUris.AddRange(addresses);
            });
        }

        /// <summary>
        /// Sets the relative or absolute URLs associated to the device endpoint.
        /// If an empty array is specified, the endpoint will be considered disabled.
        /// Note: only the first address will be returned as part of the discovery document.
        /// </summary>
        /// <param name="addresses">The addresses associated to the endpoint.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder SetDeviceEndpointUris(params string[] addresses)
        {
            if (addresses is null)
            {
                throw new ArgumentNullException(nameof(addresses));
            }

            return SetDeviceEndpointUris(addresses.Select(address => new Uri(address, UriKind.RelativeOrAbsolute)).ToArray());
        }

        /// <summary>
        /// Sets the relative or absolute URLs associated to the device endpoint.
        /// If an empty array is specified, the endpoint will be considered disabled.
        /// Note: only the first address will be returned as part of the discovery document.
        /// </summary>
        /// <param name="addresses">The addresses associated to the endpoint.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder SetDeviceEndpointUris(params Uri[] addresses)
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
                options.DeviceEndpointUris.Clear();
                options.DeviceEndpointUris.AddRange(addresses);
            });
        }

        /// <summary>
        /// Sets the relative or absolute URLs associated to the introspection endpoint.
        /// If an empty array is specified, the endpoint will be considered disabled.
        /// Note: only the first address will be returned as part of the discovery document.
        /// </summary>
        /// <param name="addresses">The addresses associated to the endpoint.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder SetIntrospectionEndpointUris(params string[] addresses)
        {
            if (addresses is null)
            {
                throw new ArgumentNullException(nameof(addresses));
            }

            return SetIntrospectionEndpointUris(addresses.Select(address => new Uri(address, UriKind.RelativeOrAbsolute)).ToArray());
        }

        /// <summary>
        /// Sets the relative or absolute URLs associated to the introspection endpoint.
        /// If an empty array is specified, the endpoint will be considered disabled.
        /// Note: only the first address will be returned as part of the discovery document.
        /// </summary>
        /// <param name="addresses">The addresses associated to the endpoint.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder SetIntrospectionEndpointUris(params Uri[] addresses)
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
                options.IntrospectionEndpointUris.Clear();
                options.IntrospectionEndpointUris.AddRange(addresses);
            });
        }

        /// <summary>
        /// Sets the relative or absolute URLs associated to the logout endpoint.
        /// If an empty array is specified, the endpoint will be considered disabled.
        /// Note: only the first address will be returned as part of the discovery document.
        /// </summary>
        /// <param name="addresses">The addresses associated to the endpoint.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder SetLogoutEndpointUris(params string[] addresses)
        {
            if (addresses is null)
            {
                throw new ArgumentNullException(nameof(addresses));
            }

            return SetLogoutEndpointUris(addresses.Select(address => new Uri(address, UriKind.RelativeOrAbsolute)).ToArray());
        }

        /// <summary>
        /// Sets the relative or absolute URLs associated to the logout endpoint.
        /// If an empty array is specified, the endpoint will be considered disabled.
        /// Note: only the first address will be returned as part of the discovery document.
        /// </summary>
        /// <param name="addresses">The addresses associated to the endpoint.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder SetLogoutEndpointUris(params Uri[] addresses)
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
                options.LogoutEndpointUris.Clear();
                options.LogoutEndpointUris.AddRange(addresses);
            });
        }

        /// <summary>
        /// Sets the relative or absolute URLs associated to the revocation endpoint.
        /// If an empty array is specified, the endpoint will be considered disabled.
        /// Note: only the first address will be returned as part of the discovery document.
        /// </summary>
        /// <param name="addresses">The addresses associated to the endpoint.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder SetRevocationEndpointUris(params string[] addresses)
        {
            if (addresses is null)
            {
                throw new ArgumentNullException(nameof(addresses));
            }

            return SetRevocationEndpointUris(addresses.Select(address => new Uri(address, UriKind.RelativeOrAbsolute)).ToArray());
        }

        /// <summary>
        /// Sets the relative or absolute URLs associated to the revocation endpoint.
        /// If an empty array is specified, the endpoint will be considered disabled.
        /// Note: only the first address will be returned as part of the discovery document.
        /// </summary>
        /// <param name="addresses">The addresses associated to the endpoint.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder SetRevocationEndpointUris(params Uri[] addresses)
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
                options.RevocationEndpointUris.Clear();
                options.RevocationEndpointUris.AddRange(addresses);
            });
        }

        /// <summary>
        /// Sets the relative or absolute URLs associated to the token endpoint.
        /// If an empty array is specified, the endpoint will be considered disabled.
        /// Note: only the first address will be returned as part of the discovery document.
        /// </summary>
        /// <param name="addresses">The addresses associated to the endpoint.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder SetTokenEndpointUris(params string[] addresses)
        {
            if (addresses is null)
            {
                throw new ArgumentNullException(nameof(addresses));
            }

            return SetTokenEndpointUris(addresses.Select(address => new Uri(address, UriKind.RelativeOrAbsolute)).ToArray());
        }

        /// <summary>
        /// Sets the relative or absolute URLs associated to the token endpoint.
        /// If an empty array is specified, the endpoint will be considered disabled.
        /// Note: only the first address will be returned as part of the discovery document.
        /// </summary>
        /// <param name="addresses">The addresses associated to the endpoint.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder SetTokenEndpointUris(params Uri[] addresses)
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
                options.TokenEndpointUris.Clear();
                options.TokenEndpointUris.AddRange(addresses);
            });
        }

        /// <summary>
        /// Sets the relative or absolute URLs associated to the userinfo endpoint.
        /// If an empty array is specified, the endpoint will be considered disabled.
        /// Note: only the first address will be returned as part of the discovery document.
        /// </summary>
        /// <param name="addresses">The addresses associated to the endpoint.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder SetUserinfoEndpointUris(params string[] addresses)
        {
            if (addresses is null)
            {
                throw new ArgumentNullException(nameof(addresses));
            }

            return SetUserinfoEndpointUris(addresses.Select(address => new Uri(address, UriKind.RelativeOrAbsolute)).ToArray());
        }

        /// <summary>
        /// Sets the relative or absolute URLs associated to the userinfo endpoint.
        /// If an empty array is specified, the endpoint will be considered disabled.
        /// Note: only the first address will be returned as part of the discovery document.
        /// </summary>
        /// <param name="addresses">The addresses associated to the endpoint.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder SetUserinfoEndpointUris(params Uri[] addresses)
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
                options.UserinfoEndpointUris.Clear();
                options.UserinfoEndpointUris.AddRange(addresses);
            });
        }

        /// <summary>
        /// Sets the relative or absolute URLs associated to the verification endpoint.
        /// If an empty array is specified, the endpoint will be considered disabled.
        /// Note: only the first address will be returned by the device endpoint.
        /// </summary>
        /// <param name="addresses">The addresses associated to the endpoint.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder SetVerificationEndpointUris(params string[] addresses)
        {
            if (addresses is null)
            {
                throw new ArgumentNullException(nameof(addresses));
            }

            return SetVerificationEndpointUris(addresses.Select(address => new Uri(address, UriKind.RelativeOrAbsolute)).ToArray());
        }

        /// <summary>
        /// Sets the relative or absolute URLs associated to the verification endpoint.
        /// If an empty array is specified, the endpoint will be considered disabled.
        /// Note: only the first address will be returned by the device endpoint.
        /// </summary>
        /// <param name="addresses">The addresses associated to the endpoint.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder SetVerificationEndpointUris(params Uri[] addresses)
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
                options.VerificationEndpointUris.Clear();
                options.VerificationEndpointUris.AddRange(addresses);
            });
        }

        /// <summary>
        /// Disables JWT access token encryption (this option doesn't affect Data Protection tokens).
        /// Disabling encryption is NOT recommended and SHOULD only be done when issuing tokens
        /// to third-party resource servers/APIs you don't control and don't fully trust.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder DisableAccessTokenEncryption()
            => Configure(options => options.DisableAccessTokenEncryption = true);

        /// <summary>
        /// Disables authorization storage so that ad-hoc authorizations are
        /// not created when an authorization code or refresh token is issued
        /// and can't be revoked to prevent associated tokens from being used.
        /// Using this option is generally NOT recommended.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder DisableAuthorizationStorage()
            => Configure(options => options.DisableAuthorizationStorage = true);

        /// <summary>
        /// Allows processing authorization and token requests that specify scopes that have not
        /// been registered using <see cref="RegisterScopes(string[])"/> or the scope manager.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder DisableScopeValidation()
            => Configure(options => options.DisableScopeValidation = true);

        /// <summary>
        /// Disables sliding expiration. When using this option, refresh tokens
        /// are issued with a fixed expiration date: when they expire, a complete
        /// authorization flow must be started to retrieve a new refresh token.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder DisableSlidingRefreshTokenExpiration()
            => Configure(options => options.DisableSlidingRefreshTokenExpiration = true);

        /// <summary>
        /// Disables token storage, so that no database entry is created
        /// for the tokens and codes returned by the OpenIddict server.
        /// Using this option is generally NOT recommended as it prevents
        /// the tokens and codes from being revoked (if needed).
        /// Note: disabling token storage requires disabling sliding
        /// expiration or enabling rolling tokens.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder DisableTokenStorage()
            => Configure(options => options.DisableTokenStorage = true);

        /// <summary>
        /// Enables the degraded mode. When the degraded mode is enabled, all the security checks that
        /// depend on the OpenIddict core managers are disabled. This option MUST be enabled with extreme
        /// caution and custom handlers MUST be registered to properly validate OpenID Connect requests.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public OpenIddictServerBuilder EnableDegradedMode()
            => Configure(options => options.EnableDegradedMode = true);

        /// <summary>
        /// Disables endpoint permissions enforcement. Calling this method is NOT recommended.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder IgnoreEndpointPermissions()
            => Configure(options => options.IgnoreEndpointPermissions = true);

        /// <summary>
        /// Disables grant type permissions enforcement. Calling this method is NOT recommended.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder IgnoreGrantTypePermissions()
            => Configure(options => options.IgnoreGrantTypePermissions = true);

        /// <summary>
        /// Disables response type permissions enforcement. Calling this method is NOT recommended.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder IgnoreResponseTypePermissions()
            => Configure(options => options.IgnoreResponseTypePermissions = true);

        /// <summary>
        /// Disables scope permissions enforcement. Calling this method is NOT recommended.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder IgnoreScopePermissions()
            => Configure(options => options.IgnoreScopePermissions = true);

        /// <summary>
        /// Registers the specified claims as supported claims so
        /// they can be returned as part of the discovery document.
        /// </summary>
        /// <param name="claims">The supported claims.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder RegisterClaims(params string[] claims)
        {
            if (claims is null)
            {
                throw new ArgumentNullException(nameof(claims));
            }

            if (claims.Any(claim => string.IsNullOrEmpty(claim)))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0073), nameof(claims));
            }

            return Configure(options => options.Claims.UnionWith(claims));
        }

        /// <summary>
        /// Registers the specified scopes as supported scopes so
        /// they can be returned as part of the discovery document.
        /// </summary>
        /// <param name="scopes">The supported scopes.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder RegisterScopes(params string[] scopes)
        {
            if (scopes is null)
            {
                throw new ArgumentNullException(nameof(scopes));
            }

            if (scopes.Any(scope => string.IsNullOrEmpty(scope)))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0074), nameof(scopes));
            }

            return Configure(options => options.Scopes.UnionWith(scopes));
        }

        /// <summary>
        /// Sets the access token lifetime, after which client applications must retrieve
        /// a new access token by making a grant_type=refresh_token token request
        /// or a prompt=none authorization request, depending on the selected flow.
        /// Using long-lived access tokens or tokens that never expire is not recommended.
        /// While discouraged, <c>null</c> can be specified to issue tokens that never expire.
        /// </summary>
        /// <param name="lifetime">The access token lifetime.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder SetAccessTokenLifetime(TimeSpan? lifetime)
            => Configure(options => options.AccessTokenLifetime = lifetime);

        /// <summary>
        /// Sets the authorization code lifetime, after which client applications
        /// are unable to send a grant_type=authorization_code token request.
        /// Using short-lived authorization codes is strongly recommended.
        /// While discouraged, <c>null</c> can be specified to issue codes that never expire.
        /// </summary>
        /// <param name="lifetime">The authorization code lifetime.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder SetAuthorizationCodeLifetime(TimeSpan? lifetime)
            => Configure(options => options.AuthorizationCodeLifetime = lifetime);

        /// <summary>
        /// Sets the device code lifetime, after which client applications are unable to
        /// send a grant_type=urn:ietf:params:oauth:grant-type:device_code token request.
        /// Using short-lived device codes is strongly recommended.
        /// While discouraged, <c>null</c> can be specified to issue codes that never expire.
        /// </summary>
        /// <param name="lifetime">The authorization code lifetime.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder SetDeviceCodeLifetime(TimeSpan? lifetime)
            => Configure(options => options.DeviceCodeLifetime = lifetime);

        /// <summary>
        /// Sets the identity token lifetime, after which client
        /// applications should refuse processing identity tokens.
        /// While discouraged, <c>null</c> can be specified to issue tokens that never expire.
        /// </summary>
        /// <param name="lifetime">The identity token lifetime.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder SetIdentityTokenLifetime(TimeSpan? lifetime)
            => Configure(options => options.IdentityTokenLifetime = lifetime);

        /// <summary>
        /// Sets the refresh token lifetime, after which client applications must get
        /// a new authorization from the user. When sliding expiration is enabled,
        /// a new refresh token is always issued to the client application,
        /// which prolongs the validity period of the refresh token.
        /// While discouraged, <c>null</c> can be specified to issue tokens that never expire.
        /// </summary>
        /// <param name="lifetime">The refresh token lifetime.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder SetRefreshTokenLifetime(TimeSpan? lifetime)
            => Configure(options => options.RefreshTokenLifetime = lifetime);

        /// <summary>
        /// Sets the user code lifetime, after which they'll no longer be considered valid.
        /// Using short-lived device codes is strongly recommended.
        /// While discouraged, <c>null</c> can be specified to issue codes that never expire.
        /// </summary>
        /// <param name="lifetime">The authorization code lifetime.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder SetUserCodeLifetime(TimeSpan? lifetime)
            => Configure(options => options.UserCodeLifetime = lifetime);

        /// <summary>
        /// Sets the issuer address, which is used as the base address
        /// for the endpoint URIs returned from the discovery endpoint.
        /// </summary>
        /// <param name="address">The issuer address.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder SetIssuer(Uri address)
        {
            if (address is null)
            {
                throw new ArgumentNullException(nameof(address));
            }

            return Configure(options => options.Issuer = address);
        }

        /// <summary>
        /// Configures OpenIddict to use reference tokens, so that the access token payloads
        /// are stored in the database (only an identifier is returned to the client application).
        /// Enabling this option is useful when storing a very large number of claims in the tokens,
        /// but it is RECOMMENDED to enable column encryption in the database or use the ASP.NET Core
        /// Data Protection integration, that provides additional protection against token leakage.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder UseReferenceAccessTokens()
            => Configure(options => options.UseReferenceAccessTokens = true);

        /// <summary>
        /// Configures OpenIddict to use reference tokens, so that the refresh token payloads
        /// are stored in the database (only an identifier is returned to the client application).
        /// Enabling this option is useful when storing a very large number of claims in the tokens,
        /// but it is RECOMMENDED to enable column encryption in the database or use the ASP.NET Core
        /// Data Protection integration, that provides additional protection against token leakage.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder UseReferenceRefreshTokens()
            => Configure(options => options.UseReferenceRefreshTokens = true);

        /// <summary>
        /// Configures OpenIddict to use rolling refresh tokens. When this option is enabled,
        /// a new refresh token is always issued for each refresh token request (and the previous
        /// one is automatically revoked unless token storage was explicitly disabled).
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder UseRollingRefreshTokens()
            => Configure(options => options.UseRollingRefreshTokens = true);

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
}
