/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using JetBrains.Annotations;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Validation;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Exposes the necessary methods required to configure the OpenIddict validation services.
    /// </summary>
    public class OpenIddictValidationBuilder
    {
        /// <summary>
        /// Initializes a new instance of <see cref="OpenIddictValidationBuilder"/>.
        /// </summary>
        /// <param name="services">The services collection.</param>
        public OpenIddictValidationBuilder([NotNull] IServiceCollection services)
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
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public OpenIddictValidationBuilder AddEventHandler<TContext>(
            [NotNull] Action<OpenIddictValidationHandlerDescriptor.Builder<TContext>> configuration)
            where TContext : OpenIddictValidationEvents.BaseContext
        {
            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            var builder = OpenIddictValidationHandlerDescriptor.CreateBuilder<TContext>();
            configuration(builder);

            return AddEventHandler(builder.Build());
        }

        /// <summary>
        /// Registers an event handler using the specified descriptor.
        /// </summary>
        /// <param name="descriptor">The handler descriptor.</param>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public OpenIddictValidationBuilder AddEventHandler([NotNull] OpenIddictValidationHandlerDescriptor descriptor)
        {
            if (descriptor == null)
            {
                throw new ArgumentNullException(nameof(descriptor));
            }

            // Register the handler in the services collection.
            Services.Add(descriptor.ServiceDescriptor);

            return Configure(options => options.CustomHandlers.Add(descriptor));
        }

        /// <summary>
        /// Removes the event handler that matches the specified descriptor.
        /// </summary>
        /// <param name="descriptor">The descriptor corresponding to the handler to remove.</param>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public OpenIddictValidationBuilder RemoveEventHandler([NotNull] OpenIddictValidationHandlerDescriptor descriptor)
        {
            if (descriptor == null)
            {
                throw new ArgumentNullException(nameof(descriptor));
            }

            Services.RemoveAll(descriptor.ServiceDescriptor.ServiceType);

            Services.PostConfigure<OpenIddictValidationOptions>(options =>
            {
                for (var index = options.CustomHandlers.Count - 1; index >= 0; index--)
                {
                    if (options.CustomHandlers[index].ServiceDescriptor.ServiceType == descriptor.ServiceDescriptor.ServiceType)
                    {
                        options.CustomHandlers.RemoveAt(index);
                    }
                }

                for (var index = options.DefaultHandlers.Count - 1; index >= 0; index--)
                {
                    if (options.DefaultHandlers[index].ServiceDescriptor.ServiceType == descriptor.ServiceDescriptor.ServiceType)
                    {
                        options.DefaultHandlers.RemoveAt(index);
                    }
                }
            });

            return this;
        }

        /// <summary>
        /// Amends the default OpenIddict validation configuration.
        /// </summary>
        /// <param name="configuration">The delegate used to configure the OpenIddict options.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder Configure([NotNull] Action<OpenIddictValidationOptions> configuration)
        {
            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            Services.Configure(configuration);

            return this;
        }

        /// <summary>
        /// Registers the <see cref="EncryptingCredentials"/> used to decrypt the tokens issued by OpenIddict.
        /// </summary>
        /// <param name="credentials">The encrypting credentials.</param>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder AddEncryptionCredentials([NotNull] EncryptingCredentials credentials)
        {
            if (credentials == null)
            {
                throw new ArgumentNullException(nameof(credentials));
            }

            return Configure(options => options.EncryptionCredentials.Add(credentials));
        }

        /// <summary>
        /// Registers a <see cref="SecurityKey"/> used to decrypt the access tokens issued by OpenIddict.
        /// </summary>
        /// <param name="key">The security key.</param>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder AddEncryptionKey([NotNull] SecurityKey key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            // If the encryption key is an asymmetric security key, ensure it has a private key.
            if (key is AsymmetricSecurityKey asymmetricSecurityKey &&
                asymmetricSecurityKey.PrivateKeyStatus == PrivateKeyStatus.DoesNotExist)
            {
                throw new InvalidOperationException("The asymmetric encryption key doesn't contain the required private key.");
            }

            if (IsAlgorithmSupported(key, SecurityAlgorithms.Aes256KW))
            {
                return AddEncryptionCredentials(new EncryptingCredentials(key,
                    SecurityAlgorithms.Aes256KW, SecurityAlgorithms.Aes256CbcHmacSha512));
            }

            if (IsAlgorithmSupported(key, SecurityAlgorithms.RsaOAEP))
            {
                return AddEncryptionCredentials(new EncryptingCredentials(key,
                    SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes256CbcHmacSha512));
            }

            throw new InvalidOperationException(new StringBuilder()
                .AppendLine("An encryption algorithm cannot be automatically inferred from the encrypting key.")
                .Append("Consider using 'options.AddEncryptionCredentials(EncryptingCredentials)' instead.")
                .ToString());

            static bool IsAlgorithmSupported(SecurityKey key, string algorithm) =>
                key.CryptoProviderFactory.IsSupportedAlgorithm(algorithm, key);
        }

        /// <summary>
        /// Registers (and generates if necessary) a user-specific development
        /// certificate used to decrypt the tokens issued by OpenIddict.
        /// </summary>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder AddDevelopmentEncryptionCertificate()
            => AddDevelopmentEncryptionCertificate(new X500DistinguishedName("CN=OpenIddict Validation Encryption Certificate"));

        /// <summary>
        /// Registers (and generates if necessary) a user-specific development
        /// certificate used to decrypt the tokens issued by OpenIddict.
        /// </summary>
        /// <param name="subject">The subject name associated with the certificate.</param>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder AddDevelopmentEncryptionCertificate([NotNull] X500DistinguishedName subject)
        {
            if (subject == null)
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

            if (certificate != null && (certificate.NotBefore > DateTime.Now || certificate.NotAfter < DateTime.Now))
            {
                store.Remove(certificate);
                certificate = null;
            }

#if SUPPORTS_CERTIFICATE_GENERATION
            // If no appropriate certificate can be found, generate and persist a new certificate in the specified store.
            if (certificate == null)
            {
                using var algorithm = RSA.Create(keySizeInBits: 2048);

                var request = new CertificateRequest(subject, algorithm, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyEncipherment, critical: true));

                certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(2));

                // Note: setting the friendly name is not supported on Unix machines (including Linux and macOS).
                // To ensure an exception is not thrown by the property setter, an OS runtime check is used here.
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    certificate.FriendlyName = "OpenIddict Validation Development Encryption Certificate";
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
            throw new PlatformNotSupportedException("X.509 certificate generation is not supported on this platform.");
#endif
        }

        /// <summary>
        /// Registers a new ephemeral key used to decrypt the tokens issued by OpenIddict: the key
        /// is discarded when the application shuts down and tokens encrypted using this key are
        /// automatically invalidated. This method should only be used during development.
        /// On production, using a X.509 certificate stored in the machine store is recommended.
        /// </summary>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder AddEphemeralEncryptionKey()
            => AddEphemeralEncryptionKey(SecurityAlgorithms.RsaOAEP);

        /// <summary>
        /// Registers a new ephemeral key used to decrypt the tokens issued by OpenIddict: the key
        /// is discarded when the application shuts down and tokens encrypted using this key are
        /// automatically invalidated. This method should only be used during development.
        /// On production, using a X.509 certificate stored in the machine store is recommended.
        /// </summary>
        /// <param name="algorithm">The algorithm associated with the encryption key.</param>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder AddEphemeralEncryptionKey([NotNull] string algorithm)
        {
            if (string.IsNullOrEmpty(algorithm))
            {
                throw new ArgumentException("The algorithm cannot be null or empty.", nameof(algorithm));
            }

            switch (algorithm)
            {
                case SecurityAlgorithms.Aes256KW:
                    return AddEncryptionCredentials(new EncryptingCredentials(CreateSymmetricSecurityKey(256),
                        algorithm, SecurityAlgorithms.Aes256CbcHmacSha512));

                case SecurityAlgorithms.RsaOAEP:
                case SecurityAlgorithms.RsaOaepKeyWrap:
                    return AddEncryptionCredentials(new EncryptingCredentials(CreateRsaSecurityKey(2048),
                        algorithm, SecurityAlgorithms.Aes256CbcHmacSha512));

                default: throw new InvalidOperationException("The specified algorithm is not supported.");
            }

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
                    throw new InvalidOperationException("RSA key generation failed.");
                }

                return new RsaSecurityKey(algorithm);
#endif
            }
        }

        /// <summary>
        /// Registers a <see cref="X509Certificate2"/> that is used to decrypt the tokens issued by OpenIddict.
        /// </summary>
        /// <param name="certificate">The certificate used to decrypt the security tokens issued by the validation.</param>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder AddEncryptionCertificate([NotNull] X509Certificate2 certificate)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            if (certificate.NotBefore > DateTime.Now)
            {
                throw new InvalidOperationException("The specified certificate is not yet valid.");
            }

            if (certificate.NotAfter < DateTime.Now)
            {
                throw new InvalidOperationException("The specified certificate is no longer valid.");
            }

            if (!certificate.HasPrivateKey)
            {
                throw new InvalidOperationException("The specified certificate doesn't contain the required private key.");
            }

            return AddEncryptionKey(new X509SecurityKey(certificate));
        }

        /// <summary>
        /// Registers a <see cref="X509Certificate2"/> retrieved from an
        /// embedded resource and used to decrypt the tokens issued by OpenIddict.
        /// </summary>
        /// <param name="assembly">The assembly containing the certificate.</param>
        /// <param name="resource">The name of the embedded resource.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder AddEncryptionCertificate(
            [NotNull] Assembly assembly, [NotNull] string resource, [NotNull] string password)
#if SUPPORTS_EPHEMERAL_KEY_SETS
            // Note: ephemeral key sets are currently not supported on macOS.
            => AddEncryptionCertificate(assembly, resource, password, RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ?
                X509KeyStorageFlags.MachineKeySet :
                X509KeyStorageFlags.EphemeralKeySet);
#else
            => AddEncryptionCertificate(assembly, resource, password, X509KeyStorageFlags.MachineKeySet);
#endif

        /// <summary>
        /// Registers a <see cref="X509Certificate2"/> retrieved from an
        /// embedded resource and used to decrypt the tokens issued by OpenIddict.
        /// </summary>
        /// <param name="assembly">The assembly containing the certificate.</param>
        /// <param name="resource">The name of the embedded resource.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <param name="flags">An enumeration of flags indicating how and where to store the private key of the certificate.</param>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder AddEncryptionCertificate(
            [NotNull] Assembly assembly, [NotNull] string resource,
            [NotNull] string password, X509KeyStorageFlags flags)
        {
            if (assembly == null)
            {
                throw new ArgumentNullException(nameof(assembly));
            }

            if (string.IsNullOrEmpty(resource))
            {
                throw new ArgumentException("The resource cannot be null or empty.", nameof(resource));
            }

            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("The password cannot be null or empty.", nameof(password));
            }

            using var stream = assembly.GetManifestResourceStream(resource);
            if (stream == null)
            {
                throw new InvalidOperationException("The certificate was not found in the specified assembly.");
            }

            return AddEncryptionCertificate(stream, password, flags);
        }

        /// <summary>
        /// Registers a <see cref="X509Certificate2"/> extracted from a
        /// stream and used to decrypt the tokens issued by OpenIddict.
        /// </summary>
        /// <param name="stream">The stream containing the certificate.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder AddEncryptionCertificate([NotNull] Stream stream, [NotNull] string password)
#if SUPPORTS_EPHEMERAL_KEY_SETS
            // Note: ephemeral key sets are currently not supported on macOS.
            => AddEncryptionCertificate(stream, password, RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ?
                X509KeyStorageFlags.MachineKeySet :
                X509KeyStorageFlags.EphemeralKeySet);
#else
            => AddEncryptionCertificate(stream, password, X509KeyStorageFlags.MachineKeySet);
#endif

        /// <summary>
        /// Registers a <see cref="X509Certificate2"/> extracted from a
        /// stream and used to decrypt the tokens issued by OpenIddict.
        /// </summary>
        /// <param name="stream">The stream containing the certificate.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <param name="flags">
        /// An enumeration of flags indicating how and where
        /// to store the private key of the certificate.
        /// </param>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder AddEncryptionCertificate(
            [NotNull] Stream stream, [NotNull] string password, X509KeyStorageFlags flags)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("The password cannot be null or empty.", nameof(password));
            }

            using var buffer = new MemoryStream();
            stream.CopyTo(buffer);

            return AddEncryptionCertificate(new X509Certificate2(buffer.ToArray(), password, flags));
        }

        /// <summary>
        /// Registers a <see cref="X509Certificate2"/> retrieved from the X.509
        /// machine store and used to decrypt the tokens issued by OpenIddict.
        /// </summary>
        /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X.509 store.</param>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder AddEncryptionCertificate([NotNull] string thumbprint)
        {
            if (string.IsNullOrEmpty(thumbprint))
            {
                throw new ArgumentException("The thumbprint cannot be null or empty.", nameof(thumbprint));
            }

            var certificate = GetCertificate(StoreLocation.CurrentUser, thumbprint) ?? GetCertificate(StoreLocation.LocalMachine, thumbprint);
            if (certificate == null)
            {
                throw new InvalidOperationException("The certificate corresponding to the specified thumbprint was not found.");
            }

            return AddEncryptionCertificate(certificate);

            static X509Certificate2 GetCertificate(StoreLocation location, string thumbprint)
            {
                using var store = new X509Store(StoreName.My, location);
                store.Open(OpenFlags.ReadOnly);

                return store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false)
                    .OfType<X509Certificate2>()
                    .SingleOrDefault();
            }
        }

        /// <summary>
        /// Registers a <see cref="X509Certificate2"/> retrieved from the given
        /// X.509 store and used to decrypt the tokens issued by OpenIddict.
        /// </summary>
        /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X.509 store.</param>
        /// <param name="name">The name of the X.509 store.</param>
        /// <param name="location">The location of the X.509 store.</param>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder AddEncryptionCertificate(
            [NotNull] string thumbprint, StoreName name, StoreLocation location)
        {
            if (string.IsNullOrEmpty(thumbprint))
            {
                throw new ArgumentException("The thumbprint cannot be null or empty.", nameof(thumbprint));
            }

            using var store = new X509Store(name, location);
            store.Open(OpenFlags.ReadOnly);

            var certificate = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false)
                .OfType<X509Certificate2>()
                .SingleOrDefault();

            if (certificate == null)
            {
                throw new InvalidOperationException("The certificate corresponding to the specified thumbprint was not found.");
            }

            return AddEncryptionCertificate(certificate);
        }

        /// <summary>
        /// Registers the specified values as valid audiences. Setting the audiences is recommended
        /// when the authorization server issues access tokens for multiple distinct resource servers.
        /// </summary>
        /// <param name="audiences">The audiences valid for this resource server.</param>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder AddAudiences([NotNull] params string[] audiences)
        {
            if (audiences == null)
            {
                throw new ArgumentNullException(nameof(audiences));
            }

            if (audiences.Any(audience => string.IsNullOrEmpty(audience)))
            {
                throw new ArgumentException("Audiences cannot be null or empty.", nameof(audiences));
            }

            return Configure(options => options.Audiences.UnionWith(audiences));
        }

        /// <summary>
        /// Enables authorization validation so that a database call is made for each API request
        /// to ensure the authorization associated with the access token is still valid.
        /// Note: enabling this option may have an impact on performance.
        /// </summary>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder EnableAuthorizationValidation()
            => Configure(options => options.EnableAuthorizationValidation = true);

        /// <summary>
        /// Sets the issuer address, which is used to determine the actual location of the
        /// OAuth 2.0/OpenID Connect configuration document when using provider discovery.
        /// </summary>
        /// <param name="address">The issuer address.</param>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder SetIssuer([NotNull] Uri address)
        {
            if (address == null)
            {
                throw new ArgumentNullException(nameof(address));
            }

            return Configure(options => options.Issuer = address);
        }

        /// <summary>
        /// Updates the token validation parameters using the specified delegate.
        /// </summary>
        /// <param name="configuration">The configuration delegate.</param>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder SetTokenValidationParameters([NotNull] Action<TokenValidationParameters> configuration)
        {
            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            return Configure(options => configuration(options.TokenValidationParameters));
        }

        /// <summary>
        /// Configures OpenIddict to use reference tokens, so that authorization codes,
        /// access tokens and refresh tokens are stored as ciphertext in the database
        /// (only an identifier is returned to the client application). Enabling this option
        /// is useful to keep track of all the issued tokens, when storing a very large
        /// number of claims in the authorization codes, access tokens and refresh tokens
        /// or when immediate revocation of reference access tokens is desired.
        /// Note: this option cannot be used when configuring JWT as the access token format.
        /// </summary>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder UseReferenceTokens()
            => Configure(options => options.UseReferenceTokens = true);

        /// <summary>
        /// Determines whether the specified object is equal to the current object.
        /// </summary>
        /// <param name="obj">The object to compare with the current object.</param>
        /// <returns><c>true</c> if the specified object is equal to the current object; otherwise, false.</returns>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals([CanBeNull] object obj) => base.Equals(obj);

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
        public override string ToString() => base.ToString();
    }
}
