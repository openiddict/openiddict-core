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
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Validation;
using SR = OpenIddict.Abstractions.OpenIddictResources;

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
        public OpenIddictValidationBuilder(IServiceCollection services)
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
            Action<OpenIddictValidationHandlerDescriptor.Builder<TContext>> configuration)
            where TContext : OpenIddictValidationEvents.BaseContext
        {
            if (configuration is null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            // Note: handlers registered using this API are assumed to be custom handlers by default.
            var builder = OpenIddictValidationHandlerDescriptor.CreateBuilder<TContext>()
                .SetType(OpenIddictValidationHandlerType.Custom);

            configuration(builder);

            return AddEventHandler(builder.Build());
        }

        /// <summary>
        /// Registers an event handler using the specified descriptor.
        /// </summary>
        /// <param name="descriptor">The handler descriptor.</param>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public OpenIddictValidationBuilder AddEventHandler(OpenIddictValidationHandlerDescriptor descriptor)
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
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public OpenIddictValidationBuilder RemoveEventHandler(OpenIddictValidationHandlerDescriptor descriptor)
        {
            if (descriptor is null)
            {
                throw new ArgumentNullException(nameof(descriptor));
            }

            Services.RemoveAll(descriptor.ServiceDescriptor.ServiceType);

            Services.PostConfigure<OpenIddictValidationOptions>(options =>
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
        /// Amends the default OpenIddict validation configuration.
        /// </summary>
        /// <param name="configuration">The delegate used to configure the OpenIddict options.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder Configure(Action<OpenIddictValidationOptions> configuration)
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
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder AddEncryptionCredentials(EncryptingCredentials credentials)
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
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder AddEncryptionKey(SecurityKey key)
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
        /// Registers an encryption certificate.
        /// </summary>
        /// <param name="certificate">The encryption certificate.</param>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder AddEncryptionCertificate(X509Certificate2 certificate)
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
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder AddEncryptionCertificate(
            Assembly assembly, string resource, string password)
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
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder AddEncryptionCertificate(
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
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder AddEncryptionCertificate(Stream stream, string password)
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
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
            Justification = "The X.509 certificate is attached to the server options.")]
        public OpenIddictValidationBuilder AddEncryptionCertificate(
            Stream stream, string password, X509KeyStorageFlags flags)
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
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder AddEncryptionCertificate(string thumbprint)
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
        /// Registers an encryption certificate retrieved from the specified X.509 store.
        /// </summary>
        /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X.509 store.</param>
        /// <param name="name">The name of the X.509 store.</param>
        /// <param name="location">The location of the X.509 store.</param>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder AddEncryptionCertificate(
            string thumbprint, StoreName name, StoreLocation location)
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
        /// Registers the specified values as valid audiences. Setting the audiences is recommended
        /// when the authorization server issues access tokens for multiple distinct resource servers.
        /// </summary>
        /// <param name="audiences">The audiences valid for this resource server.</param>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder AddAudiences(params string[] audiences)
        {
            if (audiences is null)
            {
                throw new ArgumentNullException(nameof(audiences));
            }

            if (audiences.Any(audience => string.IsNullOrEmpty(audience)))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0123), nameof(audiences));
            }

            return Configure(options => options.Audiences.UnionWith(audiences));
        }

        /// <summary>
        /// Enables authorization validation so that a database call is made for each API request
        /// to ensure the authorization associated with the access token is still valid.
        /// Note: enabling this option may have an impact on performance and
        /// can only be used with an OpenIddict-based authorization server.
        /// </summary>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder EnableAuthorizationEntryValidation()
            => Configure(options => options.EnableAuthorizationEntryValidation = true);

        /// <summary>
        /// Enables token validation so that a database call is made for each API request
        /// to ensure the token entry associated with the access token is still valid.
        /// Note: enabling this option may have an impact on performance but is required
        /// when the OpenIddict server is configured to use reference tokens.
        /// </summary>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder EnableTokenEntryValidation()
            => Configure(options => options.EnableTokenEntryValidation = true);

        /// <summary>
        /// Sets a static OpenID Connect server configuration, that will be used to
        /// resolve the metadata/introspection endpoints and the issuer signing keys.
        /// </summary>
        /// <param name="configuration">The server configuration.</param>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder SetConfiguration(OpenIdConnectConfiguration configuration)
        {
            if (configuration is null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            return Configure(options => options.Configuration = configuration);
        }

        /// <summary>
        /// Sets the client identifier client_id used when communicating
        /// with the remote authorization server (e.g for introspection).
        /// </summary>
        /// <param name="identifier">The client identifier.</param>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder SetClientId(string identifier)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0124), nameof(identifier));
            }

            return Configure(options => options.ClientId = identifier);
        }

        /// <summary>
        /// Sets the client identifier client_secret used when communicating
        /// with the remote authorization server (e.g for introspection).
        /// </summary>
        /// <param name="secret">The client secret.</param>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder SetClientSecret(string secret)
        {
            if (string.IsNullOrEmpty(secret))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0125), nameof(secret));
            }

            return Configure(options => options.ClientSecret = secret);
        }

        /// <summary>
        /// Sets the issuer address, which is used to determine the actual location of the
        /// OAuth 2.0/OpenID Connect configuration document when using provider discovery.
        /// </summary>
        /// <param name="address">The issuer address.</param>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder SetIssuer(Uri address)
        {
            if (address is null)
            {
                throw new ArgumentNullException(nameof(address));
            }

            return Configure(options => options.Issuer = address);
        }

        /// <summary>
        /// Sets the issuer address, which is used to determine the actual location of the
        /// OAuth 2.0/OpenID Connect configuration document when using provider discovery.
        /// </summary>
        /// <param name="address">The issuer address.</param>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder SetIssuer(string address)
        {
            if (string.IsNullOrEmpty(address))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0126), nameof(address));
            }

            if (!Uri.TryCreate(address, UriKind.Absolute, out Uri? uri) || !uri.IsWellFormedOriginalString())
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0127), nameof(address));
            }

            return SetIssuer(uri);
        }

        /// <summary>
        /// Configures OpenIddict to use introspection instead of local/direct validation.
        /// </summary>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public OpenIddictValidationBuilder UseIntrospection()
            => Configure(options => options.ValidationType = OpenIddictValidationType.Introspection);

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
