/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.Client.Saml;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes the necessary methods required to configure the OpenIddict SAML 2.0 service provider.
/// </summary>
public sealed class OpenIddictClientSamlBuilder
{
    /// <summary>
    /// Initializes a new instance of <see cref="OpenIddictClientSamlBuilder"/>.
    /// </summary>
    /// <param name="services">The services collection.</param>
    public OpenIddictClientSamlBuilder(IServiceCollection services)
        => Services = services ?? throw new ArgumentNullException(nameof(services));

    /// <summary>
    /// Gets the services collection.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public IServiceCollection Services { get; }

    /// <summary>
    /// Enables validation of options during application startup.
    /// </summary>
    /// <returns>The <see cref="OpenIddictClientSamlBuilder"/> instance.</returns>
    public OpenIddictClientSamlBuilder ValidateOnStart()
    {
        Services.AddOptionsWithValidateOnStart<OpenIddictClientSamlOptions>();

        return this;
    }

    /// <summary>
    /// Amends the default OpenIddict SAML service provider configuration.
    /// </summary>
    /// <param name="configuration">The delegate used to configure the OpenIddict options.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictClientSamlBuilder"/> instance.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictClientSamlBuilder Configure(Action<OpenIddictClientSamlOptions> configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        Services.Configure(configuration);

        return this;
    }

    /// <summary>
    /// Sets the entity identifier of the service provider.
    /// </summary>
    /// <param name="identifier">The entity identifier.</param>
    /// <returns>The <see cref="OpenIddictClientSamlBuilder"/> instance.</returns>
    public OpenIddictClientSamlBuilder SetEntityId(string identifier)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        return Configure(options => options.EntityId = identifier);
    }

    /// <summary>
    /// Registers an X.509 certificate (with an RSA private key) used to sign authentication requests.
    /// </summary>
    /// <param name="certificate">The certificate.</param>
    /// <returns>The <see cref="OpenIddictClientSamlBuilder"/> instance.</returns>
    public OpenIddictClientSamlBuilder AddSigningCertificate(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        return Configure(options => options.SigningCertificates.Add(certificate));
    }

    /// <summary>
    /// Registers an X.509 certificate (with an RSA private key) used to decrypt encrypted assertions, identifiers and attributes.
    /// </summary>
    /// <param name="certificate">The certificate.</param>
    /// <returns>The <see cref="OpenIddictClientSamlBuilder"/> instance.</returns>
    public OpenIddictClientSamlBuilder AddEncryptionCertificate(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        return Configure(options => options.EncryptionCertificates.Add(certificate));
    }

    /// <summary>
    /// Registers a static identity provider registration.
    /// </summary>
    /// <param name="registration">The registration.</param>
    /// <returns>The <see cref="OpenIddictClientSamlBuilder"/> instance.</returns>
    public OpenIddictClientSamlBuilder AddRegistration(OpenIddictClientSamlRegistration registration)
    {
        ArgumentNullException.ThrowIfNull(registration);

        return Configure(options => options.Registrations.Add(registration));
    }

    /// <summary>
    /// Registers a provider resolving identity provider registrations at runtime (e.g from a database).
    /// </summary>
    /// <typeparam name="TProvider">The type of the provider, registered as a singleton.</typeparam>
    /// <returns>The <see cref="OpenIddictClientSamlBuilder"/> instance.</returns>
    public OpenIddictClientSamlBuilder AddRegistrationProvider<
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TProvider>()
        where TProvider : class, IOpenIddictClientSamlRegistrationProvider
    {
        Services.TryAddEnumerable(ServiceDescriptor.Singleton<IOpenIddictClientSamlRegistrationProvider, TProvider>());

        return this;
    }

    /// <summary>
    /// Registers a provider resolving identity provider registrations at runtime (e.g from a database).
    /// </summary>
    /// <param name="provider">The provider instance.</param>
    /// <returns>The <see cref="OpenIddictClientSamlBuilder"/> instance.</returns>
    public OpenIddictClientSamlBuilder AddRegistrationProvider(IOpenIddictClientSamlRegistrationProvider provider)
    {
        ArgumentNullException.ThrowIfNull(provider);

        Services.AddSingleton(provider);

        return this;
    }

    /// <summary>
    /// Replaces the default in-memory assertion replay cache (e.g by a distributed implementation).
    /// </summary>
    /// <typeparam name="TCache">The type of the cache, registered as a singleton.</typeparam>
    /// <returns>The <see cref="OpenIddictClientSamlBuilder"/> instance.</returns>
    public OpenIddictClientSamlBuilder SetReplayCache<
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TCache>()
        where TCache : class, IOpenIddictClientSamlReplayCache
    {
        Services.Replace(ServiceDescriptor.Singleton<IOpenIddictClientSamlReplayCache, TCache>());

        return this;
    }

    /// <summary>
    /// Replaces the default metadata retriever.
    /// </summary>
    /// <typeparam name="TRetriever">The type of the retriever, registered as a singleton.</typeparam>
    /// <returns>The <see cref="OpenIddictClientSamlBuilder"/> instance.</returns>
    public OpenIddictClientSamlBuilder SetMetadataRetriever<
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TRetriever>()
        where TRetriever : class, IOpenIddictClientSamlMetadataRetriever
    {
        Services.Replace(ServiceDescriptor.Singleton<IOpenIddictClientSamlMetadataRetriever, TRetriever>());

        return this;
    }

    /// <summary>
    /// Sets the algorithms used to sign authentication requests.
    /// </summary>
    /// <param name="signatureAlgorithm">The signature algorithm (RSA-SHA256, RSA-SHA384 or RSA-SHA512).</param>
    /// <param name="digestAlgorithm">The digest algorithm (SHA-256, SHA-384 or SHA-512).</param>
    /// <returns>The <see cref="OpenIddictClientSamlBuilder"/> instance.</returns>
    public OpenIddictClientSamlBuilder SetSignatureAlgorithms(string signatureAlgorithm, string digestAlgorithm)
    {
        ArgumentException.ThrowIfNullOrEmpty(signatureAlgorithm);
        ArgumentException.ThrowIfNullOrEmpty(digestAlgorithm);

        return Configure(options =>
        {
            options.SignatureAlgorithm = signatureAlgorithm;
            options.DigestAlgorithm = digestAlgorithm;
        });
    }

    /// <summary>
    /// Sets the clock skew tolerated when validating assertions.
    /// </summary>
    /// <param name="skew">The clock skew.</param>
    /// <returns>The <see cref="OpenIddictClientSamlBuilder"/> instance.</returns>
    public OpenIddictClientSamlBuilder SetClockSkew(TimeSpan skew)
        => Configure(options => options.ClockSkew = skew);

    /// <summary>
    /// Sets the lifetime of the request state created when an authentication request is sent.
    /// </summary>
    /// <param name="lifetime">The lifetime.</param>
    /// <returns>The <see cref="OpenIddictClientSamlBuilder"/> instance.</returns>
    public OpenIddictClientSamlBuilder SetRequestStateLifetime(TimeSpan lifetime)
        => Configure(options => options.RequestStateLifetime = lifetime);

    /// <summary>
    /// Sets the maximum size, in bytes, of the decoded SAML responses.
    /// </summary>
    /// <param name="size">The maximum size.</param>
    /// <returns>The <see cref="OpenIddictClientSamlBuilder"/> instance.</returns>
    public OpenIddictClientSamlBuilder SetMaximumMessageSize(int size)
        => Configure(options => options.MaximumMessageSize = size);

    /// <summary>
    /// Sets the duration during which imported identity provider metadata is cached.
    /// </summary>
    /// <param name="interval">The refresh interval.</param>
    /// <returns>The <see cref="OpenIddictClientSamlBuilder"/> instance.</returns>
    public OpenIddictClientSamlBuilder SetMetadataRefreshInterval(TimeSpan interval)
        => Configure(options => options.MetadataRefreshInterval = interval);

    /// <summary>
    /// Sets the duration during which dynamic registrations are cached (<see langword="null"/> to disable caching).
    /// </summary>
    /// <param name="lifetime">The cache lifetime.</param>
    /// <returns>The <see cref="OpenIddictClientSamlBuilder"/> instance.</returns>
    public OpenIddictClientSamlBuilder SetDynamicRegistrationCacheLifetime(TimeSpan? lifetime)
        => Configure(options => options.DynamicRegistrationCacheLifetime = lifetime);
}
