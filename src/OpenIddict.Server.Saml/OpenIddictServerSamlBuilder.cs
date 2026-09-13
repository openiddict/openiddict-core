/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.Server.Saml;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes the necessary methods required to configure the OpenIddict SAML 2.0 identity provider.
/// </summary>
public sealed class OpenIddictServerSamlBuilder
{
    /// <summary>
    /// Initializes a new instance of <see cref="OpenIddictServerSamlBuilder"/>.
    /// </summary>
    /// <param name="services">The services collection.</param>
    public OpenIddictServerSamlBuilder(IServiceCollection services)
        => Services = services ?? throw new ArgumentNullException(nameof(services));

    /// <summary>
    /// Gets the services collection.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public IServiceCollection Services { get; }

    /// <summary>
    /// Enables validation of options during application startup.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerSamlBuilder"/> instance.</returns>
    public OpenIddictServerSamlBuilder ValidateOnStart()
    {
        Services.AddOptionsWithValidateOnStart<OpenIddictServerSamlOptions>();

        return this;
    }

    /// <summary>
    /// Amends the default OpenIddict SAML configuration.
    /// </summary>
    /// <param name="configuration">The delegate used to configure the OpenIddict options.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictServerSamlBuilder"/> instance.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictServerSamlBuilder Configure(Action<OpenIddictServerSamlOptions> configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        Services.Configure(configuration);

        return this;
    }

    /// <summary>
    /// Sets the entity identifier of the identity provider.
    /// </summary>
    /// <param name="identifier">The entity identifier.</param>
    /// <returns>The <see cref="OpenIddictServerSamlBuilder"/> instance.</returns>
    public OpenIddictServerSamlBuilder SetEntityId(string identifier)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        return Configure(options => options.EntityId = identifier);
    }

    /// <summary>
    /// Registers an X.509 certificate (with an RSA private key) used to sign responses and assertions.
    /// </summary>
    /// <param name="certificate">The certificate.</param>
    /// <returns>The <see cref="OpenIddictServerSamlBuilder"/> instance.</returns>
    public OpenIddictServerSamlBuilder AddSigningCertificate(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        return Configure(options => options.SigningCertificates.Add(certificate));
    }

    /// <summary>
    /// Registers a service provider.
    /// </summary>
    /// <param name="provider">The service provider.</param>
    /// <returns>The <see cref="OpenIddictServerSamlBuilder"/> instance.</returns>
    public OpenIddictServerSamlBuilder AddServiceProvider(OpenIddictServerSamlServiceProvider provider)
    {
        ArgumentNullException.ThrowIfNull(provider);

        return Configure(options => options.ServiceProviders.Add(provider));
    }

    /// <summary>
    /// Registers a custom service provider store, used instead of the providers registered in the options.
    /// </summary>
    /// <typeparam name="TStore">The type of the store.</typeparam>
    /// <param name="lifetime">The lifetime of the store.</param>
    /// <returns>The <see cref="OpenIddictServerSamlBuilder"/> instance.</returns>
    public OpenIddictServerSamlBuilder SetServiceProviderStore<
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TStore>(
        ServiceLifetime lifetime = ServiceLifetime.Scoped)
        where TStore : class, IOpenIddictServerSamlServiceProviderStore
    {
        Services.Replace(new ServiceDescriptor(typeof(IOpenIddictServerSamlServiceProviderStore), typeof(TStore), lifetime));

        return this;
    }

    /// <summary>
    /// Registers a custom assertion provider, used to create the subject and attributes of the assertions.
    /// </summary>
    /// <typeparam name="TProvider">The type of the assertion provider.</typeparam>
    /// <param name="lifetime">The lifetime of the provider.</param>
    /// <returns>The <see cref="OpenIddictServerSamlBuilder"/> instance.</returns>
    public OpenIddictServerSamlBuilder SetAssertionProvider<
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TProvider>(
        ServiceLifetime lifetime = ServiceLifetime.Scoped)
        where TProvider : class, IOpenIddictServerSamlAssertionProvider
    {
        Services.Replace(new ServiceDescriptor(typeof(IOpenIddictServerSamlAssertionProvider), typeof(TProvider), lifetime));

        return this;
    }

    /// <summary>
    /// Sets the algorithms used to sign responses and assertions.
    /// </summary>
    /// <param name="signatureAlgorithm">The signature algorithm (RSA-SHA256, RSA-SHA384 or RSA-SHA512).</param>
    /// <param name="digestAlgorithm">The digest algorithm (SHA-256, SHA-384 or SHA-512).</param>
    /// <returns>The <see cref="OpenIddictServerSamlBuilder"/> instance.</returns>
    public OpenIddictServerSamlBuilder SetSignatureAlgorithms(string signatureAlgorithm, string digestAlgorithm)
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
    /// Enables the signature of successful responses (in addition to the assertion signature).
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerSamlBuilder"/> instance.</returns>
    public OpenIddictServerSamlBuilder EnableResponseSigning()
        => Configure(options => options.SignResponses = true);

    /// <summary>
    /// Sets the lifetime of the assertions.
    /// </summary>
    /// <param name="lifetime">The lifetime.</param>
    /// <returns>The <see cref="OpenIddictServerSamlBuilder"/> instance.</returns>
    public OpenIddictServerSamlBuilder SetAssertionLifetime(TimeSpan lifetime)
        => Configure(options => options.AssertionLifetime = lifetime);

    /// <summary>
    /// Sets the maximum age of the authentication requests.
    /// </summary>
    /// <param name="lifetime">The lifetime.</param>
    /// <returns>The <see cref="OpenIddictServerSamlBuilder"/> instance.</returns>
    public OpenIddictServerSamlBuilder SetAuthenticationRequestLifetime(TimeSpan lifetime)
        => Configure(options => options.AuthenticationRequestLifetime = lifetime);

    /// <summary>
    /// Sets the clock skew tolerated when validating authentication requests.
    /// </summary>
    /// <param name="skew">The clock skew.</param>
    /// <returns>The <see cref="OpenIddictServerSamlBuilder"/> instance.</returns>
    public OpenIddictServerSamlBuilder SetClockSkew(TimeSpan skew)
        => Configure(options => options.ClockSkew = skew);

    /// <summary>
    /// Sets the maximum size, in bytes, of the decoded SAML messages.
    /// </summary>
    /// <param name="size">The maximum size.</param>
    /// <returns>The <see cref="OpenIddictServerSamlBuilder"/> instance.</returns>
    public OpenIddictServerSamlBuilder SetMaximumMessageSize(int size)
        => Configure(options => options.MaximumMessageSize = size);
}
