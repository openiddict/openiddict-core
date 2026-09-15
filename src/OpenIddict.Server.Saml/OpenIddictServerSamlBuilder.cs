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
    /// Registers a custom replay cache, used to detect replayed authentication requests and request states.
    /// </summary>
    /// <typeparam name="TCache">The type of the replay cache.</typeparam>
    /// <param name="lifetime">The lifetime of the replay cache.</param>
    /// <returns>The <see cref="OpenIddictServerSamlBuilder"/> instance.</returns>
    public OpenIddictServerSamlBuilder SetReplayCache<
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TCache>(
        ServiceLifetime lifetime = ServiceLifetime.Singleton)
        where TCache : class, IOpenIddictServerSamlReplayCache
    {
        Services.Replace(new ServiceDescriptor(typeof(IOpenIddictServerSamlReplayCache), typeof(TCache), lifetime));

        return this;
    }

    /// <summary>
    /// Registers a custom artifact store, used to store the messages represented by artifacts.
    /// </summary>
    /// <typeparam name="TStore">The type of the artifact store.</typeparam>
    /// <param name="lifetime">The lifetime of the artifact store.</param>
    /// <returns>The <see cref="OpenIddictServerSamlBuilder"/> instance.</returns>
    public OpenIddictServerSamlBuilder SetArtifactStore<
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TStore>(
        ServiceLifetime lifetime = ServiceLifetime.Singleton)
        where TStore : class, IOpenIddictServerSamlArtifactStore
    {
        Services.Replace(new ServiceDescriptor(typeof(IOpenIddictServerSamlArtifactStore), typeof(TStore), lifetime));

        return this;
    }

    /// <summary>
    /// Enables the HTTP-Artifact binding, used to return responses to the assertion consumer services
    /// registered with this binding, and the artifact resolution service (SOAP binding).
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerSamlBuilder"/> instance.</returns>
    public OpenIddictServerSamlBuilder EnableArtifactBinding()
        => Configure(options => options.EnableArtifactBinding = true);

    /// <summary>
    /// Sets the lifetime of the artifacts issued using the HTTP-Artifact binding.
    /// </summary>
    /// <param name="lifetime">The lifetime.</param>
    /// <returns>The <see cref="OpenIddictServerSamlBuilder"/> instance.</returns>
    public OpenIddictServerSamlBuilder SetArtifactLifetime(TimeSpan lifetime)
        => Configure(options => options.ArtifactLifetime = lifetime);

    /// <summary>
    /// Enables SAML 2.0 single logout (SAML profiles, 4.4). The login identifier claim type must also be
    /// configured using <see cref="SetLoginIdClaimType(string)"/> and the OpenIddict core services registered.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerSamlBuilder"/> instance.</returns>
    public OpenIddictServerSamlBuilder EnableSingleLogout()
        => Configure(options => options.EnableSingleLogout = true);

    /// <summary>
    /// Sets the claim type of the authenticated principal containing the login identifier.
    /// </summary>
    /// <param name="type">The claim type.</param>
    /// <returns>The <see cref="OpenIddictServerSamlBuilder"/> instance.</returns>
    public OpenIddictServerSamlBuilder SetLoginIdClaimType(string type)
    {
        ArgumentException.ThrowIfNullOrEmpty(type);

        return Configure(options => options.LoginIdClaimType = type);
    }

    /// <summary>
    /// Sets the maximum amount of time allowed to send a logout request using the SOAP binding.
    /// </summary>
    /// <param name="timeout">The timeout.</param>
    /// <returns>The <see cref="OpenIddictServerSamlBuilder"/> instance.</returns>
    public OpenIddictServerSamlBuilder SetSingleLogoutTimeout(TimeSpan timeout)
        => Configure(options => options.SingleLogoutTimeout = timeout);

    /// <summary>
    /// Sets the maximum amount of time a service provider has to return a front-channel logout response.
    /// </summary>
    /// <param name="lifetime">The lifetime.</param>
    /// <returns>The <see cref="OpenIddictServerSamlBuilder"/> instance.</returns>
    public OpenIddictServerSamlBuilder SetLogoutStateLifetime(TimeSpan lifetime)
        => Configure(options => options.LogoutStateLifetime = lifetime);

    /// <summary>
    /// Accepts logout requests that don't include any SessionIndex element (which session participants must include per
    /// SAML profiles, 4.4.4.1): the sessions of the NameID belonging to the login of the authenticated user are terminated.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerSamlBuilder"/> instance.</returns>
    public OpenIddictServerSamlBuilder AcceptLogoutRequestsWithoutSessionIndex()
        => Configure(options => options.AcceptLogoutRequestsWithoutSessionIndex = true);

    /// <summary>
    /// Registers a custom SOAP client, used to send logout requests using the SOAP binding.
    /// </summary>
    /// <typeparam name="TClient">The type of the SOAP client.</typeparam>
    /// <param name="lifetime">The lifetime of the SOAP client.</param>
    /// <returns>The <see cref="OpenIddictServerSamlBuilder"/> instance.</returns>
    public OpenIddictServerSamlBuilder SetSoapClient<
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TClient>(
        ServiceLifetime lifetime = ServiceLifetime.Singleton)
        where TClient : class, IOpenIddictServerSamlSoapClient
    {
        Services.Replace(new ServiceDescriptor(typeof(IOpenIddictServerSamlSoapClient), typeof(TClient), lifetime));

        return this;
    }

    /// <summary>
    /// Disables request replay protection: authentication requests can then be replayed during their validity window and
    /// request states can be used multiple times until they expire. Disabling replay protection is not recommended.
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerSamlBuilder"/> instance.</returns>
    public OpenIddictServerSamlBuilder DisableRequestReplayProtection()
        => Configure(options => options.EnableRequestReplayProtection = false);

    /// <summary>
    /// Sets the default algorithms used to encrypt assertions for the service providers requiring encrypted assertions.
    /// </summary>
    /// <param name="dataEncryptionAlgorithm">The data encryption algorithm (AES-256-GCM or AES-256-CBC).</param>
    /// <param name="keyTransportAlgorithm">The key transport algorithm (RSA-OAEP-MGF1P or RSA-OAEP).</param>
    /// <returns>The <see cref="OpenIddictServerSamlBuilder"/> instance.</returns>
    public OpenIddictServerSamlBuilder SetEncryptionAlgorithms(string dataEncryptionAlgorithm, string keyTransportAlgorithm)
    {
        ArgumentException.ThrowIfNullOrEmpty(dataEncryptionAlgorithm);
        ArgumentException.ThrowIfNullOrEmpty(keyTransportAlgorithm);

        return Configure(options =>
        {
            options.DataEncryptionAlgorithm = dataEncryptionAlgorithm;
            options.KeyTransportAlgorithm = keyTransportAlgorithm;
        });
    }

    /// <summary>
    /// Sets the value of the WantAuthnRequestsSigned attribute published in the metadata.
    /// </summary>
    /// <param name="value">The value.</param>
    /// <returns>The <see cref="OpenIddictServerSamlBuilder"/> instance.</returns>
    public OpenIddictServerSamlBuilder SetWantAuthenticationRequestsSigned(bool value)
        => Configure(options => options.WantAuthenticationRequestsSigned = value);

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
