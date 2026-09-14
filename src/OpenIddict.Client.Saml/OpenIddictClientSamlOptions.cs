/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Security.Cryptography.X509Certificates;

namespace OpenIddict.Client.Saml;

/// <summary>
/// Provides various settings needed to configure the OpenIddict SAML 2.0 service provider.
/// </summary>
public sealed class OpenIddictClientSamlOptions
{
    /// <summary>
    /// Gets or sets the entity identifier of the service provider (used as the Issuer of the
    /// authentication requests and as the expected audience of the assertions).
    /// </summary>
    public string? EntityId { get; set; }

    /// <summary>
    /// Gets the X.509 certificates (with an RSA private key) used to sign authentication requests.
    /// All the certificates are published in the metadata; the first certificate that is currently valid is used to sign.
    /// </summary>
    public List<X509Certificate2> SigningCertificates { get; } = [];

    /// <summary>
    /// Gets the X.509 certificates (with an RSA private key) used to decrypt encrypted assertions and identifiers.
    /// All the certificates are published in the metadata and are tried in order when decrypting.
    /// </summary>
    public List<X509Certificate2> EncryptionCertificates { get; } = [];

    /// <summary>
    /// Gets or sets the XML signature algorithm used to sign authentication requests.
    /// </summary>
    public string SignatureAlgorithm { get; set; } = OpenIddictClientSamlConstants.SignatureAlgorithms.RsaSha256;

    /// <summary>
    /// Gets or sets the XML digest algorithm used to sign authentication requests.
    /// </summary>
    public string DigestAlgorithm { get; set; } = OpenIddictClientSamlConstants.DigestAlgorithms.Sha256;

    /// <summary>
    /// Gets or sets the clock skew tolerated when validating the lifetime of assertions. By default, 2 minutes.
    /// </summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(2);

    /// <summary>
    /// Gets or sets the lifetime of the request state created when an authentication request is sent. By default, 15 minutes.
    /// </summary>
    public TimeSpan RequestStateLifetime { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Gets or sets the maximum size, in bytes, of the decoded SAML responses. By default, 256 KiB.
    /// </summary>
    public int MaximumMessageSize { get; set; } = 256 * 1024;

    /// <summary>
    /// Gets or sets the maximum size, in bytes, of the identity provider metadata documents. By default, 4 MiB.
    /// </summary>
    public int MaximumMetadataSize { get; set; } = 4 * 1024 * 1024;

    /// <summary>
    /// Gets or sets the duration during which imported identity provider metadata is cached. By default, 24 hours.
    /// </summary>
    public TimeSpan MetadataRefreshInterval { get; set; } = TimeSpan.FromHours(24);

    /// <summary>
    /// Gets or sets the duration during which the dynamic registrations resolved from
    /// <see cref="IOpenIddictClientSamlRegistrationProvider"/> implementations are cached by identifier.
    /// If set to <see langword="null"/> or <see cref="TimeSpan.Zero"/>, dynamic registrations are not cached.
    /// </summary>
    public TimeSpan? DynamicRegistrationCacheLifetime { get; set; } = TimeSpan.FromMinutes(30);

    /// <summary>
    /// Gets the identity provider registrations registered in the options.
    /// </summary>
    public List<OpenIddictClientSamlRegistration> Registrations { get; } = [];

    /// <summary>
    /// Gets or sets the time provider.
    /// </summary>
    public TimeProvider TimeProvider { get; set; } = default!;
}
