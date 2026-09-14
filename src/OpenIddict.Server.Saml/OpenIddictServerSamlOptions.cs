/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Security.Cryptography.X509Certificates;
using System.Security.Claims;

namespace OpenIddict.Server.Saml;

/// <summary>
/// Provides various settings needed to configure the OpenIddict SAML 2.0 identity provider.
/// </summary>
public sealed class OpenIddictServerSamlOptions
{
    /// <summary>
    /// Gets or sets the entity identifier of the identity provider. If not set,
    /// the absolute issuer URI configured in the server options is used.
    /// </summary>
    public string? EntityId { get; set; }

    /// <summary>
    /// Gets the X.509 certificates used to sign SAML responses and assertions. All the certificates are
    /// published in the metadata; the first certificate that is currently valid is used to sign.
    /// If empty, the X.509 signing certificates registered in the server options are used.
    /// </summary>
    public List<X509Certificate2> SigningCertificates { get; } = [];

    /// <summary>
    /// Gets or sets the XML signature algorithm used to sign responses and assertions.
    /// </summary>
    public string SignatureAlgorithm { get; set; } = OpenIddictServerSamlConstants.SignatureAlgorithms.RsaSha256;

    /// <summary>
    /// Gets or sets the XML digest algorithm used to sign responses and assertions.
    /// </summary>
    public string DigestAlgorithm { get; set; } = OpenIddictServerSamlConstants.DigestAlgorithms.Sha256;

    /// <summary>
    /// Gets or sets a boolean indicating whether successful responses should be signed in addition to the
    /// assertion they contain (assertions are always signed and error responses are always signed).
    /// This setting can be overridden per service provider.
    /// </summary>
    public bool SignResponses { get; set; }

    /// <summary>
    /// Gets or sets the lifetime of the assertions (NotOnOrAfter). By default, 5 minutes.
    /// </summary>
    public TimeSpan AssertionLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Gets or sets the maximum age of the authentication requests, based on their IssueInstant. By default, 5 minutes.
    /// </summary>
    public TimeSpan AuthenticationRequestLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Gets or sets the clock skew tolerated when validating the IssueInstant of authentication requests.
    /// By default, 2 minutes.
    /// </summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(2);

    /// <summary>
    /// Gets or sets the algorithm used to encrypt assertions for the service providers that require encrypted
    /// assertions. This setting can be overridden per service provider. By default, AES-256-GCM.
    /// </summary>
    public string DataEncryptionAlgorithm { get; set; } = OpenIddictServerSamlConstants.DataEncryptionAlgorithms.Aes256Gcm;

    /// <summary>
    /// Gets or sets the algorithm used to encrypt the assertion encryption keys. This setting can be
    /// overridden per service provider. By default, RSA-OAEP (rsa-oaep-mgf1p, SHA-1 digest and MGF1).
    /// </summary>
    public string KeyTransportAlgorithm { get; set; } = OpenIddictServerSamlConstants.KeyTransportAlgorithms.RsaOaepMgf1P;

    /// <summary>
    /// Gets or sets a boolean indicating whether the HTTP-Artifact binding is enabled: responses can then be
    /// returned to the assertion consumer services configured to use it and artifacts can be resolved using
    /// the artifact resolution service (SOAP binding). Disabled by default.
    /// </summary>
    public bool EnableArtifactBinding { get; set; }

    /// <summary>
    /// Gets or sets the lifetime of the artifacts issued using the HTTP-Artifact binding. By default, 1 minute.
    /// </summary>
    public TimeSpan ArtifactLifetime { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// Gets or sets a boolean indicating whether replayed messages are rejected: authentication request identifiers
    /// can only be used once during their validity window and request states can only be used once to return a response.
    /// Enabled by default.
    /// </summary>
    /// <remarks>
    /// The default replay cache uses the <see cref="Microsoft.Extensions.Caching.Distributed.IDistributedCache"/> registered
    /// in the DI container (or a size-limited private in-memory cache): load-balanced deployments must register a shared
    /// distributed cache (or a custom <see cref="IOpenIddictServerSamlReplayCache"/>) for replays to be detected across instances.
    /// When enabled, reloading (or navigating back to) a single sign-on URL returns an error instead of a new response.
    /// Can be disabled using <see cref="Microsoft.Extensions.DependencyInjection.OpenIddictServerSamlBuilder.DisableRequestReplayProtection()"/>.
    /// </remarks>
    public bool EnableRequestReplayProtection { get; set; } = true;

    /// <summary>
    /// Gets or sets the value of the WantAuthnRequestsSigned metadata attribute. If <see langword="null"/>, <see langword="true"/>
    /// is advertised, unless the default service provider store is used and one of the service providers registered in the
    /// options doesn't require signed authentication requests.
    /// </summary>
    public bool? WantAuthenticationRequestsSigned { get; set; }

    /// <summary>
    /// Gets or sets the maximum size, in bytes, of the decoded (and inflated) SAML messages. By default, 64 KiB.
    /// </summary>
    public int MaximumMessageSize { get; set; } = 64 * 1024;

    /// <summary>
    /// Gets the claim types used to resolve the NameID value when the persistent,
    /// transient or unspecified formats are used, in order of preference.
    /// </summary>
    public List<string> NameIdClaimTypes { get; } = [Claims.Subject, ClaimTypes.NameIdentifier];

    /// <summary>
    /// Gets the service providers registered in the options.
    /// </summary>
    public List<OpenIddictServerSamlServiceProvider> ServiceProviders { get; } = [];

    /// <summary>
    /// Gets or sets the time provider. If not set, the time provider of the server options is used.
    /// </summary>
    public TimeProvider TimeProvider { get; set; } = default!;
}
