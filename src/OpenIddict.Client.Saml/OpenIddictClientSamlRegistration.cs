/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Security.Cryptography.X509Certificates;

namespace OpenIddict.Client.Saml;

/// <summary>
/// Represents a SAML 2.0 identity provider registration used by the OpenIddict SAML service provider.
/// </summary>
public sealed class OpenIddictClientSamlRegistration
{
    /// <summary>
    /// Gets or sets the unique identifier of the registration. If not set, a stable identifier
    /// is computed from the identity provider entity identifier (or metadata address) and the provider name.
    /// </summary>
    public string? RegistrationId { get; set; }

    /// <summary>
    /// Gets or sets the provider name, used as the authentication scheme/type by the hosts.
    /// </summary>
    public string? ProviderName { get; set; }

    /// <summary>
    /// Gets or sets the provider display name.
    /// </summary>
    public string? ProviderDisplayName { get; set; }

    /// <summary>
    /// Gets or sets the entity identifier of the identity provider. When metadata is used, the entity
    /// identifier is resolved from the metadata document if not set (and must match it if set).
    /// </summary>
    public string? IdentityProviderEntityId { get; set; }

    /// <summary>
    /// Gets or sets the address (HTTPS or file URI) of the identity provider metadata document. When set,
    /// the single sign-on service URL and the signing certificates are imported from the metadata, unless
    /// they are explicitly set in this registration (in which case the explicit values are used).
    /// </summary>
    public Uri? MetadataAddress { get; set; }

    /// <summary>
    /// Gets the X.509 certificates used to validate the signature of the metadata document. If not empty,
    /// the metadata document MUST be signed using one of these certificates.
    /// </summary>
    public List<X509Certificate2> MetadataSigningCertificates { get; } = [];

    /// <summary>
    /// Gets or sets the URL of the single sign-on service of the identity provider.
    /// </summary>
    public Uri? SingleSignOnServiceUrl { get; set; }

    /// <summary>
    /// Gets or sets the binding used to send authentication requests (HTTP-Redirect by default).
    /// </summary>
    public string AuthenticationRequestBinding { get; set; } = OpenIddictClientSamlConstants.Bindings.HttpRedirect;

    /// <summary>
    /// Gets the X.509 certificates used by the identity provider to sign responses and assertions.
    /// </summary>
    public List<X509Certificate2> SigningCertificates { get; } = [];

    /// <summary>
    /// Gets or sets a boolean indicating whether authentication requests are signed. If not set, requests
    /// are signed when a service provider signing certificate is available or when the metadata requires it.
    /// </summary>
    public bool? SignAuthenticationRequests { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether assertions must be individually signed
    /// (by default, an assertion contained in a signed response is also accepted).
    /// </summary>
    public bool RequireSignedAssertions { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether assertions must be encrypted.
    /// </summary>
    public bool RequireEncryptedAssertions { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether unsolicited (identity provider-initiated) responses are accepted.
    /// Enabling this setting exposes the service provider to login CSRF attacks and is NOT recommended.
    /// </summary>
    public bool AllowUnsolicitedResponses { get; set; }

    /// <summary>
    /// Gets or sets the NameID format requested in authentication requests, if any.
    /// </summary>
    public string? NameIdFormat { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether the identity provider must authenticate the user again.
    /// </summary>
    public bool ForceAuthentication { get; set; }

    /// <summary>
    /// Gets the authentication context classes requested (using the exact comparison), if any.
    /// </summary>
    public List<string> AuthenticationContextClasses { get; } = [];

    /// <summary>
    /// Gets the mappings used to convert SAML attribute names to claim types. Attributes that are not mapped
    /// are added to the principal using their SAML attribute name as the claim type.
    /// </summary>
    public Dictionary<string, string> AttributeMappings { get; } = new(StringComparer.Ordinal);
}
