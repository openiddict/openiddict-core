/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Security.Cryptography.X509Certificates;

namespace OpenIddict.Server.Saml;

/// <summary>
/// Represents a SAML 2.0 service provider (relying party) allowed to use the identity provider.
/// </summary>
public sealed class OpenIddictServerSamlServiceProvider
{
    /// <summary>
    /// Gets or sets the entity identifier of the service provider (compared using an ordinal comparison).
    /// </summary>
    public string? EntityId { get; set; }

    /// <summary>
    /// Gets the allowed assertion consumer service URLs. The first URL is used when the authentication
    /// request doesn't specify one; AssertionConsumerServiceIndex values refer to the position in this list.
    /// </summary>
    public List<Uri> AssertionConsumerServiceUrls { get; } = [];

    /// <summary>
    /// Gets the certificates used to validate the signature of the authentication requests.
    /// </summary>
    public List<X509Certificate2> SigningCertificates { get; } = [];

    /// <summary>
    /// Gets or sets a boolean indicating whether authentication requests must be signed. Enabled by default.
    /// </summary>
    public bool RequireSignedAuthenticationRequests { get; set; } = true;

    /// <summary>
    /// Gets or sets the NameID format used in the assertions issued to this service provider.
    /// </summary>
    public string NameIdFormat { get; set; } = OpenIddictServerSamlConstants.NameIdFormats.Unspecified;

    /// <summary>
    /// Gets or sets a boolean indicating whether successful responses should be signed
    /// in addition to the assertion. If <see langword="null"/>, the global option is used.
    /// </summary>
    public bool? SignResponses { get; set; }

    /// <summary>
    /// Gets or sets the lifetime of the assertions. If <see langword="null"/>, the global option is used.
    /// </summary>
    public TimeSpan? AssertionLifetime { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether identity provider-initiated (unsolicited) single sign-on is allowed.
    /// </summary>
    public bool AllowIdentityProviderInitiatedSingleSignOn { get; set; }

    /// <summary>
    /// Gets the mappings between the claim types of the authenticated principal and
    /// the names of the SAML attributes included in the assertions (e.g "email" → "mail").
    /// Claims whose type is not listed are not included.
    /// </summary>
    public Dictionary<string, string> AttributeMappings { get; } = new(StringComparer.Ordinal);
}
