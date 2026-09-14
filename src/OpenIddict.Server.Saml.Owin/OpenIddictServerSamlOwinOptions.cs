/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Server.Saml.Owin;

/// <summary>
/// Provides various settings needed to configure the OpenIddict SAML 2.0 identity provider OWIN/Katana integration.
/// </summary>
public sealed class OpenIddictServerSamlOwinOptions
{
    /// <summary>
    /// Gets or sets the path of the metadata endpoint.
    /// </summary>
    public PathString MetadataPath { get; set; } = new("/saml/metadata");

    /// <summary>
    /// Gets or sets the path of the single sign-on endpoint.
    /// </summary>
    public PathString SingleSignOnPath { get; set; } = new("/saml/sso");

    /// <summary>
    /// Gets or sets the path of the artifact resolution endpoint (SOAP binding), that
    /// is only handled when the HTTP-Artifact binding is enabled in the SAML options.
    /// </summary>
    public PathString ArtifactResolutionPath { get; set; } = new("/saml/artifact");

    /// <summary>
    /// Gets or sets the authentication type used to authenticate and challenge the user (e.g the cookies authentication type).
    /// </summary>
    public string? AuthenticationType { get; set; }

    /// <summary>
    /// Gets or sets the lifetime of the protected request state attached to the return URL
    /// while the user is authenticated. By default, 1 hour.
    /// </summary>
    public TimeSpan RequestStateLifetime { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Gets or sets a boolean indicating whether HTTP requests are accepted (by default, only HTTPS requests are).
    /// </summary>
    public bool DisableTransportSecurityRequirement { get; set; }
}
