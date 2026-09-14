/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Client.Saml.Owin;

/// <summary>
/// Provides various settings needed to configure the OpenIddict SAML 2.0 service provider OWIN/Katana integration.
/// </summary>
public sealed class OpenIddictClientSamlOwinOptions
{
    /// <summary>
    /// Gets or sets the path of the assertion consumer service (HTTP-POST binding).
    /// </summary>
    public PathString AssertionConsumerServicePath { get; set; } = new("/saml/acs");

    /// <summary>
    /// Gets or sets the path of the service provider metadata endpoint.
    /// </summary>
    public PathString MetadataPath { get; set; } = new("/saml/metadata");

    /// <summary>
    /// Gets or sets the authentication type that triggers SAML authentication requests when used in a challenge
    /// (in addition to the provider names of the registrations, unless automatic forwarding is disabled).
    /// </summary>
    public string AuthenticationType { get; set; } = OpenIddictClientSamlOwinDefaults.AuthenticationType;

    /// <summary>
    /// Gets or sets the authentication type used to sign the user in (e.g the cookies authentication type).
    /// The identity created from the assertion is converted to use this authentication type.
    /// </summary>
    public string? SignInAuthenticationType { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether requests received by the assertion consumer service are passed to
    /// the rest of the pipeline once validated: the application is then responsible for retrieving the result using
    /// <c>IOwinContext.GetOpenIddictClientSamlResponse()</c> and for signing the user in.
    /// </summary>
    public bool EnableAssertionConsumerServicePassthrough { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether HTTP requests are accepted by the SAML endpoints
    /// (by default, only HTTPS requests are). Not recommended outside development environments.
    /// </summary>
    public bool DisableTransportSecurityRequirement { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether the provider names of the static and dynamic
    /// SAML registrations are automatically handled as challenge authentication types.
    /// </summary>
    public bool DisableAutomaticAuthenticationTypeForwarding { get; set; }

    /// <summary>
    /// Gets or sets the prefix of the correlation cookies storing the protected request states (the relay state
    /// is appended). As the assertion consumer service receives cross-site POST requests, the cookies are
    /// always issued with the SameSite=None and Secure attributes.
    /// </summary>
    public string CorrelationCookieName { get; set; } = ".OpenIddict.Client.Saml.Correlation.";
}

/// <summary>
/// Exposes the default values used by the OpenIddict SAML 2.0 service provider OWIN/Katana integration.
/// </summary>
public static class OpenIddictClientSamlOwinDefaults
{
    /// <summary>
    /// Default value for <see cref="OpenIddictClientSamlOwinOptions.AuthenticationType"/>.
    /// </summary>
    public const string AuthenticationType = "OpenIddict.Client.Saml.Owin";
}
