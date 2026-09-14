/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Client.Saml.AspNetCore;

/// <summary>
/// Provides various settings needed to configure the OpenIddict SAML 2.0 service provider ASP.NET Core integration.
/// </summary>
public sealed class OpenIddictClientSamlAspNetCoreOptions
{
    /// <summary>
    /// Gets or sets the path of the assertion consumer service (HTTP-POST binding).
    /// </summary>
    public PathString AssertionConsumerServicePath { get; set; } = "/saml/acs";

    /// <summary>
    /// Gets or sets the path of the service provider metadata endpoint.
    /// </summary>
    public PathString MetadataPath { get; set; } = "/saml/metadata";

    /// <summary>
    /// Gets or sets the authentication scheme used to persist the principal created from validated
    /// assertions (e.g the cookies scheme). If <see langword="null"/>, the default sign-in scheme is used.
    /// </summary>
    public string? SignInScheme { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether requests received by the assertion consumer service are passed
    /// to the rest of the pipeline once validated, so that the application can call <c>AuthenticateAsync()</c>
    /// with <see cref="OpenIddictClientSamlAspNetCoreDefaults.AuthenticationScheme"/> to retrieve the principal
    /// and sign the user in itself. If <see langword="false"/>, the user is automatically signed in using
    /// <see cref="SignInScheme"/> and redirected to the return URL.
    /// </summary>
    public bool EnableAssertionConsumerServicePassthrough { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether HTTP requests are accepted by the SAML endpoints
    /// (by default, only HTTPS requests are). Not recommended outside development environments.
    /// </summary>
    public bool DisableTransportSecurityRequirement { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether the provider names of the static and dynamic SAML registrations
    /// are automatically exposed as authentication schemes forwarding to the SAML authentication handler.
    /// </summary>
    public bool DisableAutomaticAuthenticationSchemeForwarding { get; set; }

    /// <summary>
    /// Gets or sets the builder used to create the correlation cookies storing the protected request states.
    /// The relay state is appended to the cookie name. As the assertion consumer service receives cross-site
    /// POST requests, the cookie uses <see cref="SameSiteMode.None"/> and requires HTTPS by default.
    /// </summary>
    public CookieBuilder CorrelationCookie { get; set; } = new()
    {
        HttpOnly = true,
        IsEssential = true,
        Name = ".OpenIddict.Client.Saml.Correlation.",
        SameSite = SameSiteMode.None,
        SecurePolicy = CookieSecurePolicy.Always
    };
}
