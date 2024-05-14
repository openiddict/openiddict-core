/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Validation.Owin;

/// <summary>
/// Provides various settings needed to configure the OpenIddict OWIN validation integration.
/// </summary>
public sealed class OpenIddictValidationOwinOptions : AuthenticationOptions
{
    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictValidationOwinOptions"/> class.
    /// </summary>
    public OpenIddictValidationOwinOptions()
        : base(OpenIddictValidationOwinDefaults.AuthenticationType)
        => AuthenticationMode = AuthenticationMode.Passive;

    /// <summary>
    /// Gets or sets a boolean indicating whether the built-in logic extracting
    /// access tokens from the standard "Authorization" header should be disabled.
    /// </summary>
    /// <remarks>
    /// Disabling access token extraction from the "Authorization" header is NOT recommended.
    /// </remarks>
    public bool DisableAccessTokenExtractionFromAuthorizationHeader { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether the built-in logic extracting access
    /// tokens from the standard "access_token" body form parameter should be disabled.
    /// </summary>
    public bool DisableAccessTokenExtractionFromBodyForm { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether the built-in logic extracting access
    /// tokens from the standard "access_token" query string parameter should be disabled.
    /// </summary>
    public bool DisableAccessTokenExtractionFromQueryString { get; set; }

    /// <summary>
    /// Gets or sets the optional "realm" value returned to the caller as part of the WWW-Authenticate header.
    /// </summary>
    public string? Realm { get; set; }
}
