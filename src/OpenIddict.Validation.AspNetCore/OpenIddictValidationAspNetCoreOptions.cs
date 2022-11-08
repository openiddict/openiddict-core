/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Validation.AspNetCore;

/// <summary>
/// Provides various settings needed to configure the OpenIddict ASP.NET Core validation integration.
/// </summary>
public sealed class OpenIddictValidationAspNetCoreOptions : AuthenticationSchemeOptions
{
    /// <summary>
    /// Gets or sets the optional "realm" value returned to the caller as part of the WWW-Authenticate header.
    /// </summary>
    public string? Realm { get; set; }
}
