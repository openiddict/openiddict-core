/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Server.AspNetCore;

/// <summary>
/// Exposes the current server transaction to the ASP.NET Core host.
/// </summary>
public class OpenIddictServerAspNetCoreFeature
{
    /// <summary>
    /// Gets or sets the server transaction that encapsulates all specific
    /// information about an individual OpenID Connect server request.
    /// </summary>
    public OpenIddictServerTransaction? Transaction { get; set; }
}
