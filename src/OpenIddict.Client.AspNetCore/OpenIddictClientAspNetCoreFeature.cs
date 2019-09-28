/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Client.AspNetCore;

/// <summary>
/// Exposes the current client transaction to the ASP.NET Core host.
/// </summary>
public class OpenIddictClientAspNetCoreFeature
{
    /// <summary>
    /// Gets or sets the client transaction that encapsulates all specific
    /// information about an individual OpenID Connect client request.
    /// </summary>
    public OpenIddictClientTransaction? Transaction { get; set; }
}
