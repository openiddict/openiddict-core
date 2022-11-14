/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;

namespace OpenIddict.Server.AspNetCore;

/// <summary>
/// Exposes the current server transaction to the ASP.NET Core host.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictServerAspNetCoreFeature
{
    /// <summary>
    /// Gets or sets the server transaction that encapsulates all specific
    /// information about an individual OpenID Connect server request.
    /// </summary>
    public OpenIddictServerTransaction? Transaction { get; set; }
}
