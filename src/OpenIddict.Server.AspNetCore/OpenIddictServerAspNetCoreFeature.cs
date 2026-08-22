/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;

namespace OpenIddict.Server.AspNetCore;

/// <summary>
/// Exposes the current server transaction to the ASP.NET Core application.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictServerAspNetCoreFeature
{
    /// <summary>
    /// Gets the transaction that encapsulates all specific information about an individual operation.
    /// </summary>
    public required OpenIddictServerTransaction Transaction
    {
        get;
        init { ArgumentNullException.ThrowIfNull(value); field = value; }
    }
}
