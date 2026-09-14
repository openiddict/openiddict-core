/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Server.AspNetCore.AdminUI;

/// <summary>
/// Provides various settings needed to configure the OpenIddict admin UI.
/// </summary>
public sealed class OpenIddictServerAspNetCoreAdminUIOptions
{
    /// <summary>
    /// Gets or sets the number of entries displayed per page (by default, 25; must be between 1 and 1000).
    /// </summary>
    public int PageSize { get; set; } = 25;

    /// <summary>
    /// Gets or sets the title displayed in the header of the admin UI pages.
    /// </summary>
    public string Title { get; set; } = "OpenIddict administration";
}
