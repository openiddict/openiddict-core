/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.EntityFramework;

/// <summary>
/// Provides various settings needed to configure
/// the OpenIddict Entity Framework 6.x integration.
/// </summary>
public sealed class OpenIddictEntityFrameworkOptions
{
    /// <summary>
    /// Gets or sets the concrete type of the <see cref="DbContext"/> used by the
    /// OpenIddict Entity Framework 6.x stores. If this property is not populated,
    /// an exception is thrown at runtime when trying to use the stores.
    /// </summary>
    public Type? DbContextType { get; set; }
}
