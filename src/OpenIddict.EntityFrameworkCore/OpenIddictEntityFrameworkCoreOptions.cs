/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.EntityFrameworkCore;

/// <summary>
/// Provides various settings needed to configure
/// the OpenIddict Entity Framework Core integration.
/// </summary>
public sealed class OpenIddictEntityFrameworkCoreOptions
{
    /// <summary>
    /// Gets or sets the concrete type of the <see cref="DbContext"/> used by the
    /// OpenIddict Entity Framework Core stores. If this property is not populated,
    /// an exception is thrown at runtime when trying to use the stores.
    /// </summary>
    public Type? DbContextType { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether bulk operations should be disabled.
    /// </summary>
    /// <remarks>
    /// Note: bulk operations are only supported when targeting .NET 7.0 and higher.
    /// </remarks>
    public bool DisableBulkOperations { get; set; }
}
