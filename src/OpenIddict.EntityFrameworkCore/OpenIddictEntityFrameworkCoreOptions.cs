/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using OpenIddict.EntityFrameworkCore.Factory;

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
    /// Gets or sets the concrete type of the <see cref="IOpeniddictEntityFrameworkCoreContextFactory"/> used by the
    /// OpenIddict Entity Framework Core stores. If this property is not populated,
    /// an exception is thrown at runtime when trying to use the stores.
    /// </summary>
    public Type? DbContextFactoryType { get; set; }
    /// <summary>
    /// Gets or sets a func can be used for non dependecy injection
    /// </summary>
    public Func<IServiceProvider, DbContext>? DbContextFunc { get; set; }
    /// <summary>
    /// Get The DbContext And Check What To Use <see cref="DbContextType"/> or <see cref="DbContextFunc"/>
    /// </summary>
    /// <param name="serviceProvider">ServiceProvider To Get Service</param>
    /// <returns>DbContext</returns>
    /// <exception cref="NullReferenceException">Throws When Both Null</exception>
    public DbContext GetDbContext(IServiceProvider serviceProvider)
    {
        if (DbContextType == null && DbContextFunc == null)
        {
            // Throw NullReferenceException If Both Null
            throw new NullReferenceException($"{nameof(DbContextType)} Or {nameof(DbContextFunc)}");
        }

        // Invoking DbContextFunc
        if (DbContextFunc == null)
        {
            return DbContextFunc.Invoke(serviceProvider);
        }
        // Here We Don't Need To Check 'DbContextType'
        else
        {
            return serviceProvider.GetService(DbContextType) as DbContext;
        }
    }
}
