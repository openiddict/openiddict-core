/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Core;
using OpenIddict.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes the necessary methods required to configure the OpenIddict Entity Framework Core services.
/// </summary>
public class OpenIddictEntityFrameworkCoreBuilder
{
    /// <summary>
    /// Initializes a new instance of <see cref="OpenIddictEntityFrameworkCoreBuilder"/>.
    /// </summary>
    /// <param name="services">The services collection.</param>
    public OpenIddictEntityFrameworkCoreBuilder(IServiceCollection services)
        => Services = services ?? throw new ArgumentNullException(nameof(services));

    /// <summary>
    /// Gets the services collection.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public IServiceCollection Services { get; }

    /// <summary>
    /// Amends the default OpenIddict Entity Framework Core configuration.
    /// </summary>
    /// <param name="configuration">The delegate used to configure the OpenIddict options.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictEntityFrameworkCoreBuilder"/>.</returns>
    public OpenIddictEntityFrameworkCoreBuilder Configure(Action<OpenIddictEntityFrameworkCoreOptions> configuration)
    {
        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        Services.Configure(configuration);

        return this;
    }

    /// <summary>
    /// Configures OpenIddict to use the default OpenIddict
    /// Entity Framework Core entities, with the specified key type.
    /// </summary>
    /// <returns>The <see cref="OpenIddictEntityFrameworkCoreBuilder"/>.</returns>
    public OpenIddictEntityFrameworkCoreBuilder ReplaceDefaultEntities<TKey>()
        where TKey : notnull, IEquatable<TKey>
        => ReplaceDefaultEntities<OpenIddictEntityFrameworkCoreApplication<TKey>,
                                  OpenIddictEntityFrameworkCoreAuthorization<TKey>,
                                  OpenIddictEntityFrameworkCoreScope<TKey>,
                                  OpenIddictEntityFrameworkCoreToken<TKey>, TKey>();

    /// <summary>
    /// Configures OpenIddict to use the specified entities, derived
    /// from the default OpenIddict Entity Framework Core entities.
    /// </summary>
    /// <returns>The <see cref="OpenIddictEntityFrameworkCoreBuilder"/>.</returns>
    public OpenIddictEntityFrameworkCoreBuilder ReplaceDefaultEntities<TApplication, TAuthorization, TScope, TToken, TKey>()
        where TApplication : OpenIddictEntityFrameworkCoreApplication<TKey, TAuthorization, TToken>
        where TAuthorization : OpenIddictEntityFrameworkCoreAuthorization<TKey, TApplication, TToken>
        where TScope : OpenIddictEntityFrameworkCoreScope<TKey>
        where TToken : OpenIddictEntityFrameworkCoreToken<TKey, TApplication, TAuthorization>
        where TKey : notnull, IEquatable<TKey>
    {
        Services.Configure<OpenIddictCoreOptions>(options =>
        {
            options.DefaultApplicationType = typeof(TApplication);
            options.DefaultAuthorizationType = typeof(TAuthorization);
            options.DefaultScopeType = typeof(TScope);
            options.DefaultTokenType = typeof(TToken);
        });

        return this;
    }

    /// <summary>
    /// Configures the OpenIddict Entity Framework Core stores to use the specified database context type.
    /// </summary>
    /// <typeparam name="TContext">The type of the <see cref="DbContext"/> used by OpenIddict.</typeparam>
    /// <returns>The <see cref="OpenIddictEntityFrameworkCoreBuilder"/>.</returns>
    public OpenIddictEntityFrameworkCoreBuilder UseDbContext<TContext>()
        where TContext : DbContext
        => UseDbContext(typeof(TContext));

    /// <summary>
    /// Configures the OpenIddict Entity Framework Core stores to use the specified database context type.
    /// </summary>
    /// <param name="type">The type of the <see cref="DbContext"/> used by OpenIddict.</param>
    /// <returns>The <see cref="OpenIddictEntityFrameworkCoreBuilder"/>.</returns>
    public OpenIddictEntityFrameworkCoreBuilder UseDbContext(Type type)
    {
        if (type is null)
        {
            throw new ArgumentNullException(nameof(type));
        }

        if (!typeof(DbContext).IsAssignableFrom(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0232), nameof(type));
        }

        return Configure(options => options.DbContextType = type);
    }

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals(object? obj) => base.Equals(obj);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => base.GetHashCode();

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override string? ToString() => base.ToString();
}
