/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using OpenIddict.Core;
using OpenIddict.MongoDb;
using OpenIddict.MongoDb.Models;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes the necessary methods required to configure the OpenIddict MongoDB services.
/// </summary>
public class OpenIddictMongoDbBuilder
{
    /// <summary>
    /// Initializes a new instance of <see cref="OpenIddictMongoDbBuilder"/>.
    /// </summary>
    /// <param name="services">The services collection.</param>
    public OpenIddictMongoDbBuilder(IServiceCollection services)
        => Services = services ?? throw new ArgumentNullException(nameof(services));

    /// <summary>
    /// Gets the services collection.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public IServiceCollection Services { get; }

    /// <summary>
    /// Amends the default OpenIddict MongoDB configuration.
    /// </summary>
    /// <param name="configuration">The delegate used to configure the OpenIddict options.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictMongoDbBuilder"/>.</returns>
    public OpenIddictMongoDbBuilder Configure(Action<OpenIddictMongoDbOptions> configuration)
    {
        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        Services.Configure(configuration);

        return this;
    }

    /// <summary>
    /// Configures OpenIddict to use the specified entity as the default application entity.
    /// </summary>
    /// <returns>The <see cref="OpenIddictMongoDbBuilder"/>.</returns>
    public OpenIddictMongoDbBuilder ReplaceDefaultApplicationEntity<TApplication>()
        where TApplication : OpenIddictMongoDbApplication
    {
        Services.Configure<OpenIddictCoreOptions>(options => options.DefaultApplicationType = typeof(TApplication));

        return this;
    }

    /// <summary>
    /// Configures OpenIddict to use the specified entity as the default authorization entity.
    /// </summary>
    /// <returns>The <see cref="OpenIddictMongoDbBuilder"/>.</returns>
    public OpenIddictMongoDbBuilder ReplaceDefaultAuthorizationEntity<TAuthorization>()
        where TAuthorization : OpenIddictMongoDbAuthorization
    {
        Services.Configure<OpenIddictCoreOptions>(options => options.DefaultAuthorizationType = typeof(TAuthorization));

        return this;
    }

    /// <summary>
    /// Configures OpenIddict to use the specified entity as the default scope entity.
    /// </summary>
    /// <returns>The <see cref="OpenIddictMongoDbBuilder"/>.</returns>
    public OpenIddictMongoDbBuilder ReplaceDefaultScopeEntity<TScope>()
        where TScope : OpenIddictMongoDbScope
    {
        Services.Configure<OpenIddictCoreOptions>(options => options.DefaultScopeType = typeof(TScope));

        return this;
    }

    /// <summary>
    /// Configures OpenIddict to use the specified entity as the default token entity.
    /// </summary>
    /// <returns>The <see cref="OpenIddictMongoDbBuilder"/>.</returns>
    public OpenIddictMongoDbBuilder ReplaceDefaultTokenEntity<TToken>()
        where TToken : OpenIddictMongoDbToken
    {
        Services.Configure<OpenIddictCoreOptions>(options => options.DefaultTokenType = typeof(TToken));

        return this;
    }

    /// <summary>
    /// Replaces the default applications collection name (by default, openiddict.applications).
    /// </summary>
    /// <param name="name">The collection name</param>
    /// <returns>The <see cref="OpenIddictMongoDbBuilder"/>.</returns>
    public OpenIddictMongoDbBuilder SetApplicationsCollectionName(string name)
    {
        if (string.IsNullOrEmpty(name))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0261), nameof(name));
        }

        return Configure(options => options.ApplicationsCollectionName = name);
    }

    /// <summary>
    /// Replaces the default authorizations collection name (by default, openiddict.authorizations).
    /// </summary>
    /// <param name="name">The collection name</param>
    /// <returns>The <see cref="OpenIddictMongoDbBuilder"/>.</returns>
    public OpenIddictMongoDbBuilder SetAuthorizationsCollectionName(string name)
    {
        if (string.IsNullOrEmpty(name))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0261), nameof(name));
        }

        return Configure(options => options.AuthorizationsCollectionName = name);
    }

    /// <summary>
    /// Replaces the default scopes collection name (by default, openiddict.scopes).
    /// </summary>
    /// <param name="name">The collection name</param>
    /// <returns>The <see cref="OpenIddictMongoDbBuilder"/>.</returns>
    public OpenIddictMongoDbBuilder SetScopesCollectionName(string name)
    {
        if (string.IsNullOrEmpty(name))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0261), nameof(name));
        }

        return Configure(options => options.ScopesCollectionName = name);
    }

    /// <summary>
    /// Replaces the default tokens collection name (by default, openiddict.tokens).
    /// </summary>
    /// <param name="name">The collection name</param>
    /// <returns>The <see cref="OpenIddictMongoDbBuilder"/>.</returns>
    public OpenIddictMongoDbBuilder SetTokensCollectionName(string name)
    {
        if (string.IsNullOrEmpty(name))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0261), nameof(name));
        }

        return Configure(options => options.TokensCollectionName = name);
    }

    /// <summary>
    /// Configures the MongoDB stores to use the specified database
    /// instead of retrieving it from the dependency injection container.
    /// </summary>
    /// <param name="database">The <see cref="IMongoDatabase"/>.</param>
    /// <returns>The <see cref="OpenIddictMongoDbBuilder"/>.</returns>
    public OpenIddictMongoDbBuilder UseDatabase(IMongoDatabase database)
    {
        if (database is null)
        {
            throw new ArgumentNullException(nameof(database));
        }

        return Configure(options => options.Database = database);
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
