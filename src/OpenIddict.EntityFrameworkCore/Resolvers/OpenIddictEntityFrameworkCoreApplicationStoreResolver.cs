/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Concurrent;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.EntityFrameworkCore.Models;
using OpenIddict.Extensions;

namespace OpenIddict.EntityFrameworkCore;

/// <summary>
/// Exposes a method allowing to resolve an application store.
/// </summary>
public class OpenIddictEntityFrameworkCoreApplicationStoreResolver : IOpenIddictApplicationStoreResolver
{
    private readonly TypeResolutionCache _cache;
    private readonly IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions> _options;
    private readonly IServiceProvider _provider;

    public OpenIddictEntityFrameworkCoreApplicationStoreResolver(
        TypeResolutionCache cache,
        IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions> options,
        IServiceProvider provider)
    {
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
    }

    /// <summary>
    /// Returns an application store compatible with the specified application type or throws an
    /// <see cref="InvalidOperationException"/> if no store can be built using the specified type.
    /// </summary>
    /// <typeparam name="TApplication">The type of the Application entity.</typeparam>
    /// <returns>An <see cref="IOpenIddictApplicationStore{TApplication}"/>.</returns>
    public IOpenIddictApplicationStore<TApplication> Get<TApplication>() where TApplication : class
    {
        var store = _provider.GetService<IOpenIddictApplicationStore<TApplication>>();
        if (store is not null)
        {
            return store;
        }

        var type = _cache.GetOrAdd(typeof(TApplication), key =>
        {
            var root = OpenIddictHelpers.FindGenericBaseType(key, typeof(OpenIddictEntityFrameworkCoreApplication<,,>)) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0252));

            var context = _options.CurrentValue.DbContextType ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0253));

            return typeof(OpenIddictEntityFrameworkCoreApplicationStore<,,,,>).MakeGenericType(
                /* TApplication: */ key,
                /* TAuthorization: */ root.GenericTypeArguments[1],
                /* TToken: */ root.GenericTypeArguments[2],
                /* TContext: */ context,
                /* TKey: */ root.GenericTypeArguments[0]);
        });

        return (IOpenIddictApplicationStore<TApplication>) _provider.GetRequiredService(type);
    }

    // Note: Entity Framework Core resolvers are registered as scoped dependencies as their inner
    // service provider must be able to resolve scoped services (typically, the store they return).
    // To avoid having to declare a static type resolution cache, a special cache service is used
    // here and registered as a singleton dependency so that its content persists beyond the scope.
    public class TypeResolutionCache : ConcurrentDictionary<Type, Type> { }
}
