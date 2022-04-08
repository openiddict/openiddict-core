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
/// Exposes a method allowing to resolve an authorization store.
/// </summary>
public class OpenIddictEntityFrameworkCoreAuthorizationStoreResolver : IOpenIddictAuthorizationStoreResolver
{
    private readonly TypeResolutionCache _cache;
    private readonly IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions> _options;
    private readonly IServiceProvider _provider;

    public OpenIddictEntityFrameworkCoreAuthorizationStoreResolver(
        TypeResolutionCache cache!!,
        IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions> options!!,
        IServiceProvider provider!!)
    {
        _cache = cache;
        _options = options;
        _provider = provider;
    }

    /// <summary>
    /// Returns an authorization store compatible with the specified authorization type or throws an
    /// <see cref="InvalidOperationException"/> if no store can be built using the specified type.
    /// </summary>
    /// <typeparam name="TAuthorization">The type of the Authorization entity.</typeparam>
    /// <returns>An <see cref="IOpenIddictAuthorizationStore{TAuthorization}"/>.</returns>
    public IOpenIddictAuthorizationStore<TAuthorization> Get<TAuthorization>() where TAuthorization : class
    {
        var store = _provider.GetService<IOpenIddictAuthorizationStore<TAuthorization>>();
        if (store is not null)
        {
            return store;
        }

        var type = _cache.GetOrAdd(typeof(TAuthorization), key =>
        {
            var root = OpenIddictHelpers.FindGenericBaseType(key, typeof(OpenIddictEntityFrameworkCoreAuthorization<,,>)) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0254));

            var context = _options.CurrentValue.DbContextType ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0253));

            return typeof(OpenIddictEntityFrameworkCoreAuthorizationStore<,,,,>).MakeGenericType(
                /* TAuthorization: */ key,
                /* TApplication: */ root.GenericTypeArguments[1],
                /* TToken: */ root.GenericTypeArguments[2],
                /* TContext: */ context,
                /* TKey: */ root.GenericTypeArguments[0]);
        });

        return (IOpenIddictAuthorizationStore<TAuthorization>) _provider.GetRequiredService(type);
    }

    // Note: Entity Framework Core resolvers are registered as scoped dependencies as their inner
    // service provider must be able to resolve scoped services (typically, the store they return).
    // To avoid having to declare a static type resolution cache, a special cache service is used
    // here and registered as a singleton dependency so that its content persists beyond the scope.
    public class TypeResolutionCache : ConcurrentDictionary<Type, Type> { }
}
