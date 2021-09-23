using Microsoft.Extensions.DependencyInjection;

namespace OpenIddict.Core;

/// <summary>
/// Exposes a method allowing to resolve a scope store.
/// </summary>
public class OpenIddictScopeStoreResolver : IOpenIddictScopeStoreResolver
{
    private readonly IServiceProvider _provider;

    public OpenIddictScopeStoreResolver(IServiceProvider provider)
        => _provider = provider;

    /// <summary>
    /// Returns a scope store compatible with the specified scope type or throws an
    /// <see cref="InvalidOperationException"/> if no store can be built using the specified type.
    /// </summary>
    /// <typeparam name="TScope">The type of the Scope entity.</typeparam>
    /// <returns>An <see cref="IOpenIddictScopeStore{TScope}"/>.</returns>
    public IOpenIddictScopeStore<TScope> Get<TScope>() where TScope : class
        => _provider.GetService<IOpenIddictScopeStore<TScope>>() ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0230));
}
