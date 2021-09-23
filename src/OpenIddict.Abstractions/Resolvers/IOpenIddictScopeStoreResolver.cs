using System;

namespace OpenIddict.Abstractions;

/// <summary>
/// Exposes a method allowing to resolve a scope store.
/// </summary>
public interface IOpenIddictScopeStoreResolver
{
    /// <summary>
    /// Returns a scope store compatible with the specified scope type or throws an
    /// <see cref="InvalidOperationException"/> if no store can be built using the specified type.
    /// </summary>
    /// <typeparam name="TScope">The type of the Scope entity.</typeparam>
    /// <returns>An <see cref="IOpenIddictScopeStore{TScope}"/>.</returns>
    IOpenIddictScopeStore<TScope> Get<TScope>() where TScope : class;
}
