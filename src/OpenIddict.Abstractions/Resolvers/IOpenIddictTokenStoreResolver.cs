using System;

namespace OpenIddict.Abstractions;

/// <summary>
/// Exposes a method allowing to resolve a token store.
/// </summary>
public interface IOpenIddictTokenStoreResolver
{
    /// <summary>
    /// Returns a token store compatible with the specified token type or throws an
    /// <see cref="InvalidOperationException"/> if no store can be built using the specified type.
    /// </summary>
    /// <typeparam name="TToken">The type of the Token entity.</typeparam>
    /// <returns>An <see cref="IOpenIddictTokenStore{TToken}"/>.</returns>
    IOpenIddictTokenStore<TToken> Get<TToken>() where TToken : class;
}
