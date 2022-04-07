using Microsoft.Extensions.DependencyInjection;

namespace OpenIddict.Core;

/// <summary>
/// Exposes a method allowing to resolve a token store.
/// </summary>
public class OpenIddictTokenStoreResolver : IOpenIddictTokenStoreResolver
{
    private readonly IServiceProvider _provider;

    public OpenIddictTokenStoreResolver(IServiceProvider provider!!)
        => _provider = provider;

    /// <summary>
    /// Returns a token store compatible with the specified token type or throws an
    /// <see cref="InvalidOperationException"/> if no store can be built using the specified type.
    /// </summary>
    /// <typeparam name="TToken">The type of the Token entity.</typeparam>
    /// <returns>An <see cref="IOpenIddictTokenStore{TToken}"/>.</returns>
    public IOpenIddictTokenStore<TToken> Get<TToken>() where TToken : class
        => _provider.GetService<IOpenIddictTokenStore<TToken>>() ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0231));
}
