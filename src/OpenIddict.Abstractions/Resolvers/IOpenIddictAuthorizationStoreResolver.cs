using System;

namespace OpenIddict.Abstractions;

/// <summary>
/// Exposes a method allowing to resolve an authorization store.
/// </summary>
public interface IOpenIddictAuthorizationStoreResolver
{
    /// <summary>
    /// Returns an authorization store compatible with the specified authorization type or throws an
    /// <see cref="InvalidOperationException"/> if no store can be built using the specified type.
    /// </summary>
    /// <typeparam name="TAuthorization">The type of the Authorization entity.</typeparam>
    /// <returns>An <see cref="IOpenIddictAuthorizationStore{TAuthorization}"/>.</returns>
    IOpenIddictAuthorizationStore<TAuthorization> Get<TAuthorization>() where TAuthorization : class;
}
