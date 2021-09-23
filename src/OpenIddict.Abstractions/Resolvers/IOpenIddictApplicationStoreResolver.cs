using System;

namespace OpenIddict.Abstractions;

/// <summary>
/// Exposes a method allowing to resolve an application store.
/// </summary>
public interface IOpenIddictApplicationStoreResolver
{
    /// <summary>
    /// Returns an application store compatible with the specified application type or throws an
    /// <see cref="InvalidOperationException"/> if no store can be built using the specified type.
    /// </summary>
    /// <typeparam name="TApplication">The type of the Application entity.</typeparam>
    /// <returns>An <see cref="IOpenIddictApplicationStore{TApplication}"/>.</returns>
    IOpenIddictApplicationStore<TApplication> Get<TApplication>() where TApplication : class;
}
