/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics.CodeAnalysis;

namespace OpenIddict.Abstractions;

/// <summary>
/// Provides methods allowing to cache applications after retrieving them from the store.
/// </summary>
/// <typeparam name="TApplication">The type of the Application entity.</typeparam>
public interface IOpenIddictApplicationCache<TApplication> where TApplication : class
{
    /// <summary>
    /// Add the specified application to the cache.
    /// </summary>
    /// <param name="application">The application to add to the cache.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask AddAsync(TApplication application, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves an application using its client identifier.
    /// </summary>
    /// <param name="identifier">The client identifier associated with the application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the client application corresponding to the identifier.
    /// </returns>
    ValueTask<TApplication?> FindByClientIdAsync(string identifier, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves an application using its unique identifier.
    /// </summary>
    /// <param name="identifier">The unique identifier associated with the application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the client application corresponding to the identifier.
    /// </returns>
    ValueTask<TApplication?> FindByIdAsync(string identifier, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves all the applications associated with the specified post_logout_redirect_uri.
    /// </summary>
    /// <param name="uri">The post_logout_redirect_uri associated with the applications.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The client applications corresponding to the specified redirect_uri.</returns>
    IAsyncEnumerable<TApplication> FindByPostLogoutRedirectUriAsync(
        [StringSyntax(StringSyntaxAttribute.Uri)] string uri, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves all the applications associated with the specified redirect_uri.
    /// </summary>
    /// <param name="uri">The redirect_uri associated with the applications.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The client applications corresponding to the specified redirect_uri.</returns>
    IAsyncEnumerable<TApplication> FindByRedirectUriAsync(
        [StringSyntax(StringSyntaxAttribute.Uri)] string uri, CancellationToken cancellationToken);

    /// <summary>
    /// Removes the specified application from the cache.
    /// </summary>
    /// <param name="application">The application to remove from the cache.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask RemoveAsync(TApplication application, CancellationToken cancellationToken);
}
