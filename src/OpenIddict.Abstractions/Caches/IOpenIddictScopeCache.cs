/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Threading;
using System.Threading.Tasks;
using JetBrains.Annotations;

namespace OpenIddict.Abstractions
{
    /// <summary>
    /// Provides methods allowing to cache scopes after retrieving them from the store.
    /// </summary>
    /// <typeparam name="TScope">The type of the Scope entity.</typeparam>
    public interface IOpenIddictScopeCache<TScope> where TScope : class
    {
        /// <summary>
        /// Add the specified scope to the cache.
        /// </summary>
        /// <param name="scope">The scope to add to the cache.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        Task AddAsync([NotNull] TScope scope, CancellationToken cancellationToken);

        /// <summary>
        /// Retrieves a scope using its unique identifier.
        /// </summary>
        /// <param name="identifier">The unique identifier associated with the scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the scope corresponding to the identifier.
        /// </returns>
        ValueTask<TScope> FindByIdAsync([NotNull] string identifier, CancellationToken cancellationToken);

        /// <summary>
        /// Retrieves a scope using its name.
        /// </summary>
        /// <param name="name">The name associated with the scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the scope corresponding to the specified name.
        /// </returns>
        ValueTask<TScope> FindByNameAsync([NotNull] string name, CancellationToken cancellationToken);

        /// <summary>
        /// Retrieves a list of scopes using their name.
        /// </summary>
        /// <param name="names">The names associated with the scopes.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the scopes corresponding to the specified names.
        /// </returns>
        ValueTask<ImmutableArray<TScope>> FindByNamesAsync(ImmutableArray<string> names, CancellationToken cancellationToken);

        /// <summary>
        /// Retrieves all the scopes that contain the specified resource.
        /// </summary>
        /// <param name="resource">The resource associated with the scopes.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the scopes associated with the specified resource.
        /// </returns>
        ValueTask<ImmutableArray<TScope>> FindByResourceAsync([NotNull] string resource, CancellationToken cancellationToken);

        /// <summary>
        /// Removes the specified scope from the cache.
        /// </summary>
        /// <param name="scope">The scope to remove from the cache.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        Task RemoveAsync([NotNull] TScope scope, CancellationToken cancellationToken);
    }
}
