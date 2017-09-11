/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Linq;

namespace OpenIddict.Core
{
    /// <summary>
    /// Provides methods allowing to manage the scopes stored in a database.
    /// </summary>
    /// <typeparam name="TScope">The type of the Scope entity.</typeparam>
    public interface IOpenIddictScopeStore<TScope> where TScope : class
    {
        /// <summary>
        /// Gets the scopes as a queryable source, if supported by the store.
        /// </summary>
        IQueryable<TScope> Scopes { get; }
    }
}