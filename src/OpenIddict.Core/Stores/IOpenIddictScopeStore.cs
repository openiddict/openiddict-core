/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict {
    /// <summary>
    /// Provides an abstraction for a store which manages authorization scopes.
    /// </summary>
    /// <typeparam name="TScope">The type encapsulating an authorization scope.</typeparam>
    public interface IOpenIddictScopeStore<TScope> where TScope : class { }
}