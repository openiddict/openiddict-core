/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Threading;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace OpenIddict {
    /// <summary>
    /// Provides methods allowing to manage the scopes stored in the store.
    /// </summary>
    /// <typeparam name="TScope">The type of the Scope entity.</typeparam>
    public class OpenIddictScopeManager<TScope> where TScope : class {
        public OpenIddictScopeManager(
            [NotNull] IServiceProvider services,
            [NotNull] IOpenIddictAuthorizationStore<TScope> store,
            [NotNull] ILogger<OpenIddictAuthorizationManager<TScope>> logger) {
            Context = services?.GetRequiredService<IHttpContextAccessor>()?.HttpContext;
            Logger = logger;
            Store = store;
        }

        /// <summary>
        /// Gets the HTTP context associated with the current manager.
        /// </summary>
        protected HttpContext Context { get; }

        /// <summary>
        /// Gets the cancellation token used to abort async operations.
        /// </summary>
        protected CancellationToken CancellationToken => Context?.RequestAborted ?? CancellationToken.None;

        /// <summary>
        /// Gets the logger associated with the current manager.
        /// </summary>
        protected ILogger Logger { get; }

        /// <summary>
        /// Gets the store associated with the current manager.
        /// </summary>
        protected IOpenIddictAuthorizationStore<TScope> Store { get; }
    }
}