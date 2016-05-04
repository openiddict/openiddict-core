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
    /// Provides methods allowing to manage the authorizations stored in the store.
    /// </summary>
    /// <typeparam name="TAuthorization">The type of the Authorization entity.</typeparam>
    public class OpenIddictAuthorizationManager<TAuthorization> where TAuthorization : class {
        public OpenIddictAuthorizationManager(
            [NotNull] IServiceProvider services,
            [NotNull] IOpenIddictAuthorizationStore<TAuthorization> store,
            [NotNull] ILogger<OpenIddictAuthorizationManager<TAuthorization>> logger) {
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
        protected IOpenIddictAuthorizationStore<TAuthorization> Store { get; }
    }
}