/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using JetBrains.Annotations;

namespace OpenIddict.Server
{
    /// <summary>
    /// Represents an OpenIddict server event.
    /// </summary>
    /// <typeparam name="TContext">The type of the context instance associated with the event.</typeparam>
    public class OpenIddictServerEvent<TContext> : IOpenIddictServerEvent where TContext : class
    {
        /// <summary>
        /// Creates a new instance of <see cref="OpenIddictServerEvent{TContext}"/>.
        /// </summary>
        /// <param name="context">The context instance associated with the event.</param>
        public OpenIddictServerEvent([NotNull] TContext context)
            => Context = context ?? throw new ArgumentNullException(nameof(context));

        /// <summary>
        /// Gets the context instance associated with the event.
        /// </summary>
        public TContext Context { get; }
    }
}
