/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using JetBrains.Annotations;

namespace OpenIddict.Validation
{
    /// <summary>
    /// Represents an OpenIddict validation event.
    /// </summary>
    /// <typeparam name="TContext">The type of the context instance associated with the event.</typeparam>
    public class OpenIddictValidationEvent<TContext> : IOpenIddictValidationEvent where TContext : class
    {
        /// <summary>
        /// Creates a new instance of <see cref="OpenIddictValidationEvent{TContext}"/>.
        /// </summary>
        /// <param name="context">The context instance associated with the event.</param>
        public OpenIddictValidationEvent([NotNull] TContext context)
            => Context = context ?? throw new ArgumentNullException(nameof(context));

        /// <summary>
        /// Gets the context instance associated with the event.
        /// </summary>
        public TContext Context { get; }
    }
}
