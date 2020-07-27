/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Threading.Tasks;
using static OpenIddict.Validation.OpenIddictValidationEvents;

namespace OpenIddict.Validation
{
    /// <summary>
    /// Represents a handler able to process <typeparamref name="TContext"/> events.
    /// </summary>
    /// <typeparam name="TContext">The type of the events handled by this instance.</typeparam>
    public class OpenIddictValidationHandler<TContext> : IOpenIddictValidationHandler<TContext> where TContext : BaseContext
    {
        private readonly Func<TContext, ValueTask> _handler;

        /// <summary>
        /// Creates a new event using the specified handler delegate.
        /// </summary>
        /// <param name="handler">The event handler delegate.</param>
        public OpenIddictValidationHandler(Func<TContext, ValueTask> handler)
            => _handler = handler ?? throw new ArgumentNullException(nameof(handler));

        /// <summary>
        /// Processes the event.
        /// </summary>
        /// <param name="context">The event to process.</param>
        /// <returns>
        /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public ValueTask HandleAsync(TContext context)
            => _handler(context ?? throw new ArgumentNullException(nameof(context)));
    }
}
