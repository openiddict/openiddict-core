/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Threading;
using System.Threading.Tasks;
using JetBrains.Annotations;

namespace OpenIddict.Validation
{
    /// <summary>
    /// Represents a handler able to process <typeparamref name="TEvent"/> events.
    /// </summary>
    /// <typeparam name="TEvent">The type of the events handled by this instance.</typeparam>
    public interface IOpenIddictValidationEventHandler<TEvent> where TEvent : class, IOpenIddictValidationEvent
    {
        /// <summary>
        /// Processes the event.
        /// </summary>
        /// <param name="notification">The event to process.</param>
        /// <param name="cancellationToken">
        /// The <see cref="CancellationToken"/> that can be used to abort the operation.
        /// </param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        Task HandleAsync([NotNull] TEvent notification, CancellationToken cancellationToken);
    }
}
