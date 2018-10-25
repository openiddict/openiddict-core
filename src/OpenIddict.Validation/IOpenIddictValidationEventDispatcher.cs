/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Threading.Tasks;
using JetBrains.Annotations;

namespace OpenIddict.Validation
{
    /// <summary>
    /// Dispatches events by invoking the corresponding handlers.
    /// </summary>
    public interface IOpenIddictValidationEventDispatcher
    {
        /// <summary>
        /// Publishes a new event.
        /// </summary>
        /// <typeparam name="TEvent">The type of the event to publish.</typeparam>
        /// <param name="notification">The event to publish.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        Task DispatchAsync<TEvent>([NotNull] TEvent notification) where TEvent : class, IOpenIddictValidationEvent;
    }
}
