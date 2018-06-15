using System.Threading;
using System.Threading.Tasks;
using JetBrains.Annotations;

namespace OpenIddict.Validation
{
    /// <summary>
    /// Dispatches events by invoking the corresponding handlers.
    /// </summary>
    public interface IOpenIddictValidationEventService
    {
        /// <summary>
        /// Publishes a new event.
        /// </summary>
        /// <typeparam name="TEvent">The type of the event to publish.</typeparam>
        /// <param name="notification">The event to publish.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        Task PublishAsync<TEvent>([NotNull] TEvent notification, CancellationToken cancellationToken = default)
            where TEvent : class, IOpenIddictValidationEvent;
    }
}
