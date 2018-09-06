/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Server
{
    /// <summary>
    /// Represents the state of an event triggered by the OpenIddict
    /// server components and processed by user-defined handlers.
    /// </summary>
    public enum OpenIddictServerEventState
    {
        /// <summary>
        /// Marks the event as unhandled, allowing the event service to invoke the
        /// other event handlers registered in the dependency injection container.
        /// Using this value is recommended for event handlers that don't produce
        /// an immediate response (i.e that don't call context.HandleResponse(),
        /// context.SkipHandler(), context.Validate() or context.Reject()).
        /// </summary>
        Unhandled = 0,

        /// <summary>
        /// Marks the event as fully handled, preventing the event service from invoking
        /// other event handlers registered in the dependency injection container.
        /// Using this value is recommended for event handlers that produce an
        /// immediate response (i.e that call context.HandleResponse(),
        /// context.SkipHandler(), context.Validate() or context.Reject()).
        /// </summary>
        Handled = 1
    }
}
