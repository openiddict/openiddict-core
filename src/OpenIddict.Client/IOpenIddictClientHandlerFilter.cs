/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Client;

/// <summary>
/// Represents a handler filter responsible for determining whether a
/// handler should process an event depending on the specified context.
/// </summary>
/// <typeparam name="TContext">The type of the context associated with events filtered by this instance.</typeparam>
public interface IOpenIddictClientHandlerFilter<in TContext> where TContext : BaseContext
{
    /// <summary>
    /// Determines whether the handler referencing this filter instance should
    /// be instantiated and process the event, based on the specified context.
    /// </summary>
    /// <param name="context">The context associated with the event to process.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose boolean result determines whether the handler will be invoked or not.
    /// </returns>
    ValueTask<bool> IsActiveAsync(TContext context);
}
