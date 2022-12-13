/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;

namespace OpenIddict.Server;

/// <summary>
/// Represents a service able to dispatch events to a list of handlers.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public interface IOpenIddictServerDispatcher
{
    /// <summary>
    /// Dispatches an event of the specified type to the handlers that
    /// implement <see cref="IOpenIddictServerHandler{TContext}"/>.
    /// </summary>
    /// <typeparam name="TContext">The type of the context associated with the event to dispatch.</typeparam>
    /// <param name="context">The context associated with the event to dispatch.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    ValueTask DispatchAsync<TContext>(TContext context) where TContext : BaseContext;
}
