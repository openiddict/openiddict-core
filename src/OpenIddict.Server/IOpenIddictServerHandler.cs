/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Server;

/// <summary>
/// Represents a handler able to process <typeparamref name="TContext"/> events.
/// </summary>
/// <typeparam name="TContext">The type of the context associated with events handled by this instance.</typeparam>
public interface IOpenIddictServerHandler<in TContext> where TContext : BaseContext
{
    /// <summary>
    /// Processes the event.
    /// </summary>
    /// <param name="context">The context associated with the event to process.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    ValueTask HandleAsync(TContext context);
}
