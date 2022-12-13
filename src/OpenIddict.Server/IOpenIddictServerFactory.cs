/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;

namespace OpenIddict.Server;

/// <summary>
/// Represents a service responsible for creating transactions.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Never)]
public interface IOpenIddictServerFactory
{
    /// <summary>
    /// Creates a new <see cref="OpenIddictServerTransaction"/> that is used as a
    /// way to store per-request data needed to process the requested operation.
    /// </summary>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous
    /// operation, whose result returns the created transaction.
    /// </returns>
    ValueTask<OpenIddictServerTransaction> CreateTransactionAsync();
}
