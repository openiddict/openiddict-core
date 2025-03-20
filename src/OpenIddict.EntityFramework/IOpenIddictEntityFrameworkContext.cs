/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;

namespace OpenIddict.EntityFramework;

/// <summary>
/// Exposes the Entity Framework context used by the OpenIddict stores.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public interface IOpenIddictEntityFrameworkContext
{
    /// <summary>
    /// Gets the <see cref="DbContext"/>.
    /// </summary>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the
    /// asynchronous operation, whose result returns the <see cref="DbContext"/>.
    /// </returns>
    ValueTask<DbContext> GetDbContextAsync(CancellationToken cancellationToken);
}
