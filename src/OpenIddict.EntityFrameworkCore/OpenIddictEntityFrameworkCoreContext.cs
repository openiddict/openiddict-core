/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;

namespace OpenIddict.EntityFrameworkCore;

/// <inheritdoc/>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictEntityFrameworkCoreContext<TContext> : IOpenIddictEntityFrameworkCoreContext
    where TContext : DbContext
{
    private readonly TContext? _context;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictEntityFrameworkCoreContext{TContext}"/> class.
    /// </summary>
    public OpenIddictEntityFrameworkCoreContext()
    {
    }

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictEntityFrameworkCoreContext{TContext}"/> class.
    /// </summary>
    /// <param name="context">The Entity Framework Core context, if available.</param>
    public OpenIddictEntityFrameworkCoreContext(TContext? context) => _context = context;

    /// <inheritdoc/>
    public ValueTask<DbContext> GetDbContextAsync(CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return new(Task.FromCanceled<DbContext>(cancellationToken));
        }

        if (_context is not DbContext context)
        {
            return new(Task.FromException<DbContext>(new InvalidOperationException(SR.GetResourceString(SR.ID0471))));
        }

        return new(context);
    }
}
