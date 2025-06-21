/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;

namespace OpenIddict.EntityFrameworkCore;

/// <inheritdoc/>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class
    OpenIddictEntityFrameworkCoreContext<TWriteContext, TReadContext> : IOpenIddictEntityFrameworkCoreContext
    where TWriteContext : DbContext
    where TReadContext : DbContext
{
    private readonly TWriteContext? _writeContext;

    private readonly TReadContext? _readContext;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictEntityFrameworkCoreContext{TContext,TReadContext}"/> class.
    /// </summary>
    public OpenIddictEntityFrameworkCoreContext()
    {
    }

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictEntityFrameworkCoreContext{TContext,TReadContext}"/> class.
    /// </summary>
    /// <param name="writeContext">The Entity Framework Core context, if available.</param>
    /// <param name="readContext">The Entity Framework Core context, if available.</param>
    public OpenIddictEntityFrameworkCoreContext(TWriteContext? writeContext, TReadContext? readContext)
    {
        _writeContext = writeContext;
        _readContext = readContext;
    }

    /// <inheritdoc/>
    public ValueTask<DbContext> GetWriteDbContextAsync(CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return new(Task.FromCanceled<DbContext>(cancellationToken));
        }

        if (_writeContext is not DbContext context)
        {
            return new(Task.FromException<DbContext>(new InvalidOperationException(SR.GetResourceString(SR.ID0471))));
        }

        return new(context);
    }

    /// <inheritdoc/>
    public ValueTask<DbContext> GetReadDbContextAsync(CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return new(Task.FromCanceled<DbContext>(cancellationToken));
        }

        if (_readContext is null)
        {
            return GetWriteDbContextAsync(cancellationToken);
        }

        if (_readContext is not DbContext context)
        {
            return new(Task.FromException<DbContext>(new InvalidOperationException(SR.GetResourceString(SR.ID0471))));
        }

        return new(context);
    }
}