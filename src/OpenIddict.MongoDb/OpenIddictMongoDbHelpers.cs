/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;

namespace MongoDB.Driver;

/// <summary>
/// Exposes extensions simplifying the integration between OpenIddict and MongoDB.
/// </summary>
internal static class OpenIddictMongoDbHelpers
{
    /// <summary>
    /// Executes the query and returns the results as a streamed async enumeration.
    /// </summary>
    /// <typeparam name="T">The type of the returned entities.</typeparam>
    /// <param name="source">The query source.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The streamed async enumeration containing the results.</returns>
    internal static IAsyncEnumerable<T> ToAsyncEnumerable<T>(this IAsyncCursorSource<T> source, CancellationToken cancellationToken)
    {
        if (source is null)
        {
            throw new ArgumentNullException(nameof(source));
        }

        return ExecuteAsync(source, cancellationToken);

        static async IAsyncEnumerable<T> ExecuteAsync(IAsyncCursorSource<T> source, [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            using var cursor = await source.ToCursorAsync(cancellationToken);

            while (await cursor.MoveNextAsync(cancellationToken))
            {
                foreach (var element in cursor.Current)
                {
                    yield return element;
                }
            }
        }
    }

    /// <summary>
    /// Executes the query and returns the results as a streamed async enumeration.
    /// </summary>
    /// <typeparam name="T">The type of the returned entities.</typeparam>
    /// <param name="source">The query source.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The streamed async enumeration containing the results.</returns>
    internal static IAsyncEnumerable<T> ToAsyncEnumerable<T>(this IQueryable<T> source, CancellationToken cancellationToken)
    {
        if (source is null)
        {
            throw new ArgumentNullException(nameof(source));
        }

        return ((IAsyncCursorSource<T>) source).ToAsyncEnumerable(cancellationToken);
    }
}
