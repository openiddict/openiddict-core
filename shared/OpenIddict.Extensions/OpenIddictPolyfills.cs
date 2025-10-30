/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics;

namespace OpenIddict.Extensions;

/// <summary>
/// Exposes common polyfills used by the OpenIddict assemblies.
/// </summary>
internal static class OpenIddictPolyfills
{
    extension<TSource>(IEnumerable<TSource> source)
    {
#if !SUPPORTS_CHUNK_LINQ_EXTENSION
        /// <summary>
        /// Split the elements of a sequence into chunks of size at most <paramref name="size"/>.
        /// </summary>
        /// <remarks>
        /// Every chunk except the last will be of size <paramref name="size"/>.
        /// The last chunk will contain the remaining elements and may be of a smaller size.
        /// </remarks>
        /// <param name="size">Maximum size of each chunk.</param>
        /// <returns>
        /// An <see cref="IEnumerable{T}"/> that contains the elements of the input
        /// sequence split into chunks of size <paramref name="size"/>.
        /// </returns>
        public IEnumerable<TSource[]> Chunk(int size)
        {
            // Note: this polyfill was directly copied from .NET's source code:
            // https://github.com/dotnet/runtime/blob/main/src/libraries/System.Linq/src/System/Linq/Chunk.cs.

            using IEnumerator<TSource> enumerator = source.GetEnumerator();

            if (enumerator.MoveNext())
            {
                var count = Math.Min(size, 4);
                int index;

                do
                {
                    var array = new TSource[count];

                    array[0] = enumerator.Current;
                    index = 1;

                    if (size != array.Length)
                    {
                        for (; index < size && enumerator.MoveNext(); index++)
                        {
                            if (index >= array.Length)
                            {
                                count = (int) Math.Min((uint) size, 2 * (uint) array.Length);
                                Array.Resize(ref array, count);
                            }

                            array[index] = enumerator.Current;
                        }
                    }

                    else
                    {
                        var local = array;
                        Debug.Assert(local.Length == size);
                        for (; (uint) index < (uint) local.Length && enumerator.MoveNext(); index++)
                        {
                            local[index] = enumerator.Current;
                        }
                    }

                    if (index != array.Length)
                    {
                        Array.Resize(ref array, index);
                    }

                    yield return array;
                }

                while (index >= size && enumerator.MoveNext());
            }
        }
#endif

#if !SUPPORTS_TOHASHSET_LINQ_EXTENSION
        /// <summary>
        /// Creates a new <see cref="HashSet{T}"/> instance and imports the elements present in the specified source.
        /// </summary>
        /// <param name="comparer">The comparer to use.</param>
        /// <returns>A new <see cref="HashSet{T}"/> instance and imports the elements present in the specified source.</returns>
        public HashSet<TSource> ToHashSet(IEqualityComparer<TSource>? comparer) => new(source, comparer);
#endif
    }

    extension(Task task)
    {
#if !SUPPORTS_TASK_WAIT_ASYNC
        /// <summary>
        /// Waits until the specified task returns a result or the cancellation token is signaled.
        /// </summary>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        /// <exception cref="OperationCanceledException">The specified <paramref name="cancellationToken"/> is signaled.</exception>
        public async Task WaitAsync(CancellationToken cancellationToken)
        {
            var source = new TaskCompletionSource<bool>(TaskCreationOptions.None);

            using (cancellationToken.Register(static state => ((TaskCompletionSource<bool>) state!).SetResult(true), source))
            {
                if (await Task.WhenAny(task, source.Task) == source.Task)
                {
                    throw new OperationCanceledException(cancellationToken);
                }

                await task;
            }
        }
#endif
    }

    extension<TResult>(Task<TResult> task)
    {
#if !SUPPORTS_TASK_WAIT_ASYNC
        /// <summary>
        /// Waits until the specified task returns a result or the cancellation token is signaled.
        /// </summary>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        /// <exception cref="OperationCanceledException">The specified <paramref name="cancellationToken"/> is signaled.</exception>
        public async Task<TResult> WaitAsync(CancellationToken cancellationToken)
        {
            var source = new TaskCompletionSource<bool>(TaskCreationOptions.None);

            using (cancellationToken.Register(static state => ((TaskCompletionSource<bool>) state!).SetResult(true), source))
            {
                if (await Task.WhenAny(task, source.Task) == source.Task)
                {
                    throw new OperationCanceledException(cancellationToken);
                }

                return await task;
            }
        }
#endif
    }

    extension(ValueTask)
    {
#if !SUPPORTS_VALUETASK_COMPLETED_TASK
        /// <summary>
        /// Gets a task that has already completed successfully.
        /// </summary>
        public static ValueTask CompletedTask => default;
#endif
    }

    extension<TResult>(ValueTask<TResult>)
    {
#if !SUPPORTS_VALUETASK_COMPLETED_TASK
        /// <summary>
        /// Gets a task that has already completed successfully.
        /// </summary>
        public static ValueTask<TResult> CompletedTask => default;
#endif
    }
}
