/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;

namespace OpenIddict.Client.Windows;

/// <summary>
/// Contains the APIs needed to coordinate authentication operations that happen in a different context.
/// </summary>
public sealed class OpenIddictClientWindowsMarshaller
{
    private readonly ConcurrentDictionary<string, Lazy<(
        string RequestForgeryProtection,
        SemaphoreSlim Semaphore,
        TaskCompletionSource<ProcessAuthenticationContext> TaskCompletionSource)>> _operations = new();

    /// <summary>
    /// Determines whether the authentication demand corresponding to the specified nonce is tracked.
    /// </summary>
    /// <param name="nonce">The nonce, used as a unique identifier.</param>
    /// <returns><see langword="true"/> if the operation is tracked, <see langword="false"/> otherwise.</returns>
    internal bool IsTracked(string nonce) => _operations.ContainsKey(nonce);

    /// <summary>
    /// Tries to add the specified authentication demand to the list of tracked operations.
    /// </summary>
    /// <param name="nonce">The nonce, used as a unique identifier.</param>
    /// <param name="protection">The request forgery protection associated with the specified authentication demand.</param>
    /// <returns><see langword="true"/> if the operation could be added, <see langword="false"/> otherwise.</returns>
    internal bool TryAdd(string nonce, string protection)
        => _operations.TryAdd(nonce, new(() => (protection, new SemaphoreSlim(initialCount: 1, maxCount: 1), new())));

    /// <summary>
    /// Tries to acquire a lock on the authentication demand corresponding to the specified nonce.
    /// </summary>
    /// <param name="nonce">The nonce, used as a unique identifier.</param>
    /// <returns><see langword="true"/> if the lock could be taken, <see langword="false"/> otherwise.</returns>
    internal bool TryAcquireLock(string nonce)
        => _operations.TryGetValue(nonce, out var operation) && operation.Value.Semaphore.Wait(TimeSpan.Zero);

    /// <summary>
    /// Tries to resolve the authentication context associated with the specified nonce.
    /// </summary>
    /// <param name="nonce">The nonce, used as a unique identifier.</param>
    /// <param name="context">The authentication context associated with the tracked operation.</param>
    /// <returns><see langword="true"/> if the context could be resolved, <see langword="false"/> otherwise.</returns>
    internal bool TryGetResult(string nonce, [NotNullWhen(true)] out ProcessAuthenticationContext? context)
    {
        if (!_operations.TryGetValue(nonce, out var operation))
        {
            context = null;
            return false;
        }

        if (!operation.IsValueCreated || !operation.Value.TaskCompletionSource.Task.IsCompleted)
        {
            context = null;
            return false;
        }

        context = operation.Value.TaskCompletionSource.Task.Result;
        return true;
    }

    /// <summary>
    /// Tries to wait for the authentication demand associated with the specified nonce to complete.
    /// </summary>
    /// <param name="nonce">The nonce, used as a unique identifier.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns><see langword="true"/> if the authentication demand is tracked, <see langword="false"/> otherwise.</returns>
    /// <exception cref="OperationCanceledException">The operation was canceled by the user.</exception>
    internal async Task<bool> TryWaitForCompletionAsync(string nonce, CancellationToken cancellationToken)
    {
        if (!_operations.TryGetValue(nonce, out var operation))
        {
            return false;
        }

        var source = new TaskCompletionSource<bool>(TaskCreationOptions.None);
        using (cancellationToken.Register(static state => ((TaskCompletionSource<bool>) state!).SetResult(true), source))
        {
            if (await Task.WhenAny(operation.Value.TaskCompletionSource.Task, source.Task) == source.Task)
            {
                throw new OperationCanceledException(cancellationToken);
            }

            await operation.Value.TaskCompletionSource.Task;
            return true;
        }
    }

    /// <summary>
    /// Tries to resolve the request forgery protection associated with the specified authentication demand.
    /// </summary>
    /// <param name="nonce">The nonce, used as a unique identifier.</param>
    /// <param name="protection">The request forgery protection associated with the specified authentication demand.</param>
    /// <returns><see langword="true"/> if the operation could be validated, <see langword="false"/> otherwise.</returns>
    internal bool TryGetRequestForgeryProtection(string nonce, [NotNullWhen(true)] out string? protection)
    {
        if (_operations.TryGetValue(nonce, out var operation))
        {
            protection = operation.Value.RequestForgeryProtection;
            return true;
        }

        protection = null;
        return false;
    }

    /// <summary>
    /// Tries to complete the specified authentication demand.
    /// </summary>
    /// <param name="nonce">The nonce, used as a unique identifier.</param>
    /// <param name="context">The authentication context that will be returned to the caller.</param>
    /// <returns><see langword="true"/> if the operation could be completed, <see langword="false"/> otherwise.</returns>
    internal bool TryComplete(string nonce, ProcessAuthenticationContext context)
        => _operations.TryGetValue(nonce, out var operation) && operation.Value.TaskCompletionSource.TrySetResult(context);

    /// <summary>
    /// Tries to remove the specified authentication operation from the list of tracked operations.
    /// </summary>
    /// <param name="nonce">The nonce, used as a unique identifier.</param>
    /// <returns><see langword="true"/> if the operation could be removed, <see langword="false"/> otherwise.</returns>
    internal bool TryRemove(string nonce) => _operations.TryRemove(nonce, out _);
}
