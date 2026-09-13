/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Concurrent;

namespace OpenIddict.Client.AspNetCore.Bff;

/// <summary>
/// Ensures a single asynchronous operation runs per key: concurrent callers using the same key share the same operation
/// and, if a retention period is specified, successful results are returned to subsequent callers until it elapses.
/// </summary>
/// <typeparam name="TResult">The type of the result.</typeparam>
internal sealed class OpenIddictClientAspNetCoreBffKeyedOperations<TResult>
{
    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets the number of tracked operations.
    /// </summary>
    public int Count => _entries.Count;

    /// <summary>
    /// Runs the operation associated with the specified key or joins the pending/retained operation, if applicable.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="factory">The operation factory.</param>
    /// <param name="retention">The period during which a successful result is retained.</param>
    /// <param name="provider">The time provider.</param>
    /// <returns>The result of the operation.</returns>
    public Task<TResult> RunAsync(string key, Func<Task<TResult>> factory, TimeSpan retention, TimeProvider provider)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);
        ArgumentNullException.ThrowIfNull(factory);
        ArgumentNullException.ThrowIfNull(provider);

        while (true)
        {
            var now = provider.GetUtcNow();

            if (_entries.TryGetValue(key, out var entry))
            {
                if (entry.ExpirationDate is not DateTimeOffset date || date > now)
                {
                    return entry.Operation.Value;
                }

                // Remove the expired entry (unless it was already replaced by another caller) and try again.
                _entries.TryRemove(new KeyValuePair<string, Entry>(key, entry));
                continue;
            }

            entry = new Entry();
            entry.Operation = new Lazy<Task<TResult>>(() => ExecuteAsync(key, entry, factory, retention, provider));

            if (_entries.TryAdd(key, entry))
            {
                Purge(now);

                return entry.Operation.Value;
            }
        }
    }

    private async Task<TResult> ExecuteAsync(string key, Entry entry,
        Func<Task<TResult>> factory, TimeSpan retention, TimeProvider provider)
    {
        try
        {
            var result = await factory().ConfigureAwait(false);

            if (retention > TimeSpan.Zero)
            {
                entry.ExpirationDate = provider.GetUtcNow() + retention;
            }

            else
            {
                _entries.TryRemove(new KeyValuePair<string, Entry>(key, entry));
            }

            return result;
        }

        catch
        {
            // Never retain failed operations so that subsequent callers can try again.
            _entries.TryRemove(new KeyValuePair<string, Entry>(key, entry));

            throw;
        }
    }

    private void Purge(DateTimeOffset now)
    {
        foreach (var entry in _entries)
        {
            if (entry.Value.ExpirationDate is DateTimeOffset date && date <= now)
            {
                _entries.TryRemove(entry);
            }
        }
    }

    private sealed class Entry
    {
        public Lazy<Task<TResult>> Operation { get; set; } = default!;

        private long _expiration;

        // Note: the expiration date is stored as UTC ticks (0 meaning "not completed or not retained")
        // to ensure it can be atomically read and written by concurrent threads.
        public DateTimeOffset? ExpirationDate
        {
            get => Volatile.Read(ref _expiration) is long ticks and not 0 ? new DateTimeOffset(ticks, TimeSpan.Zero) : null;
            set => Volatile.Write(ref _expiration, value?.UtcTicks ?? 0);
        }
    }
}
