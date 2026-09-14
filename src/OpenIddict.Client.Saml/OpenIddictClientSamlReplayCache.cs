/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Concurrent;
using System.ComponentModel;
using Microsoft.Extensions.Options;

namespace OpenIddict.Client.Saml;

/// <summary>
/// Provides an in-memory <see cref="IOpenIddictClientSamlReplayCache"/> implementation.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictClientSamlReplayCache : IOpenIddictClientSamlReplayCache
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _entries = new(StringComparer.Ordinal);
    private readonly IOptionsMonitor<OpenIddictClientSamlOptions> _options;
    private DateTimeOffset _nextPurge;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientSamlReplayCache"/> class.
    /// </summary>
    /// <param name="options">The SAML options.</param>
    public OpenIddictClientSamlReplayCache(IOptionsMonitor<OpenIddictClientSamlOptions> options)
        => _options = options ?? throw new ArgumentNullException(nameof(options));

    /// <inheritdoc/>
    public ValueTask<bool> TryAddAsync(string key, DateTimeOffset expirationDate, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);

        var now = _options.CurrentValue.TimeProvider.GetUtcNow();

        // Remove the expired entries at most once per minute to prevent the cache from growing indefinitely.
        if (now >= _nextPurge)
        {
            _nextPurge = now.AddMinutes(1);

            foreach (var entry in _entries)
            {
                if (entry.Value <= now)
                {
                    ((ICollection<KeyValuePair<string, DateTimeOffset>>) _entries).Remove(entry);
                }
            }
        }

        while (true)
        {
            if (_entries.TryAdd(key, expirationDate))
            {
                return new(true);
            }

            // If the existing entry is expired, try to replace it atomically.
            if (_entries.TryGetValue(key, out var existing) && existing <= now)
            {
                if (_entries.TryUpdate(key, expirationDate, existing))
                {
                    return new(true);
                }

                continue;
            }

            return new(false);
        }
    }
}
