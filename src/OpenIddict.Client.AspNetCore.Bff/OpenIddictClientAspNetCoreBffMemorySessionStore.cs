/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Concurrent;
using System.Security.Claims;
using Microsoft.Extensions.Options;

namespace OpenIddict.Client.AspNetCore.Bff;

/// <summary>
/// Provides an in-memory server-side session store supporting back-channel logout.
/// </summary>
/// <remarks>
/// Sessions are lost when the application restarts and are not shared between instances:
/// multi-instance deployments must use a custom <see cref="IOpenIddictClientAspNetCoreBffSessionStore"/>.
/// </remarks>
public sealed class OpenIddictClientAspNetCoreBffMemorySessionStore : IOpenIddictClientAspNetCoreBffSessionStore
{
    private readonly ConcurrentDictionary<string, AuthenticationTicket> _tickets = new(StringComparer.Ordinal);
    private readonly IOptionsMonitor<OpenIddictClientOptions> _options;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientAspNetCoreBffMemorySessionStore"/> class.
    /// </summary>
    /// <param name="options">The OpenIddict client options.</param>
    public OpenIddictClientAspNetCoreBffMemorySessionStore(IOptionsMonitor<OpenIddictClientOptions> options)
        => _options = options ?? throw new ArgumentNullException(nameof(options));

    /// <summary>
    /// Gets the number of sessions currently stored.
    /// </summary>
    public int Count => _tickets.Count;

    /// <inheritdoc/>
    public Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        ArgumentNullException.ThrowIfNull(ticket);

        var key = Guid.NewGuid().ToString("N");
        _tickets[key] = ticket;

        Purge();

        return Task.FromResult(key);
    }

    /// <inheritdoc/>
    public Task RenewAsync(string key, AuthenticationTicket ticket)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);
        ArgumentNullException.ThrowIfNull(ticket);

        // Note: sessions removed after a back-channel logout notification must not be resurrected.
        if (_tickets.TryGetValue(key, out var existing))
        {
            _tickets.TryUpdate(key, ticket, existing);
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task<AuthenticationTicket?> RetrieveAsync(string key)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);

        if (!_tickets.TryGetValue(key, out var ticket))
        {
            return Task.FromResult<AuthenticationTicket?>(null);
        }

        if (IsExpired(ticket))
        {
            _tickets.TryRemove(new KeyValuePair<string, AuthenticationTicket>(key, ticket));

            return Task.FromResult<AuthenticationTicket?>(null);
        }

        return Task.FromResult<AuthenticationTicket?>(ticket);
    }

    /// <inheritdoc/>
    public Task RemoveAsync(string key)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);

        _tickets.TryRemove(key, out _);

        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public ValueTask<int> RemoveSessionsAsync(string registrationId, string? subject,
        string? sessionId, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(registrationId);

        if (string.IsNullOrEmpty(subject) && string.IsNullOrEmpty(sessionId))
        {
            return new(0);
        }

        var count = 0;

        foreach (var entry in _tickets)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (Matches(entry.Value.Principal, registrationId, subject, sessionId) && _tickets.TryRemove(entry))
            {
                count++;
            }
        }

        return new(count);
    }

    internal static bool Matches(ClaimsPrincipal principal, string registrationId, string? subject, string? sessionId)
    {
        if (!string.Equals(principal.FindFirst(Claims.Private.RegistrationId)?.Value, registrationId, StringComparison.Ordinal))
        {
            return false;
        }

        if (!string.IsNullOrEmpty(subject) && !string.Equals(subject, (principal.FindFirst(Claims.Subject) ??
            principal.FindFirst(ClaimTypes.NameIdentifier))?.Value, StringComparison.Ordinal))
        {
            return false;
        }

        if (!string.IsNullOrEmpty(sessionId) && !string.Equals(sessionId,
            principal.FindFirst(Claims.SessionId)?.Value, StringComparison.Ordinal))
        {
            return false;
        }

        return true;
    }

    private bool IsExpired(AuthenticationTicket ticket) => ticket.Properties.ExpiresUtc is DateTimeOffset date &&
        date <= _options.CurrentValue.TimeProvider.GetUtcNow();

    private void Purge()
    {
        foreach (var entry in _tickets)
        {
            if (IsExpired(entry.Value))
            {
                _tickets.TryRemove(entry);
            }
        }
    }
}
