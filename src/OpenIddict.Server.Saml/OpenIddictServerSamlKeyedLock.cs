/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Server.Saml;

/// <summary>
/// Provides striped locks used to serialize operations targeting the same cache key without
/// serializing unrelated operations (e.g. while waiting for a remote distributed cache).
/// </summary>
internal sealed class OpenIddictServerSamlKeyedLock
{
    private const int StripeCount = 64;

    private readonly SemaphoreSlim[] _semaphores = new SemaphoreSlim[StripeCount];
    private readonly object[] _objects = new object[StripeCount];

    public OpenIddictServerSamlKeyedLock()
    {
        for (var index = 0; index < StripeCount; index++)
        {
            _semaphores[index] = new SemaphoreSlim(initialCount: 1, maxCount: 1);
            _objects[index] = new object();
        }
    }

    /// <summary>
    /// Gets the asynchronous lock associated with the specified key.
    /// </summary>
    public SemaphoreSlim GetSemaphore(string key) => _semaphores[GetStripe(key)];

    /// <summary>
    /// Gets the synchronous lock associated with the specified key.
    /// </summary>
    public object GetSynchronizationObject(string key) => _objects[GetStripe(key)];

    private static int GetStripe(string key) => (int) ((uint) StringComparer.Ordinal.GetHashCode(key) % StripeCount);
}
