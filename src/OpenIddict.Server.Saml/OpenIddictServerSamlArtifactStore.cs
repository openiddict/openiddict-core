/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Text;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using static OpenIddict.Server.Saml.OpenIddictServerSamlModels;

namespace OpenIddict.Server.Saml;

/// <summary>
/// Stores the SAML messages represented by artifacts using the <see cref="IDistributedCache"/> registered
/// in the DI container or, if no distributed cache was registered, a private in-memory cache.
/// </summary>
/// <remarks>
/// <see cref="IDistributedCache"/> doesn't offer an atomic "get and remove" operation: concurrent resolutions are
/// serialized in the current process but not across instances. Load-balanced deployments requiring strict
/// single use should register an <see cref="IOpenIddictServerSamlArtifactStore"/> backed by an atomic store.
/// </remarks>
public sealed class OpenIddictServerSamlArtifactStore : IOpenIddictServerSamlArtifactStore
{
    private const byte Version = 1;

    private readonly IDistributedCache _cache;
    private readonly SemaphoreSlim _lock = new(initialCount: 1, maxCount: 1);
    private readonly IOptionsMonitor<OpenIddictServerSamlOptions> _options;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictServerSamlArtifactStore"/> class.
    /// </summary>
    /// <param name="provider">The service provider, used to resolve the optional distributed cache.</param>
    /// <param name="options">The SAML options.</param>
    public OpenIddictServerSamlArtifactStore(IServiceProvider provider, IOptionsMonitor<OpenIddictServerSamlOptions> options)
    {
        ArgumentNullException.ThrowIfNull(provider);

        _cache = provider.GetService<IDistributedCache>() ??
            new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <inheritdoc/>
    public async ValueTask AddAsync(string handle, ArtifactMessage message, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(handle);
        ArgumentNullException.ThrowIfNull(message);

        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true))
        {
            writer.Write(Version);
            writer.Write(message.ServiceProvider);
            writer.Write(message.ExpirationDate.UtcTicks);
            writer.Write(message.Message);
        }

        await _cache.SetAsync(GetKey(handle), stream.ToArray(), new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = OpenIddictServerSamlHelpers.GetCacheLifetime(
                message.ExpirationDate, _options.CurrentValue.TimeProvider.GetUtcNow())
        }, cancellationToken);
    }

    /// <inheritdoc/>
    public async ValueTask<ArtifactMessage?> RemoveAsync(string handle, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(handle);

        var key = GetKey(handle);

        byte[]? data;

        await _lock.WaitAsync(cancellationToken);

        try
        {
            data = await _cache.GetAsync(key, cancellationToken);
            if (data is null)
            {
                return null;
            }

            await _cache.RemoveAsync(key, cancellationToken);
        }

        finally
        {
            _lock.Release();
        }

        try
        {
            using var stream = new MemoryStream(data, writable: false);
            using var reader = new BinaryReader(stream, Encoding.UTF8);

            if (reader.ReadByte() is not Version)
            {
                return null;
            }

            var message = new ArtifactMessage
            {
                ServiceProvider = reader.ReadString(),
                ExpirationDate = new DateTimeOffset(reader.ReadInt64(), TimeSpan.Zero),
                Message = reader.ReadString()
            };

            return stream.Position == stream.Length ? message : null;
        }

        catch (Exception exception) when (exception is ArgumentException or EndOfStreamException or FormatException or IOException)
        {
            return null;
        }
    }

    private static string GetKey(string handle)
        => "openiddict-saml-artifact:" + OpenIddictServerSamlHelpers.HashIdentifier(handle);
}
