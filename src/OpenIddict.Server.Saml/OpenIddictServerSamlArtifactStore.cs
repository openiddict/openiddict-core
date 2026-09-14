/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Security.Cryptography;
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
/// <para>
/// <see cref="IDistributedCache"/> doesn't offer an atomic "get and remove" operation: concurrent resolutions are
/// serialized in the current process but not across instances. Load-balanced deployments requiring strict
/// single use should register an <see cref="IOpenIddictServerSamlArtifactStore"/> backed by an atomic store.
/// </para>
/// <para>
/// Stored messages are encrypted (AES-256-GCM) using a key derived from the artifact handle, that is never stored:
/// the cache only contains ciphertexts indexed by a hash of the handle. The private in-memory cache used when no
/// distributed cache is registered is size-limited to prevent resource exhaustion: when the limit is reached,
/// artifacts can be evicted before they are resolved (which makes the corresponding logins fail).
/// </para>
/// </remarks>
public sealed class OpenIddictServerSamlArtifactStore : IOpenIddictServerSamlArtifactStore
{
    private const byte Version = 2;
    private const int NonceSize = 12, TagSize = 16;

    /// <summary>
    /// The maximum size, in bytes, of the messages stored in the private in-memory cache (64 MiB).
    /// </summary>
    private const long MemoryCacheSizeLimit = 64 * 1024 * 1024;

    private static readonly byte[] KeyDerivationLabel = Encoding.ASCII.GetBytes("OpenIddict.Server.Saml.ArtifactStore.v2");

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

        // Note: MemoryDistributedCache uses the length of the stored values as the size of the cache entries.
        _cache = provider.GetService<IDistributedCache>() ??
            new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions { SizeLimit = MemoryCacheSizeLimit }));
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <inheritdoc/>
    public async ValueTask AddAsync(string handle, ArtifactMessage message, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(handle);
        ArgumentNullException.ThrowIfNull(message);

        byte[] plaintext;

        using (var stream = new MemoryStream())
        using (var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true))
        {
            writer.Write(message.ServiceProvider);
            writer.Write(message.ExpirationDate.UtcTicks);
            writer.Write(message.Message);
            writer.Flush();

            plaintext = stream.ToArray();
        }

        var key = GetKey(handle);

        await _cache.SetAsync(key, Protect(handle, key, plaintext), new DistributedCacheEntryOptions
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

        if (Unprotect(handle, key, data) is not byte[] plaintext)
        {
            return null;
        }

        try
        {
            using var stream = new MemoryStream(plaintext, writable: false);
            using var reader = new BinaryReader(stream, Encoding.UTF8);

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

    // Layout: version (1 byte) | nonce (12 bytes) | ciphertext | tag (16 bytes). The cache key is used as associated data.
    private static byte[] Protect(string handle, string cacheKey, byte[] plaintext)
    {
        var key = DeriveKey(handle);

        try
        {
            var nonce = RandomNumberGenerator.GetBytes(NonceSize);
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[TagSize];

            using (var aes = new AesGcm(key, TagSize))
            {
                aes.Encrypt(nonce, plaintext, ciphertext, tag, Encoding.UTF8.GetBytes(cacheKey));
            }

            var result = new byte[1 + NonceSize + ciphertext.Length + TagSize];
            result[0] = Version;
            Buffer.BlockCopy(nonce, 0, result, 1, NonceSize);
            Buffer.BlockCopy(ciphertext, 0, result, 1 + NonceSize, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, result, 1 + NonceSize + ciphertext.Length, TagSize);

            return result;
        }

        finally
        {
            Array.Clear(key, 0, key.Length);
        }
    }

    private static byte[]? Unprotect(string handle, string cacheKey, byte[] data)
    {
        if (data.Length < 1 + NonceSize + TagSize || data[0] is not Version)
        {
            return null;
        }

        var key = DeriveKey(handle);

        try
        {
            var nonce = new byte[NonceSize];
            var ciphertext = new byte[data.Length - 1 - NonceSize - TagSize];
            var tag = new byte[TagSize];

            Buffer.BlockCopy(data, 1, nonce, 0, NonceSize);
            Buffer.BlockCopy(data, 1 + NonceSize, ciphertext, 0, ciphertext.Length);
            Buffer.BlockCopy(data, 1 + NonceSize + ciphertext.Length, tag, 0, TagSize);

            var plaintext = new byte[ciphertext.Length];

            using (var aes = new AesGcm(key, TagSize))
            {
                aes.Decrypt(nonce, ciphertext, tag, plaintext, Encoding.UTF8.GetBytes(cacheKey));
            }

            return plaintext;
        }

        catch (CryptographicException)
        {
            return null;
        }

        finally
        {
            Array.Clear(key, 0, key.Length);
        }
    }

    // Note: the encryption key is derived from the unguessable artifact handle (HMAC-SHA256), that is only
    // known by the service provider the artifact was returned to and is never stored (only its SHA-256 hash is).
    private static byte[] DeriveKey(string handle)
    {
        using var algorithm = new HMACSHA256(Encoding.UTF8.GetBytes(handle));

        return algorithm.ComputeHash(KeyDerivationLabel);
    }

    private static string GetKey(string handle)
        => "openiddict-saml-artifact:" + OpenIddictServerSamlHelpers.HashIdentifier(handle);
}
