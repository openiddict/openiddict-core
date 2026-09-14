/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Buffers.Text;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Server;

/// <summary>
/// Manages the keys automatically created, rotated and retired by the OpenIddict server.
/// </summary>
/// <remarks>
/// Key lifecycle: a key is published as soon as it is created, used to protect tokens from its activation
/// date to its expiration date and still published/used to unprotect tokens until its retirement date.
/// A successor is created <see cref="OpenIddictServerOptions.KeyPropagationTime"/> before the current key expires.
/// </remarks>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictServerKeyRing
{
    private readonly SemaphoreSlim _lock = new(initialCount: 1, maxCount: 1);
    private readonly ILogger<OpenIddictServerKeyRing> _logger;
    private readonly ConcurrentDictionary<string, RsaSecurityKey> _keys = new(StringComparer.Ordinal);
    private readonly IOptionsMonitor<OpenIddictServerOptions> _options;
    private Snapshot? _snapshot;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictServerKeyRing"/> class.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="options">The server options.</param>
    public OpenIddictServerKeyRing(ILogger<OpenIddictServerKeyRing> logger, IOptionsMonitor<OpenIddictServerOptions> options)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <summary>
    /// Resolves the credentials that must be used by the specified transaction.
    /// </summary>
    /// <param name="transaction">The transaction.</param>
    /// <returns>The credentials.</returns>
    public static async ValueTask<OpenIddictServerCredentials> ResolveCredentialsAsync(OpenIddictServerTransaction transaction)
    {
        ArgumentNullException.ThrowIfNull(transaction);

        if (transaction.Credentials is not null)
        {
            return transaction.Credentials;
        }

        // Note: when issuer resolution is enabled, the base URI of the transaction is the resolved issuer.
        return transaction.Credentials = await ResolveCredentialsAsync(transaction.ServiceProvider, transaction.Options,
            transaction.Options.EnableIssuerResolution ? transaction.BaseUri : null, transaction.CancellationToken);
    }

    /// <summary>
    /// Resolves the credentials that must be used for the specified issuer.
    /// </summary>
    /// <param name="provider">The service provider.</param>
    /// <param name="options">The server options.</param>
    /// <param name="issuer">
    /// The issuer resolved for the current request when issuer resolution is enabled, <see langword="null"/> otherwise.
    /// </param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The credentials.</returns>
    public static async ValueTask<OpenIddictServerCredentials> ResolveCredentialsAsync(IServiceProvider provider,
        OpenIddictServerOptions options, Uri? issuer, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(options);

        // If issuer-specific credentials are available, use them instead of the default credentials.
        if (issuer is { IsAbsoluteUri: true } &&
            provider.GetService<IOpenIddictServerIssuerCredentialsProvider>() is IOpenIddictServerIssuerCredentialsProvider source &&
            await source.GetCredentialsAsync(issuer, provider, cancellationToken) is OpenIddictServerCredentials credentials)
        {
            return credentials;
        }

        if (!options.EnableAutomaticKeyManagement)
        {
            return new(options.SigningCredentials, options.EncryptionCredentials);
        }

        return await provider.GetRequiredService<OpenIddictServerKeyRing>().GetCredentialsAsync(provider, cancellationToken);
    }

    /// <summary>
    /// Returns the current credentials, creating new keys in the database if necessary.
    /// </summary>
    /// <param name="provider">The service provider used to resolve the key manager and the key protector.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The credentials, the active keys first.</returns>
    public async ValueTask<OpenIddictServerCredentials> GetCredentialsAsync(
        IServiceProvider provider, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(provider);

        var options = _options.CurrentValue;

        if (_snapshot is Snapshot snapshot && snapshot.ExpirationDate > options.TimeProvider.GetUtcNow())
        {
            return snapshot.Credentials;
        }

        await _lock.WaitAsync(cancellationToken);

        try
        {
            var now = options.TimeProvider.GetUtcNow();

            if (_snapshot is Snapshot current && current.ExpirationDate > now)
            {
                return current.Credentials;
            }

            _snapshot = await CreateSnapshotAsync(provider, options, now, cancellationToken);

            return _snapshot.Credentials;
        }

        finally
        {
            _lock.Release();
        }
    }

    /// <summary>
    /// Discards the cached credentials, forcing the keys to be reloaded from the database.
    /// </summary>
    public void Invalidate() => _snapshot = null;

    private async ValueTask<Snapshot> CreateSnapshotAsync(IServiceProvider provider,
        OpenIddictServerOptions options, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var manager = provider.GetService<IOpenIddictKeyManager>()
            ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

        var protector = provider.GetService<IOpenIddictServerKeyProtector>()
            ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0542));

        var entries = await ListEntriesAsync(manager, now, cancellationToken);

        var created = false;

        foreach (var usage in (string[]) [JsonWebKeyUseNames.Sig, JsonWebKeyUseNames.Enc])
        {
            // If no key of this type remains valid beyond the propagation window, create a successor
            // that is activated when the last key expires (or immediately if all the keys expired).
            if (entries.Exists(entry => string.Equals(entry.Usage, usage, StringComparison.Ordinal) && entry.ExpirationDate > now + options.KeyPropagationTime))
            {
                continue;
            }

            var activation = entries
                .Where(entry => string.Equals(entry.Usage, usage, StringComparison.Ordinal) && entry.ExpirationDate > now)
                .Select(static entry => entry.ExpirationDate)
                .DefaultIfEmpty(now)
                .Max();

            await CreateKeyAsync(manager, protector, options, usage, now, activation, cancellationToken);

            created = true;
        }

        // Reload the keys to also take into account the keys concurrently created by other instances.
        if (created)
        {
            entries = await ListEntriesAsync(manager, now, cancellationToken);
        }

        var signing = new List<SigningCredentials>();
        var encryption = new List<EncryptingCredentials>();

        var ordered = entries
            .OrderByDescending(static entry => entry.ActivationDate)
            .ThenByDescending(static entry => entry.CreationDate)
            .ThenByDescending(static entry => entry.KeyId, StringComparer.Ordinal)
            .ToList();

        foreach (var usage in (string[]) [JsonWebKeyUseNames.Sig, JsonWebKeyUseNames.Enc])
        {
            var candidates = ordered.FindAll(entry => string.Equals(entry.Usage, usage, StringComparison.Ordinal));

            // Note: the sort order is deterministic so that all the instances select the same active key.
            var active = candidates.Find(entry => entry.ActivationDate <= now) ?? candidates.LastOrDefault();

            foreach (var entry in active is null ? candidates : [active, .. candidates.Where(entry => entry != active)])
            {
                var key = Unprotect(protector, entry);
                if (key is null)
                {
                    continue;
                }

                if (usage is JsonWebKeyUseNames.Sig)
                {
                    signing.Add(new SigningCredentials(key, entry.Algorithm));
                }

                else
                {
                    encryption.Add(new EncryptingCredentials(key, entry.Algorithm, SecurityAlgorithms.Aes256CbcHmacSha512));
                }
            }

            // Statically registered credentials are used after the active key.
            if (usage is JsonWebKeyUseNames.Sig)
            {
                signing.InsertRange(Math.Min(1, signing.Count), options.SigningCredentials);
            }

            else
            {
                encryption.InsertRange(Math.Min(1, encryption.Count), options.EncryptionCredentials);
            }
        }

        // Refresh the snapshot at the next lifecycle transition, and at least once per cache lifetime.
        var expiration = entries
            .SelectMany(entry => (DateTimeOffset[]) [
                entry.ActivationDate,
                entry.ExpirationDate - options.KeyPropagationTime,
                entry.RetirementDate])
            .Where(date => date > now)
            .DefaultIfEmpty(DateTimeOffset.MaxValue)
            .Min();

        if (expiration > now + options.KeyRingCacheLifetime)
        {
            expiration = now + options.KeyRingCacheLifetime;
        }

        return new Snapshot(new OpenIddictServerCredentials(signing, encryption), expiration);
    }

    private async ValueTask CreateKeyAsync(IOpenIddictKeyManager manager, IOpenIddictServerKeyProtector protector,
        OpenIddictServerOptions options, string usage, DateTimeOffset now, DateTimeOffset activation, CancellationToken cancellationToken)
    {
        using var algorithm = RSA.Create(keySizeInBits: 2048);

        var parameters = algorithm.ExportParameters(includePrivateParameters: true);

        var descriptor = new OpenIddictKeyDescriptor
        {
            ActivationDate = activation,
            Algorithm = usage is JsonWebKeyUseNames.Sig ? SecurityAlgorithms.RsaSha256 : SecurityAlgorithms.RsaOAEP,
            CreationDate = now,
            ExpirationDate = activation + options.KeyRotationInterval,
            KeyId = Base64Url.EncodeToString(SHA256.HashData(parameters.Modulus!))[..40],
            Payload = protector.Protect(Serialize(parameters)),
            RetirementDate = activation + options.KeyRotationInterval + options.KeyRetentionTime,
            Status = Statuses.Valid,
            Usage = usage
        };

        await manager.CreateAsync(descriptor, cancellationToken);

        _logger.LogInformation(6309, SR.GetResourceString(SR.ID6309), descriptor.KeyId, usage, activation);
    }

    private RsaSecurityKey? Unprotect(IOpenIddictServerKeyProtector protector, Entry entry)
    {
        if (_keys.TryGetValue(entry.Payload, out var key))
        {
            return key;
        }

        try
        {
            using var document = JsonDocument.Parse(protector.Unprotect(entry.Payload));

            key = new RsaSecurityKey(Deserialize(document.RootElement)) { KeyId = entry.KeyId };
        }

        catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
        {
            _logger.LogWarning(6310, exception, SR.GetResourceString(SR.ID6310), entry.KeyId);

            return null;
        }

        return _keys.GetOrAdd(entry.Payload, key);
    }

    private static async ValueTask<List<Entry>> ListEntriesAsync(
        IOpenIddictKeyManager manager, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var entries = new List<Entry>();

        await foreach (var key in manager.ListAsync(count: null, offset: null, cancellationToken))
        {
            if (!await manager.HasStatusAsync(key, Statuses.Valid, cancellationToken) ||
                await manager.GetActivationDateAsync(key, cancellationToken) is not DateTimeOffset activation ||
                await manager.GetExpirationDateAsync(key, cancellationToken) is not DateTimeOffset expiration ||
                await manager.GetRetirementDateAsync(key, cancellationToken) is not DateTimeOffset retirement ||
                retirement <= now ||
                await manager.GetUsageAsync(key, cancellationToken) is not string usage ||
                usage is not (JsonWebKeyUseNames.Sig or JsonWebKeyUseNames.Enc) ||
                await manager.GetAlgorithmAsync(key, cancellationToken) is not { Length: > 0 } algorithm ||
                await manager.GetKeyIdAsync(key, cancellationToken) is not { Length: > 0 } identifier ||
                await manager.GetPayloadAsync(key, cancellationToken) is not { Length: > 0 } payload)
            {
                continue;
            }

            entries.Add(new Entry(identifier, usage, algorithm, payload,
                await manager.GetCreationDateAsync(key, cancellationToken) ?? activation,
                activation, expiration, retirement));
        }

        return entries;
    }

    private static string Serialize(RSAParameters parameters)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString(JsonWebKeyParameterNames.Kty, JsonWebAlgorithmsKeyTypes.RSA);
            writer.WriteString(JsonWebKeyParameterNames.N, Base64Url.EncodeToString(parameters.Modulus!));
            writer.WriteString(JsonWebKeyParameterNames.E, Base64Url.EncodeToString(parameters.Exponent!));
            writer.WriteString(JsonWebKeyParameterNames.D, Base64Url.EncodeToString(parameters.D!));
            writer.WriteString(JsonWebKeyParameterNames.P, Base64Url.EncodeToString(parameters.P!));
            writer.WriteString(JsonWebKeyParameterNames.Q, Base64Url.EncodeToString(parameters.Q!));
            writer.WriteString(JsonWebKeyParameterNames.DP, Base64Url.EncodeToString(parameters.DP!));
            writer.WriteString(JsonWebKeyParameterNames.DQ, Base64Url.EncodeToString(parameters.DQ!));
            writer.WriteString(JsonWebKeyParameterNames.QI, Base64Url.EncodeToString(parameters.InverseQ!));
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static RSAParameters Deserialize(JsonElement element)
    {
        return new()
        {
            Modulus = Decode(JsonWebKeyParameterNames.N),
            Exponent = Decode(JsonWebKeyParameterNames.E),
            D = Decode(JsonWebKeyParameterNames.D),
            P = Decode(JsonWebKeyParameterNames.P),
            Q = Decode(JsonWebKeyParameterNames.Q),
            DP = Decode(JsonWebKeyParameterNames.DP),
            DQ = Decode(JsonWebKeyParameterNames.DQ),
            InverseQ = Decode(JsonWebKeyParameterNames.QI)
        };

        byte[] Decode(string name) => Base64Url.DecodeFromChars(element.GetProperty(name).GetString());
    }

    private sealed record class Entry(string KeyId, string Usage, string Algorithm, string Payload,
        DateTimeOffset CreationDate, DateTimeOffset ActivationDate, DateTimeOffset ExpirationDate, DateTimeOffset RetirementDate);

    private sealed record class Snapshot(OpenIddictServerCredentials Credentials, DateTimeOffset ExpirationDate);
}
