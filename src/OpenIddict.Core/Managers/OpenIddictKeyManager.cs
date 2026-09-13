/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel.DataAnnotations;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using static OpenIddict.Abstractions.OpenIddictExceptions;
using ValidationException = OpenIddict.Abstractions.OpenIddictExceptions.ValidationException;

namespace OpenIddict.Core;

/// <summary>
/// Provides methods allowing to manage the cryptographic keys stored in the store.
/// </summary>
/// <remarks>
/// Applications that do not want to depend on a specific entity type can use the non-generic
/// <see cref="IOpenIddictKeyManager"/> instead, for which the actual entity type is resolved at runtime.
/// </remarks>
/// <typeparam name="TEntity">The type of the key entity.</typeparam>
public class OpenIddictKeyManager<TEntity> : IOpenIddictKeyManager where TEntity : class
{
    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictKeyManager{TEntity}"/> class.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="options">The options.</param>
    /// <param name="store">The store.</param>
    public OpenIddictKeyManager(
        ILogger<OpenIddictKeyManager<TEntity>> logger,
        IOptionsMonitor<OpenIddictCoreOptions> options,
        IOpenIddictKeyStore<TEntity> store)
    {
        Logger = logger ?? throw new ArgumentNullException(nameof(logger));
        Options = options ?? throw new ArgumentNullException(nameof(options));
        Store = store ?? throw new ArgumentNullException(nameof(store));
    }

    /// <summary>
    /// Gets the logger associated with the current manager.
    /// </summary>
    protected ILogger Logger { get; }

    /// <summary>
    /// Gets the options associated with the current manager.
    /// </summary>
    protected IOptionsMonitor<OpenIddictCoreOptions> Options { get; }

    /// <summary>
    /// Gets the store associated with the current manager.
    /// </summary>
    protected IOpenIddictKeyStore<TEntity> Store { get; }

    /// <inheritdoc cref="IOpenIddictKeyManager.CountAsync(CancellationToken)"/>
    public virtual ValueTask<long> CountAsync(CancellationToken cancellationToken = default)
        => Store.CountAsync(cancellationToken);

    /// <inheritdoc cref="IOpenIddictKeyManager.CreateAsync(object, CancellationToken)"/>
    public virtual async ValueTask CreateAsync(TEntity key, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);

        // If no status was explicitly specified, assume that the key is valid.
        if (string.IsNullOrEmpty(await Store.GetStatusAsync(key, cancellationToken)))
        {
            await Store.SetStatusAsync(key, Statuses.Valid, cancellationToken);
        }

        // If no creation date was explicitly specified, set it to the current time.
        if (await Store.GetCreationDateAsync(key, cancellationToken) is null)
        {
            await Store.SetCreationDateAsync(key, Options.CurrentValue.TimeProvider.GetUtcNow(), cancellationToken);
        }

        await EnsureValidAsync(key, SR.ID0207, cancellationToken);
        await Store.CreateAsync(key, cancellationToken);
    }

    /// <inheritdoc cref="IOpenIddictKeyManager.CreateAsync(OpenIddictKeyDescriptor, CancellationToken)"/>
    public virtual async ValueTask<TEntity> CreateAsync(
        OpenIddictKeyDescriptor descriptor, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(descriptor);

        var key = await Store.InstantiateAsync(cancellationToken)
            ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0208));

        await PopulateAsync(key, descriptor, cancellationToken);
        await CreateAsync(key, cancellationToken);

        return key;
    }

    /// <inheritdoc cref="IOpenIddictKeyManager.DeleteAsync(object, CancellationToken)"/>
    public virtual ValueTask DeleteAsync(TEntity key, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);

        return Store.DeleteAsync(key, cancellationToken);
    }

    /// <inheritdoc cref="IOpenIddictKeyManager.FindByIdAsync(string, CancellationToken)"/>
    public virtual async ValueTask<TEntity?> FindByIdAsync(string identifier, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var key = await Store.FindByIdAsync(identifier, cancellationToken);
        if (key is null)
        {
            return null;
        }

        // SQL engines like Microsoft SQL Server or MySQL are known to use case-insensitive lookups by default.
        // To ensure a case-sensitive comparison is enforced independently of the database/table/query collation
        // used by the store, a second pass using string.Equals(StringComparison.Ordinal) is manually made here.
        if (!Options.CurrentValue.DisableAdditionalFiltering &&
            !string.Equals(await Store.GetIdAsync(key, cancellationToken), identifier, StringComparison.Ordinal))
        {
            return null;
        }

        return key;
    }

    /// <inheritdoc cref="IOpenIddictKeyManager.GetActivationDateAsync(object, CancellationToken)"/>
    public virtual ValueTask<DateTimeOffset?> GetActivationDateAsync(TEntity key, CancellationToken cancellationToken = default)
        => Store.GetActivationDateAsync(key ?? throw new ArgumentNullException(nameof(key)), cancellationToken);

    /// <inheritdoc cref="IOpenIddictKeyManager.GetAlgorithmAsync(object, CancellationToken)"/>
    public virtual ValueTask<string?> GetAlgorithmAsync(TEntity key, CancellationToken cancellationToken = default)
        => Store.GetAlgorithmAsync(key ?? throw new ArgumentNullException(nameof(key)), cancellationToken);

    /// <inheritdoc cref="IOpenIddictKeyManager.GetCreationDateAsync(object, CancellationToken)"/>
    public virtual ValueTask<DateTimeOffset?> GetCreationDateAsync(TEntity key, CancellationToken cancellationToken = default)
        => Store.GetCreationDateAsync(key ?? throw new ArgumentNullException(nameof(key)), cancellationToken);

    /// <inheritdoc cref="IOpenIddictKeyManager.GetExpirationDateAsync(object, CancellationToken)"/>
    public virtual ValueTask<DateTimeOffset?> GetExpirationDateAsync(TEntity key, CancellationToken cancellationToken = default)
        => Store.GetExpirationDateAsync(key ?? throw new ArgumentNullException(nameof(key)), cancellationToken);

    /// <inheritdoc cref="IOpenIddictKeyManager.GetIdAsync(object, CancellationToken)"/>
    public virtual ValueTask<string?> GetIdAsync(TEntity key, CancellationToken cancellationToken = default)
        => Store.GetIdAsync(key ?? throw new ArgumentNullException(nameof(key)), cancellationToken);

    /// <inheritdoc cref="IOpenIddictKeyManager.GetKeyIdAsync(object, CancellationToken)"/>
    public virtual ValueTask<string?> GetKeyIdAsync(TEntity key, CancellationToken cancellationToken = default)
        => Store.GetKeyIdAsync(key ?? throw new ArgumentNullException(nameof(key)), cancellationToken);

    /// <inheritdoc cref="IOpenIddictKeyManager.GetPayloadAsync(object, CancellationToken)"/>
    public virtual ValueTask<string?> GetPayloadAsync(TEntity key, CancellationToken cancellationToken = default)
        => Store.GetPayloadAsync(key ?? throw new ArgumentNullException(nameof(key)), cancellationToken);

    /// <inheritdoc cref="IOpenIddictKeyManager.GetPropertiesAsync(object, CancellationToken)"/>
    public virtual ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(
        TEntity key, CancellationToken cancellationToken = default)
        => Store.GetPropertiesAsync(key ?? throw new ArgumentNullException(nameof(key)), cancellationToken);

    /// <inheritdoc cref="IOpenIddictKeyManager.GetRetirementDateAsync(object, CancellationToken)"/>
    public virtual ValueTask<DateTimeOffset?> GetRetirementDateAsync(TEntity key, CancellationToken cancellationToken = default)
        => Store.GetRetirementDateAsync(key ?? throw new ArgumentNullException(nameof(key)), cancellationToken);

    /// <inheritdoc cref="IOpenIddictKeyManager.GetStatusAsync(object, CancellationToken)"/>
    public virtual ValueTask<string?> GetStatusAsync(TEntity key, CancellationToken cancellationToken = default)
        => Store.GetStatusAsync(key ?? throw new ArgumentNullException(nameof(key)), cancellationToken);

    /// <inheritdoc cref="IOpenIddictKeyManager.GetUsageAsync(object, CancellationToken)"/>
    public virtual ValueTask<string?> GetUsageAsync(TEntity key, CancellationToken cancellationToken = default)
        => Store.GetUsageAsync(key ?? throw new ArgumentNullException(nameof(key)), cancellationToken);

    /// <inheritdoc cref="IOpenIddictKeyManager.HasStatusAsync(object, string, CancellationToken)"/>
    public virtual async ValueTask<bool> HasStatusAsync(TEntity key, string status, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentException.ThrowIfNullOrEmpty(status);

        return string.Equals(await Store.GetStatusAsync(key, cancellationToken), status, StringComparison.Ordinal);
    }

    /// <inheritdoc cref="IOpenIddictKeyManager.ListAsync(int?, int?, CancellationToken)"/>
    public virtual IAsyncEnumerable<TEntity> ListAsync(
        int? count = null, int? offset = null, CancellationToken cancellationToken = default)
        => Store.ListAsync(count, offset, cancellationToken);

    /// <inheritdoc cref="IOpenIddictKeyManager.PopulateAsync(object, OpenIddictKeyDescriptor, CancellationToken)"/>
    public virtual async ValueTask PopulateAsync(TEntity key,
        OpenIddictKeyDescriptor descriptor, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(descriptor);

        await Store.SetActivationDateAsync(key, descriptor.ActivationDate, cancellationToken);
        await Store.SetAlgorithmAsync(key, descriptor.Algorithm, cancellationToken);
        await Store.SetCreationDateAsync(key, descriptor.CreationDate, cancellationToken);
        await Store.SetExpirationDateAsync(key, descriptor.ExpirationDate, cancellationToken);
        await Store.SetKeyIdAsync(key, descriptor.KeyId, cancellationToken);
        await Store.SetPayloadAsync(key, descriptor.Payload, cancellationToken);
        await Store.SetPropertiesAsync(key, [.. descriptor.Properties], cancellationToken);
        await Store.SetRetirementDateAsync(key, descriptor.RetirementDate, cancellationToken);
        await Store.SetStatusAsync(key, descriptor.Status, cancellationToken);
        await Store.SetUsageAsync(key, descriptor.Usage, cancellationToken);
    }

    /// <inheritdoc cref="IOpenIddictKeyManager.PopulateAsync(OpenIddictKeyDescriptor, object, CancellationToken)"/>
    public virtual async ValueTask PopulateAsync(OpenIddictKeyDescriptor descriptor,
        TEntity key, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        ArgumentNullException.ThrowIfNull(key);

        descriptor.ActivationDate = await Store.GetActivationDateAsync(key, cancellationToken);
        descriptor.Algorithm = await Store.GetAlgorithmAsync(key, cancellationToken);
        descriptor.CreationDate = await Store.GetCreationDateAsync(key, cancellationToken);
        descriptor.ExpirationDate = await Store.GetExpirationDateAsync(key, cancellationToken);
        descriptor.KeyId = await Store.GetKeyIdAsync(key, cancellationToken);
        descriptor.Payload = await Store.GetPayloadAsync(key, cancellationToken);
        descriptor.RetirementDate = await Store.GetRetirementDateAsync(key, cancellationToken);
        descriptor.Status = await Store.GetStatusAsync(key, cancellationToken);
        descriptor.Usage = await Store.GetUsageAsync(key, cancellationToken);

        descriptor.Properties.Clear();
        foreach (var pair in await Store.GetPropertiesAsync(key, cancellationToken))
        {
            descriptor.Properties.Add(pair.Key, pair.Value);
        }
    }

    /// <inheritdoc cref="IOpenIddictKeyManager.PruneAsync(DateTimeOffset, CancellationToken)"/>
    public virtual ValueTask<long> PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken = default)
        => Store.PruneAsync(threshold, cancellationToken);

    /// <inheritdoc cref="IOpenIddictKeyManager.TryRevokeAsync(object, CancellationToken)"/>
    public virtual async ValueTask<bool> TryRevokeAsync(TEntity key, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);

        if (await HasStatusAsync(key, Statuses.Revoked, cancellationToken))
        {
            return true;
        }

        await Store.SetStatusAsync(key, Statuses.Revoked, cancellationToken);

        try
        {
            await UpdateAsync(key, cancellationToken);

            return true;
        }

        catch (ConcurrencyException)
        {
            return false;
        }
    }

    /// <inheritdoc cref="IOpenIddictKeyManager.UpdateAsync(object, CancellationToken)"/>
    public virtual async ValueTask UpdateAsync(TEntity key, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);

        await EnsureValidAsync(key, SR.ID0215, cancellationToken);
        await Store.UpdateAsync(key, cancellationToken);
    }

    /// <inheritdoc cref="IOpenIddictKeyManager.UpdateAsync(object, OpenIddictKeyDescriptor, CancellationToken)"/>
    public virtual async ValueTask UpdateAsync(TEntity key,
        OpenIddictKeyDescriptor descriptor, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(descriptor);

        await PopulateAsync(key, descriptor, cancellationToken);
        await UpdateAsync(key, cancellationToken);
    }

    /// <inheritdoc cref="IOpenIddictKeyManager.ValidateAsync(object, CancellationToken)"/>
    public virtual IAsyncEnumerable<ValidationResult> ValidateAsync(TEntity key, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<ValidationResult> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(await Store.GetStatusAsync(key, cancellationToken)))
            {
                yield return new ValidationResult(SR.GetResourceString(SR.ID2038));
            }

            if (string.IsNullOrEmpty(await Store.GetKeyIdAsync(key, cancellationToken)))
            {
                yield return new ValidationResult(SR.GetResourceString(SR.ID2220));
            }

            if (string.IsNullOrEmpty(await Store.GetPayloadAsync(key, cancellationToken)))
            {
                yield return new ValidationResult(SR.GetResourceString(SR.ID2221));
            }

            if (await Store.GetUsageAsync(key, cancellationToken) is not ("sig" or "enc"))
            {
                yield return new ValidationResult(SR.GetResourceString(SR.ID2222));
            }

            if (string.IsNullOrEmpty(await Store.GetAlgorithmAsync(key, cancellationToken)))
            {
                yield return new ValidationResult(SR.GetResourceString(SR.ID2223));
            }

            if (await Store.GetActivationDateAsync(key, cancellationToken) is not DateTimeOffset activation ||
                await Store.GetExpirationDateAsync(key, cancellationToken) is not DateTimeOffset expiration ||
                await Store.GetRetirementDateAsync(key, cancellationToken) is not DateTimeOffset retirement ||
                expiration <= activation || retirement < expiration)
            {
                yield return new ValidationResult(SR.GetResourceString(SR.ID2224));
            }
        }
    }

    private async ValueTask EnsureValidAsync(TEntity key, string message, CancellationToken cancellationToken)
    {
        var results = ImmutableArray.CreateBuilder<ValidationResult>();

        await foreach (var result in ValidateAsync(key, cancellationToken))
        {
            results.Add(result);
        }

        if (results.Any(static result => result != ValidationResult.Success))
        {
            var builder = new StringBuilder();
            builder.AppendLine(SR.GetResourceString(message));
            builder.AppendLine();

            foreach (var result in results)
            {
                builder.AppendLine(result.ErrorMessage);
            }

            throw new ValidationException(builder.ToString(), results.ToImmutable());
        }
    }

    /// <inheritdoc/>
    ValueTask<long> IOpenIddictKeyManager.CountAsync(CancellationToken cancellationToken)
        => CountAsync(cancellationToken);

    /// <inheritdoc/>
    async ValueTask<object> IOpenIddictKeyManager.CreateAsync(OpenIddictKeyDescriptor descriptor, CancellationToken cancellationToken)
        => await CreateAsync(descriptor, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictKeyManager.CreateAsync(object key, CancellationToken cancellationToken)
        => CreateAsync((TEntity) key, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictKeyManager.DeleteAsync(object key, CancellationToken cancellationToken)
        => DeleteAsync((TEntity) key, cancellationToken);

    /// <inheritdoc/>
    async ValueTask<object?> IOpenIddictKeyManager.FindByIdAsync(string identifier, CancellationToken cancellationToken)
        => await FindByIdAsync(identifier, cancellationToken);

    /// <inheritdoc/>
    ValueTask<DateTimeOffset?> IOpenIddictKeyManager.GetActivationDateAsync(object key, CancellationToken cancellationToken)
        => GetActivationDateAsync((TEntity) key, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictKeyManager.GetAlgorithmAsync(object key, CancellationToken cancellationToken)
        => GetAlgorithmAsync((TEntity) key, cancellationToken);

    /// <inheritdoc/>
    ValueTask<DateTimeOffset?> IOpenIddictKeyManager.GetCreationDateAsync(object key, CancellationToken cancellationToken)
        => GetCreationDateAsync((TEntity) key, cancellationToken);

    /// <inheritdoc/>
    ValueTask<DateTimeOffset?> IOpenIddictKeyManager.GetExpirationDateAsync(object key, CancellationToken cancellationToken)
        => GetExpirationDateAsync((TEntity) key, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictKeyManager.GetIdAsync(object key, CancellationToken cancellationToken)
        => GetIdAsync((TEntity) key, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictKeyManager.GetKeyIdAsync(object key, CancellationToken cancellationToken)
        => GetKeyIdAsync((TEntity) key, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictKeyManager.GetPayloadAsync(object key, CancellationToken cancellationToken)
        => GetPayloadAsync((TEntity) key, cancellationToken);

    /// <inheritdoc/>
    ValueTask<ImmutableDictionary<string, JsonElement>> IOpenIddictKeyManager.GetPropertiesAsync(object key, CancellationToken cancellationToken)
        => GetPropertiesAsync((TEntity) key, cancellationToken);

    /// <inheritdoc/>
    ValueTask<DateTimeOffset?> IOpenIddictKeyManager.GetRetirementDateAsync(object key, CancellationToken cancellationToken)
        => GetRetirementDateAsync((TEntity) key, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictKeyManager.GetStatusAsync(object key, CancellationToken cancellationToken)
        => GetStatusAsync((TEntity) key, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictKeyManager.GetUsageAsync(object key, CancellationToken cancellationToken)
        => GetUsageAsync((TEntity) key, cancellationToken);

    /// <inheritdoc/>
    ValueTask<bool> IOpenIddictKeyManager.HasStatusAsync(object key, string status, CancellationToken cancellationToken)
        => HasStatusAsync((TEntity) key, status, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<object> IOpenIddictKeyManager.ListAsync(int? count, int? offset, CancellationToken cancellationToken)
        => ListAsync(count, offset, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictKeyManager.PopulateAsync(OpenIddictKeyDescriptor descriptor, object key, CancellationToken cancellationToken)
        => PopulateAsync(descriptor, (TEntity) key, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictKeyManager.PopulateAsync(object key, OpenIddictKeyDescriptor descriptor, CancellationToken cancellationToken)
        => PopulateAsync((TEntity) key, descriptor, cancellationToken);

    /// <inheritdoc/>
    ValueTask<long> IOpenIddictKeyManager.PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken)
        => PruneAsync(threshold, cancellationToken);

    /// <inheritdoc/>
    ValueTask<bool> IOpenIddictKeyManager.TryRevokeAsync(object key, CancellationToken cancellationToken)
        => TryRevokeAsync((TEntity) key, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictKeyManager.UpdateAsync(object key, CancellationToken cancellationToken)
        => UpdateAsync((TEntity) key, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictKeyManager.UpdateAsync(object key, OpenIddictKeyDescriptor descriptor, CancellationToken cancellationToken)
        => UpdateAsync((TEntity) key, descriptor, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<ValidationResult> IOpenIddictKeyManager.ValidateAsync(object key, CancellationToken cancellationToken)
        => ValidateAsync((TEntity) key, cancellationToken);
}
