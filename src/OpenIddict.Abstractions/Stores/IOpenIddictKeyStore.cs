/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Text.Json;

namespace OpenIddict.Abstractions;

/// <summary>
/// Provides methods allowing to manage the cryptographic keys stored in a database.
/// </summary>
/// <typeparam name="TEntity">The type of the key entity.</typeparam>
public interface IOpenIddictKeyStore<TEntity> where TEntity : class
{
    /// <summary>
    /// Determines the number of keys that exist in the database.
    /// </summary>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The number of keys in the database.</returns>
    ValueTask<long> CountAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Creates a new key.
    /// </summary>
    /// <param name="key">The key to create.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask CreateAsync(TEntity key, CancellationToken cancellationToken);

    /// <summary>
    /// Removes an existing key.
    /// </summary>
    /// <param name="key">The key to delete.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask DeleteAsync(TEntity key, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves a key using its unique identifier.
    /// </summary>
    /// <param name="identifier">The unique identifier associated with the key.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The key corresponding to the identifier.</returns>
    ValueTask<TEntity?> FindByIdAsync(string identifier, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the activation date associated with a key.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The activation date associated with the key.</returns>
    ValueTask<DateTimeOffset?> GetActivationDateAsync(TEntity key, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the JSON Web Algorithm associated with a key.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The algorithm associated with the key.</returns>
    ValueTask<string?> GetAlgorithmAsync(TEntity key, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the creation date associated with a key.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The creation date associated with the key.</returns>
    ValueTask<DateTimeOffset?> GetCreationDateAsync(TEntity key, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the expiration date associated with a key.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The expiration date associated with the key.</returns>
    ValueTask<DateTimeOffset?> GetExpirationDateAsync(TEntity key, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the unique identifier associated with a key.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The unique identifier associated with the key.</returns>
    ValueTask<string?> GetIdAsync(TEntity key, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the public key identifier ("kid") associated with a key.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The public key identifier associated with the key.</returns>
    ValueTask<string?> GetKeyIdAsync(TEntity key, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the protected key material associated with a key.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The protected key material associated with the key.</returns>
    ValueTask<string?> GetPayloadAsync(TEntity key, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the additional properties associated with a key.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The additional properties associated with the key.</returns>
    ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(TEntity key, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the retirement date associated with a key.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The retirement date associated with the key.</returns>
    ValueTask<DateTimeOffset?> GetRetirementDateAsync(TEntity key, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the status associated with a key.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The status associated with the key.</returns>
    ValueTask<string?> GetStatusAsync(TEntity key, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the usage ("sig" or "enc") associated with a key.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The usage associated with the key.</returns>
    ValueTask<string?> GetUsageAsync(TEntity key, CancellationToken cancellationToken);

    /// <summary>
    /// Instantiates a new key.
    /// </summary>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The instantiated key, that can be persisted in the database.</returns>
    ValueTask<TEntity> InstantiateAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Returns all the keys, ordered by identifier.
    /// </summary>
    /// <param name="count">The number of results to return.</param>
    /// <param name="offset">The number of results to skip.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>All the keys.</returns>
    IAsyncEnumerable<TEntity> ListAsync(int? count, int? offset, CancellationToken cancellationToken);

    /// <summary>
    /// Removes the keys retired before the specified <paramref name="threshold"/>
    /// and the non-valid keys created before the specified <paramref name="threshold"/>.
    /// </summary>
    /// <param name="threshold">The date before which keys are pruned.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The number of keys that were removed.</returns>
    ValueTask<long> PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the activation date associated with a key.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="date">The activation date.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetActivationDateAsync(TEntity key, DateTimeOffset? date, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the JSON Web Algorithm associated with a key.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="algorithm">The algorithm.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetAlgorithmAsync(TEntity key, string? algorithm, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the creation date associated with a key.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="date">The creation date.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetCreationDateAsync(TEntity key, DateTimeOffset? date, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the expiration date associated with a key.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="date">The expiration date.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetExpirationDateAsync(TEntity key, DateTimeOffset? date, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the public key identifier ("kid") associated with a key.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="identifier">The public key identifier.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetKeyIdAsync(TEntity key, string? identifier, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the protected key material associated with a key.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="payload">The protected key material.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetPayloadAsync(TEntity key, string? payload, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the additional properties associated with a key.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="properties">The additional properties.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetPropertiesAsync(TEntity key, ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the retirement date associated with a key.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="date">The retirement date.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetRetirementDateAsync(TEntity key, DateTimeOffset? date, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the status associated with a key.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="status">The status.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetStatusAsync(TEntity key, string? status, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the usage ("sig" or "enc") associated with a key.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="usage">The usage.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetUsageAsync(TEntity key, string? usage, CancellationToken cancellationToken);

    /// <summary>
    /// Updates an existing key.
    /// </summary>
    /// <param name="key">The key to update.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask UpdateAsync(TEntity key, CancellationToken cancellationToken);
}
