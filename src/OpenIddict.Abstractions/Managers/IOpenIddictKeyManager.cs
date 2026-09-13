/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel.DataAnnotations;
using System.Text.Json;

namespace OpenIddict.Abstractions;

/// <summary>
/// Provides methods allowing to manage the cryptographic keys stored in the store.
/// </summary>
/// <remarks>
/// Note: this interface is not meant to be implemented by custom managers,
/// that should inherit from the generic OpenIddictKeyManager class.
/// It is primarily intended to be used by services that cannot easily depend
/// on the generic key manager. The actual key entity type is automatically
/// determined at runtime based on the OpenIddict core options.
/// </remarks>
public interface IOpenIddictKeyManager
{
    /// <summary>
    /// Determines the number of keys that exist in the database.
    /// </summary>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The number of keys in the database.</returns>
    ValueTask<long> CountAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new key based on the specified descriptor.
    /// </summary>
    /// <param name="descriptor">The key descriptor.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The key.</returns>
    ValueTask<object> CreateAsync(OpenIddictKeyDescriptor descriptor, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new key.
    /// </summary>
    /// <param name="key">The key to create.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask CreateAsync(object key, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes an existing key.
    /// </summary>
    /// <param name="key">The key to delete.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask DeleteAsync(object key, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a key using its unique identifier.
    /// </summary>
    /// <param name="identifier">The unique identifier associated with the key.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The key corresponding to the identifier.</returns>
    ValueTask<object?> FindByIdAsync(string identifier, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the activation date associated with a key.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The activation date associated with the key.</returns>
    ValueTask<DateTimeOffset?> GetActivationDateAsync(object key, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the JSON Web Algorithm associated with a key.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The algorithm associated with the key.</returns>
    ValueTask<string?> GetAlgorithmAsync(object key, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the creation date associated with a key.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The creation date associated with the key.</returns>
    ValueTask<DateTimeOffset?> GetCreationDateAsync(object key, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the expiration date associated with a key.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The expiration date associated with the key.</returns>
    ValueTask<DateTimeOffset?> GetExpirationDateAsync(object key, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the unique identifier associated with a key.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The unique identifier associated with the key.</returns>
    ValueTask<string?> GetIdAsync(object key, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the public key identifier ("kid") associated with a key.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The public key identifier associated with the key.</returns>
    ValueTask<string?> GetKeyIdAsync(object key, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the protected key material associated with a key.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The protected key material associated with the key.</returns>
    ValueTask<string?> GetPayloadAsync(object key, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the additional properties associated with a key.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The additional properties associated with the key.</returns>
    ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(object key, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the retirement date associated with a key.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The retirement date associated with the key.</returns>
    ValueTask<DateTimeOffset?> GetRetirementDateAsync(object key, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the status associated with a key.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The status associated with the key.</returns>
    ValueTask<string?> GetStatusAsync(object key, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the usage ("sig" or "enc") associated with a key.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The usage associated with the key.</returns>
    ValueTask<string?> GetUsageAsync(object key, CancellationToken cancellationToken = default);

    /// <summary>
    /// Determines whether a given key has the specified status.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="status">The expected status.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns><see langword="true"/> if the key has the specified status, <see langword="false"/> otherwise.</returns>
    ValueTask<bool> HasStatusAsync(object key, string status, CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns all the keys, ordered by identifier.
    /// </summary>
    /// <param name="count">The number of results to return.</param>
    /// <param name="offset">The number of results to skip.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>All the keys.</returns>
    IAsyncEnumerable<object> ListAsync(int? count = null, int? offset = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Populates the specified descriptor using the properties exposed by the key.
    /// </summary>
    /// <param name="descriptor">The descriptor.</param>
    /// <param name="key">The key.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask PopulateAsync(OpenIddictKeyDescriptor descriptor, object key, CancellationToken cancellationToken = default);

    /// <summary>
    /// Populates the key using the specified descriptor.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="descriptor">The descriptor.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask PopulateAsync(object key, OpenIddictKeyDescriptor descriptor, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes the keys retired before the specified <paramref name="threshold"/>
    /// and the non-valid keys created before the specified <paramref name="threshold"/>.
    /// </summary>
    /// <param name="threshold">The date before which keys are pruned.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The number of keys that were removed.</returns>
    ValueTask<long> PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken = default);

    /// <summary>
    /// Tries to revoke a key.
    /// </summary>
    /// <param name="key">The key to revoke.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns><see langword="true"/> if the key was successfully revoked, <see langword="false"/> otherwise.</returns>
    ValueTask<bool> TryRevokeAsync(object key, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates an existing key.
    /// </summary>
    /// <param name="key">The key to update.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask UpdateAsync(object key, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates an existing key.
    /// </summary>
    /// <param name="key">The key to update.</param>
    /// <param name="descriptor">The descriptor used to update the key.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask UpdateAsync(object key, OpenIddictKeyDescriptor descriptor, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates the key to ensure it's in a consistent state.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The validation error encountered when validating the key.</returns>
    IAsyncEnumerable<ValidationResult> ValidateAsync(object key, CancellationToken cancellationToken = default);
}
