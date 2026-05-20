/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Security.Cryptography;

namespace OpenIddict.Core;

/// <summary>
/// Provides various settings needed to configure the OpenIddict core services.
/// </summary>
public sealed class OpenIddictCoreOptions
{
    /// <summary>
    /// Gets or sets the hash algorithm used to protect the client secrets (by default, SHA512).
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public HashAlgorithmName ClientSecretKeyDerivationHashAlgorithm { get; set; } = HashAlgorithmName.SHA512;

    /// <summary>
    /// Gets or sets the number of iterations used to protect the client secrets (by default, 100 000).
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public int ClientSecretKeyDerivationIterations { get; set; } = 100_000;

    /// <summary>
    /// Gets or sets the length (in bits) of the PBKDF2 key used to protect the client secrets (by default, 512 bits).
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public int ClientSecretKeyDerivationOutputLength { get; set; } = 512;

    /// <summary>
    /// Gets or sets the length (in bits) of the salt used to protect the client secrets (by default, 256 bits).
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public int ClientSecretKeyDerivationSaltLength { get; set; } = 256;

    /// <summary>
    /// Gets or sets a boolean indicating whether additional filtering should be disabled,
    /// so that the OpenIddict managers don't execute a second check to ensure the results
    /// returned by the stores exactly match the specified query filters, casing included.
    /// This property SHOULD NOT be set to <see langword="true"/> except when the underlying stores
    /// are guaranteed to execute case-sensitive filtering at the database level.
    /// Disabling this feature MAY result in security vulnerabilities in the other cases.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public bool DisableAdditionalFiltering { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether automatic client secret rehashing should be disabled.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public bool DisableAutomaticClientSecretRehashing { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether entity caching should be disabled.
    /// Disabling entity caching may have a noticeable impact on the performance
    /// of your application and result in multiple queries being sent by the stores.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public bool DisableEntityCaching { get; set; }

    /// <summary>
    /// Gets or sets the maximum number of cached entries allowed. When the threshold
    /// is reached, the cache is automatically compacted to ensure it doesn't grow
    /// abnormally and doesn't cause a memory starvation or out-of-memory exceptions.
    /// This property is not used when <see cref="DisableEntityCaching"/> is <see langword="true"/>.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public int EntityCacheLimit { get; set; } = 250;

    /// <summary>
    /// Gets or sets the time provider.
    /// </summary>
    /// <remarks>
    /// Note: if this property is not explicitly set, the time provider is
    /// automatically resolved from the dependency injection container.
    /// If no service can be found, <see cref="TimeProvider.System"/> is used.
    /// </remarks>
    public TimeProvider TimeProvider { get; set; } = default!;
}
