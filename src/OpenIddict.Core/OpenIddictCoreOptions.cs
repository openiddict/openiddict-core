/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Core;

/// <summary>
/// Provides various settings needed to configure the OpenIddict core services.
/// </summary>
public sealed class OpenIddictCoreOptions
{
    /// <summary>
    /// Gets or sets a boolean indicating whether additional filtering should be disabled,
    /// so that the OpenIddict managers don't execute a second check to ensure the results
    /// returned by the stores exactly match the specified query filters, casing included.
    /// This property SHOULD NOT be set to <see langword="true"/> except when the underlying stores
    /// are guaranteed to execute case-sensitive filtering at the database level.
    /// Disabling this feature MAY result in security vulnerabilities in the other cases.
    /// </summary>
    public bool DisableAdditionalFiltering { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether entity caching should be disabled.
    /// Disabling entity caching may have a noticeable impact on the performance
    /// of your application and result in multiple queries being sent by the stores.
    /// </summary>
    public bool DisableEntityCaching { get; set; }

    /// <summary>
    /// Gets or sets the maximum number of cached entries allowed. When the threshold
    /// is reached, the cache is automatically compacted to ensure it doesn't grow
    /// abnormally and doesn't cause a memory starvation or out-of-memory exceptions.
    /// This property is not used when <see cref="DisableEntityCaching"/> is <see langword="true"/>.
    /// </summary>
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
