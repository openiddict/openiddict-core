/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace OpenIddict.Core;

/// <summary>
/// Contains the methods required to ensure that the OpenIddict core configuration is valid.
/// </summary>
public class OpenIddictCoreConfiguration : IPostConfigureOptions<OpenIddictCoreOptions>
{
    private readonly IServiceProvider _serviceProvider;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictCoreConfiguration"/> class.
    /// </summary>
    /// <param name="serviceProvider">The service provider.</param>
    public OpenIddictCoreConfiguration(IServiceProvider serviceProvider)
        => _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));

    /// <inheritdoc/>
    public void PostConfigure(string? name, OpenIddictCoreOptions options)
    {
#if SUPPORTS_TIME_PROVIDER
        if (options.TimeProvider is null)
        {
            options.TimeProvider = _serviceProvider.GetService<TimeProvider>() ?? TimeProvider.System;
        }
#endif
    }
}
