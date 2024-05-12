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
    private readonly IServiceProvider _provider;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictCoreConfiguration"/> class.
    /// </summary>
    /// <param name="provider">The service provider.</param>
    public OpenIddictCoreConfiguration(IServiceProvider provider)
        => _provider = provider ?? throw new ArgumentNullException(nameof(provider));

    /// <inheritdoc/>
    public void PostConfigure(string? name, OpenIddictCoreOptions options)
    {
#if SUPPORTS_TIME_PROVIDER
        options.TimeProvider ??= _provider.GetService<TimeProvider>() ?? TimeProvider.System;
#endif
    }
}
