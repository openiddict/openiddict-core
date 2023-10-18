/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using OpenIddict.Pruning.BackgroundService;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes extensions allowing to register the OpenIddict Pruning using BackgroundService in the DI container.
/// </summary>
public static class OpenIddictPruningExtensions
{
    /// <summary>
    /// Registers the OpenIddict Pruning using BackgroundService in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictPruningBuilder"/> instance.</returns>
    public static OpenIddictPruningBuilder UseBackgroundServicePruning(this OpenIddictCoreBuilder builder)
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

#if NET
        builder.Services.AddHostedService<OpenIddictPruningBackgroundService>();
#else
        builder.Services.TryAddEnumerable(ServiceDescriptor.Transient<IHostedService, OpenIddictPruningBackgroundService>());
#endif

        builder.Services.TryAdd(ServiceDescriptor
           .Singleton<IConfigureOptions<OpenIddictPruningOptions>, OpenIddictPruningConfiguration>());

        return new OpenIddictPruningBuilder(builder.Services);
    }

    /// <summary>
    /// Registers the OpenIddict Pruning using BackgroundService in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <param name="configuration">The configuration delegate used to configure the Pruning.NET services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictCoreBuilder"/> instance.</returns>
    public static OpenIddictCoreBuilder UseBackgroundServicePruning(
        this OpenIddictCoreBuilder builder, Action<OpenIddictPruningBuilder> configuration)
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        configuration(builder.UseBackgroundServicePruning());

        return builder;
    }
}
