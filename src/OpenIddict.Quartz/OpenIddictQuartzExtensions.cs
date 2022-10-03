/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using OpenIddict.Quartz;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes extensions allowing to register the OpenIddict Quartz.NET integration.
/// </summary>
public static class OpenIddictQuartzExtensions
{
    /// <summary>
    /// Registers the OpenIddict Quartz.NET integration in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictQuartzBuilder"/> instance.</returns>
    public static OpenIddictQuartzBuilder UseQuartz(this OpenIddictCoreBuilder builder)
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        builder.Services.AddQuartz();

        // The OpenIddict job is registered as a service to allow
        // Quartz.NET's DI integration to resolve it from the DI.
        builder.Services.TryAddTransient<OpenIddictQuartzJob>();

        // Note: TryAddEnumerable() is used here to ensure the initializer is registered only once.
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IConfigureOptions<QuartzOptions>, OpenIddictQuartzConfiguration>());

        return new OpenIddictQuartzBuilder(builder.Services);
    }

    /// <summary>
    /// Registers the OpenIddict Quartz.NET integration in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <param name="configuration">The configuration delegate used to configure the Quartz.NET services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictCoreBuilder"/> instance.</returns>
    public static OpenIddictCoreBuilder UseQuartz(
        this OpenIddictCoreBuilder builder, Action<OpenIddictQuartzBuilder> configuration)
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        configuration(builder.UseQuartz());

        return builder;
    }
}
