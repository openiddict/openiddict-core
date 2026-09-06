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
        ArgumentNullException.ThrowIfNull(builder);

        // Note: the AddQuartz() method MUST only be called once to avoid adding multiple jobs and triggers.
        if (!builder.Services.Any(static descriptor => descriptor.ServiceType == typeof(OpenIddictQuartzJob)))
        {
            builder.Services.AddQuartz(options =>
            {
                options.AddJob<OpenIddictQuartzJob>(static builder =>
                {
                    builder.StoreDurably()
                           .WithIdentity(OpenIddictQuartzJob.Identity)
                           .WithDescription(SR.GetResourceString(SR.ID8001));
                });

                options.AddTrigger(static builder =>
                {
                    // Note: this trigger uses a quite long interval (1 hour), which means it may be potentially never
                    // reached if the application is shut down or recycled. As such, this trigger is set up to fire
                    // between 1 and 10 minutes after the application starts to ensure the job is executed at least once.
                    builder.ForJob(OpenIddictQuartzJob.Identity)
                           .WithIdentity(SR.GetResourceString(SR.ID8004), SR.GetResourceString(SR.ID8005))
                           .WithSimpleSchedule(options => options.WithInterval(TimeSpan.FromHours(1)).RepeatForever())
                           .WithDescription(SR.GetResourceString(SR.ID8002))
                           .StartAt(TimeProvider.System.GetUtcNow() + TimeSpan.FromMinutes(new Random().Next(1, 10)));
                });
            });
        }

#if !NET10_0_OR_GREATER
        // Note: unlike Quartz.NET 4.0+, Quartz.NET 3.x doesn't automatically register the job as a service.
        builder.Services.TryAddTransient<OpenIddictQuartzJob>();
#endif

        // Note: TryAddEnumerable() is used here to ensure the initializer is registered only once.
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IPostConfigureOptions<OpenIddictQuartzOptions>, OpenIddictQuartzConfiguration>());

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
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configuration);

        configuration(builder.UseQuartz());

        return builder;
    }
}
