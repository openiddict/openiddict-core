/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Linq;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.Quartz;
using Quartz;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace Microsoft.Extensions.DependencyInjection
{
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
        /// <returns>The <see cref="OpenIddictQuartzBuilder"/>.</returns>
        public static OpenIddictQuartzBuilder UseQuartz(this OpenIddictCoreBuilder builder)
        {
            if (builder is null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            // Warning: the AddQuartz() method is deliberately not used as it's not idempotent.
            // Calling it at this point may override user-defined services (e.g Quartz DI support).

            builder.Services.TryAddTransient<OpenIddictQuartzJob>();

            // To ensure this method can be safely called multiple times, the job details
            // of the OpenIddict job are only added if no existing IJobDetail instance
            // pointing to OpenIddictQuartzJob was already registered in the DI container.
            if (!builder.Services.Any(descriptor => descriptor.ServiceType == typeof(IJobDetail) &&
                                                    descriptor.ImplementationInstance is IJobDetail job &&
                                                    job.Key.Equals(OpenIddictQuartzJob.Identity)))
            {
                builder.Services.AddSingleton(
                    JobBuilder.Create<OpenIddictQuartzJob>()
                        .StoreDurably()
                        .WithIdentity(OpenIddictQuartzJob.Identity)
                        .WithDescription(SR.GetResourceString(SR.ID8000))
                        .Build());
            }

            // To ensure this method can be safely called multiple times, the trigger details
            // of the OpenIddict job are only added if no existing ITrigger instance
            // pointing to OpenIddictQuartzJob was already registered in the DI container.
            if (!builder.Services.Any(descriptor => descriptor.ServiceType == typeof(ITrigger) &&
                                                    descriptor.ImplementationInstance is ITrigger trigger &&
                                                    trigger.JobKey.Equals(OpenIddictQuartzJob.Identity)))
            {
                // Note: this trigger uses a quite long interval (1 hour), which means it may be
                // potentially never reached if the application is shut down or recycled. As such,
                // this trigger is set up to fire immediately to ensure it's executed at least once.
                builder.Services.AddSingleton(
                    TriggerBuilder.Create()
                        .ForJob(OpenIddictQuartzJob.Identity)
                        .WithSimpleSchedule(options => options.WithIntervalInHours(1).RepeatForever())
                        .WithDescription(SR.GetResourceString(SR.ID8001))
                        .StartNow()
                        .Build());
            }

            return new OpenIddictQuartzBuilder(builder.Services);
        }

        /// <summary>
        /// Registers the OpenIddict Quartz.NET integration in the DI container.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <param name="configuration">The configuration delegate used to configure the Quartz.NET services.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
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
}
