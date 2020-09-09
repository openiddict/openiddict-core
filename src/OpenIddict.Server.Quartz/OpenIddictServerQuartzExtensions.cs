/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Linq;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.Server.Quartz;
using Quartz;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Exposes extensions allowing to register the OpenIddict server Quartz.NET integration.
    /// </summary>
    public static class OpenIddictServerQuartzExtensions
    {
        /// <summary>
        /// Registers the OpenIddict server Quartz.NET integration in the DI container.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictServerQuartzBuilder"/>.</returns>
        public static OpenIddictServerQuartzBuilder UseQuartz(this OpenIddictServerBuilder builder)
        {
            if (builder is null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            // Warning: the AddQuartz() method is deliberately not used as it's not idempotent.
            // Calling it at this point may override user-defined services (e.g Quartz DI support).

            builder.Services.TryAddTransient<OpenIddictServerQuartzJob>();

            // To ensure this method can be safely called multiple times, the job details
            // of the OpenIddict server job are only added if no existing IJobDetail instance
            // pointing to OpenIddictServerQuartzJob was already registered in the DI container.
            if (!builder.Services.Any(descriptor => descriptor.ServiceType == typeof(IJobDetail) &&
                                                    descriptor.ImplementationInstance is IJobDetail job &&
                                                    job.Key.Equals(OpenIddictServerQuartzJob.Identity)))
            {
                builder.Services.AddSingleton(
                    JobBuilder.Create<OpenIddictServerQuartzJob>()
                        .StoreDurably()
                        .WithIdentity(OpenIddictServerQuartzJob.Identity)
                        .WithDescription(SR.GetResourceString(SR.ID9000))
                        .Build());
            }

            // To ensure this method can be safely called multiple times, the trigger details
            // of the OpenIddict server job are only added if no existing ITrigger instance
            // pointing to OpenIddictServerQuartzJob was already registered in the DI container.
            if (!builder.Services.Any(descriptor => descriptor.ServiceType == typeof(ITrigger) &&
                                                    descriptor.ImplementationInstance is ITrigger trigger &&
                                                    trigger.JobKey.Equals(OpenIddictServerQuartzJob.Identity)))
            {
                // Note: this trigger uses a quite long interval (1 hour), which means it may be
                // potentially never reached if the application is shut down or recycled. As such,
                // this trigger is set up to fire immediately to ensure it's executed at least once.
                builder.Services.AddSingleton(
                    TriggerBuilder.Create()
                        .ForJob(OpenIddictServerQuartzJob.Identity)
                        .WithSimpleSchedule(options => options.WithIntervalInHours(1).RepeatForever())
                        .WithDescription(SR.GetResourceString(SR.ID9001))
                        .StartNow()
                        .Build());
            }

            return new OpenIddictServerQuartzBuilder(builder.Services);
        }

        /// <summary>
        /// Registers the OpenIddict server Quartz.NET integration in the DI container.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <param name="configuration">The configuration delegate used to configure the server services.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public static OpenIddictServerBuilder UseQuartz(
            this OpenIddictServerBuilder builder, Action<OpenIddictServerQuartzBuilder> configuration)
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
