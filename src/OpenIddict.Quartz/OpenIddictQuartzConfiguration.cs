/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using Microsoft.Extensions.Options;
using Quartz;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.Quartz
{
    /// <summary>
    /// Contains the methods required to ensure that the OpenIddict Quartz.NET configuration is valid.
    /// </summary>
    public class OpenIddictQuartzConfiguration : IConfigureOptions<QuartzOptions>
    {
        /// <inheritdoc/>
        public void Configure(QuartzOptions options)
        {
            if (options is null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            options.AddJob<OpenIddictQuartzJob>(builder =>
            {
                builder.StoreDurably()
                       .WithIdentity(OpenIddictQuartzJob.Identity)
                       .WithDescription(SR.GetResourceString(SR.ID8000));
            });

            options.AddTrigger(builder =>
            {
                // Note: this trigger uses a quite long interval (1 hour), which means it may be potentially
                // never reached if the application is shut down or recycled. As such, this trigger is set up
                // to fire 2 minutes after the application starts to ensure it's executed at least once.
                builder.ForJob(OpenIddictQuartzJob.Identity)
                       .WithSimpleSchedule(options => options.WithIntervalInHours(1).RepeatForever())
                       .WithDescription(SR.GetResourceString(SR.ID8001))
                       .StartAt(DateBuilder.FutureDate(2, IntervalUnit.Minute));
            });
        }
    }
}
