﻿/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace OpenIddict.Quartz;

/// <summary>
/// Contains the methods required to ensure that the OpenIddict Quartz.NET configuration is valid.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictQuartzConfiguration : IConfigureOptions<QuartzOptions>,
    IPostConfigureOptions<OpenIddictQuartzOptions>
{
    private readonly IServiceProvider _serviceProvider;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictQuartzConfiguration"/> class.
    /// </summary>
    /// <param name="serviceProvider">The service provider.</param>
    public OpenIddictQuartzConfiguration(IServiceProvider serviceProvider)
        => _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));

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
                   .WithDescription(SR.GetResourceString(SR.ID8001));
        });

        options.AddTrigger(builder =>
        {
            // Note: this trigger uses a quite long interval (1 hour), which means it may be potentially never
            // reached if the application is shut down or recycled. As such, this trigger is set up to fire
            // between 1 and 10 minutes after the application starts to ensure the job is executed at least once.
            builder.ForJob(OpenIddictQuartzJob.Identity)
                   .WithIdentity(SR.GetResourceString(SR.ID8004), SR.GetResourceString(SR.ID8005))
                   .WithSimpleSchedule(options => options.WithIntervalInHours(1).RepeatForever())
                   .WithDescription(SR.GetResourceString(SR.ID8002))
                   .StartAt(DateBuilder.FutureDate(new Random().Next(1, 10), IntervalUnit.Minute));
        });
    }

    public void PostConfigure(string? name, OpenIddictQuartzOptions options)
    {
#if SUPPORTS_TIME_PROVIDER
        if (options.TimeProvider is null)
        {
            options.TimeProvider = _serviceProvider.GetService<TimeProvider>() ?? TimeProvider.System;
        }
#endif
    }
}
