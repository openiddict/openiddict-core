/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;

namespace OpenIddict.Quartz;

/// <summary>
/// Provides various settings needed to configure the OpenIddict Quartz.NET integration.
/// </summary>
public class OpenIddictQuartzOptions
{
    /// <summary>
    /// Gets or sets a boolean indicating whether authorizations pruning should be disabled.
    /// </summary>
    public bool DisableAuthorizationPruning { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether tokens pruning should be disabled.
    /// </summary>
    public bool DisableTokenPruning { get; set; }

    /// <summary>
    /// Gets or sets the number of times a failed Quartz.NET job can be retried.
    /// By default, failed jobs are automatically retried twice after the initial failure.
    /// </summary>
    public int MaximumRefireCount { get; set; } = 2;

    /// <summary>
    /// Gets or sets the minimum lifespan authorizations must have to be pruned.
    /// By default, this value is set to 14 days and cannot be less than 10 minutes.
    /// </summary>
    public TimeSpan MinimumAuthorizationLifespan { get; set; } = TimeSpan.FromDays(14);

    /// <summary>
    /// Gets or sets the minimum lifespan tokens must have to be pruned.
    /// By default, this value is set to 14 days and cannot be less than 10 minutes.
    /// </summary>
    public TimeSpan MinimumTokenLifespan { get; set; } = TimeSpan.FromDays(14);
}
