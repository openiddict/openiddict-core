/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Pruning.BackgroundService;

/// <summary>
/// Provides various settings needed to configure the OpenIddict Pruning using BackgroundService.
/// </summary>
public class OpenIddictPruningOptions
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
    /// Gets or sets the minimum lifespan authorizations must have to be pruned.
    /// By default, this value is set to 14 days and cannot be less than 10 minutes.
    /// </summary>
    public TimeSpan MinimumAuthorizationLifespan { get; set; } = TimeSpan.FromDays(14);

    /// <summary>
    /// Gets or sets the minimum lifespan tokens must have to be pruned.
    /// By default, this value is set to 14 days and cannot be less than 10 minutes.
    /// </summary>
    public TimeSpan MinimumTokenLifespan { get; set; } = TimeSpan.FromDays(14);

    /// <summary>
    /// Gets or sets duration before the first run is executed.
    /// By default, this value is a random value between 1 and 10 minutes.
    /// </summary>
    public TimeSpan FirstRun { get; set; } = TimeSpan.FromMinutes(new Random().Next(1, 10));

    /// <summary>
    /// Gets or sets interval between consecutive.
    /// By default, this value is 1 hour.
    /// </summary>
    public TimeSpan Interval { get; set; } = TimeSpan.FromHours(1);

}
