/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using OpenIddict.Pruning.BackgroundService;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes the necessary methods required to configure the OpenIddict Pruning using BackgroundService.
/// </summary>
public sealed class OpenIddictPruningBuilder
{
    /// <summary>
    /// Initializes a new instance of <see cref="OpenIddictPruningBuilder"/>.
    /// </summary>
    /// <param name="services">The services collection.</param>
    public OpenIddictPruningBuilder(IServiceCollection services)
        => Services = services ?? throw new ArgumentNullException(nameof(services));

    /// <summary>
    /// Gets the services collection.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public IServiceCollection Services { get; }

    /// <summary>
    /// Amends the default OpenIddict Pruning using BackgroundService.
    /// </summary>
    /// <param name="configuration">The delegate used to configure the OpenIddict options.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictPruningBuilder"/> instance.</returns>
    public OpenIddictPruningBuilder Configure(Action<OpenIddictPruningOptions> configuration)
    {
        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        Services.Configure(configuration);

        return this;
    }

    /// <summary>
    /// Disables authorizations pruning.
    /// </summary>
    /// <returns>The <see cref="OpenIddictPruningBuilder"/> instance.</returns>
    public OpenIddictPruningBuilder DisableAuthorizationPruning()
        => Configure(options => options.DisableAuthorizationPruning = true);

    /// <summary>
    /// Disables tokens pruning.
    /// </summary>
    /// <returns>The <see cref="OpenIddictPruningBuilder"/> instance.</returns>
    public OpenIddictPruningBuilder DisableTokenPruning()
        => Configure(options => options.DisableTokenPruning = true);

    /// <summary>
    /// Sets the minimum lifespan authorizations must have to be pruned.
    /// </summary>
    /// <param name="lifespan">The minimum lifespan authorizations must have to be pruned.</param>
    /// <returns>The <see cref="OpenIddictPruningBuilder"/> instance.</returns>
    public OpenIddictPruningBuilder SetMinimumAuthorizationLifespan(TimeSpan lifespan)
    {
        if (lifespan < TimeSpan.FromMinutes(10))
        {
            throw new ArgumentOutOfRangeException(nameof(lifespan), SR.GetResourceString(SR.ID0280));
        }

        return Configure(options => options.MinimumAuthorizationLifespan = lifespan);
    }

    /// <summary>
    /// Sets the minimum lifespan tokens must have to be pruned.
    /// </summary>
    /// <param name="lifespan">The minimum lifespan tokens must have to be pruned.</param>
    /// <returns>The <see cref="OpenIddictPruningBuilder"/> instance.</returns>
    public OpenIddictPruningBuilder SetMinimumTokenLifespan(TimeSpan lifespan)
    {
        if (lifespan < TimeSpan.FromMinutes(10))
        {
            throw new ArgumentOutOfRangeException(nameof(lifespan), SR.GetResourceString(SR.ID0280));
        }

        return Configure(options => options.MinimumTokenLifespan = lifespan);
    }

    /// <summary>
    /// Sets the delay before executing for the first time.
    /// </summary>
    /// <param name="delay">The delay before executing for the first time.</param>
    /// <returns>The <see cref="OpenIddictPruningBuilder"/> instance.</returns>
    public OpenIddictPruningBuilder SetFirstRun(TimeSpan delay)
       => Configure(options => options.FirstRun = delay);

    /// <summary>
    /// Sets the interval between consecutive runs.
    /// </summary>
    /// <param name="interval">The interval between consecutive runs.</param>
    /// <returns>The <see cref="OpenIddictPruningBuilder"/> instance.</returns>
    public OpenIddictPruningBuilder SetInterval(TimeSpan interval)
       => Configure(options => options.Interval = interval);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals(object? obj) => base.Equals(obj);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => base.GetHashCode();

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override string? ToString() => base.ToString();
}
