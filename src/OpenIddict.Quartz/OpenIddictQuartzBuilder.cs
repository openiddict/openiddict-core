/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using OpenIddict.Quartz;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes the necessary methods required to configure the OpenIddict Quartz.NET integration.
/// </summary>
public class OpenIddictQuartzBuilder
{
    /// <summary>
    /// Initializes a new instance of <see cref="OpenIddictQuartzBuilder"/>.
    /// </summary>
    /// <param name="services">The services collection.</param>
    public OpenIddictQuartzBuilder(IServiceCollection services!!)
        => Services = services;

    /// <summary>
    /// Gets the services collection.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public IServiceCollection Services { get; }

    /// <summary>
    /// Amends the default OpenIddict Quartz.NET configuration.
    /// </summary>
    /// <param name="configuration">The delegate used to configure the OpenIddict options.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictQuartzBuilder"/>.</returns>
    public OpenIddictQuartzBuilder Configure(Action<OpenIddictQuartzOptions> configuration!!)
    {
        Services.Configure(configuration);

        return this;
    }

    /// <summary>
    /// Disables authorizations pruning.
    /// </summary>
    /// <returns>The <see cref="OpenIddictQuartzBuilder"/>.</returns>
    public OpenIddictQuartzBuilder DisableAuthorizationPruning()
        => Configure(options => options.DisableAuthorizationPruning = true);

    /// <summary>
    /// Disables tokens pruning.
    /// </summary>
    /// <returns>The <see cref="OpenIddictQuartzBuilder"/>.</returns>
    public OpenIddictQuartzBuilder DisableTokenPruning()
        => Configure(options => options.DisableTokenPruning = true);

    /// <summary>
    /// Sets the number of times a failed Quartz.NET job can be retried.
    /// </summary>
    /// <param name="count">The number of times a failed Quartz.NET job can be retried.</param>
    /// <returns>The <see cref="OpenIddictQuartzBuilder"/>.</returns>
    public OpenIddictQuartzBuilder SetMaximumRefireCount(int count)
    {
        if (count < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(count), SR.GetResourceString(SR.ID0279));
        }

        return Configure(options => options.MaximumRefireCount = count);
    }

    /// <summary>
    /// Sets the minimum lifespan authorizations must have to be pruned.
    /// </summary>
    /// <param name="lifespan">The minimum lifespan authorizations must have to be pruned.</param>
    /// <returns>The <see cref="OpenIddictQuartzBuilder"/>.</returns>
    public OpenIddictQuartzBuilder SetMinimumAuthorizationLifespan(TimeSpan lifespan)
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
    /// <returns>The <see cref="OpenIddictQuartzBuilder"/>.</returns>
    public OpenIddictQuartzBuilder SetMinimumTokenLifespan(TimeSpan lifespan)
    {
        if (lifespan < TimeSpan.FromMinutes(10))
        {
            throw new ArgumentOutOfRangeException(nameof(lifespan), SR.GetResourceString(SR.ID0280));
        }

        return Configure(options => options.MinimumTokenLifespan = lifespan);
    }

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
