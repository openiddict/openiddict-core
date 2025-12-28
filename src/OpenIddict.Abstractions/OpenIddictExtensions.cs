/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes extensions allowing to register the OpenIddict services.
/// </summary>
public static class OpenIddictExtensions
{
    /// <summary>
    /// Provides a common entry point for registering the OpenIddict services.
    /// </summary>
    /// <param name="services">The services collection.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictBuilder"/> instance.</returns>
    public static OpenIddictBuilder AddOpenIddict(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        return new OpenIddictBuilder(services);
    }

    /// <summary>
    /// Provides a common entry point for registering the OpenIddict services.
    /// </summary>
    /// <param name="services">The services collection.</param>
    /// <param name="configuration">The configuration delegate used to register new services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddOpenIddict(this IServiceCollection services, Action<OpenIddictBuilder> configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        configuration(services.AddOpenIddict());

        return services;
    }
}
