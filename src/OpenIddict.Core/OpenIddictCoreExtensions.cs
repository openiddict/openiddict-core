/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using OpenIddict.Core;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes extensions allowing to register the OpenIddict core services.
/// </summary>
public static class OpenIddictCoreExtensions
{
    /// <summary>
    /// Registers the OpenIddict core services in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictBuilder"/> instance.</returns>
    public static OpenIddictCoreBuilder AddCore(this OpenIddictBuilder builder)
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        builder.Services.AddLogging();
        builder.Services.AddMemoryCache();
        builder.Services.AddOptions();

        builder.Services.TryAddScoped(typeof(IOpenIddictApplicationCache<>), typeof(OpenIddictApplicationCache<>));
        builder.Services.TryAddScoped(typeof(IOpenIddictAuthorizationCache<>), typeof(OpenIddictAuthorizationCache<>));
        builder.Services.TryAddScoped(typeof(IOpenIddictScopeCache<>), typeof(OpenIddictScopeCache<>));
        builder.Services.TryAddScoped(typeof(IOpenIddictTokenCache<>), typeof(OpenIddictTokenCache<>));

        builder.Services.TryAddScoped(typeof(OpenIddictApplicationManager<>));
        builder.Services.TryAddScoped(typeof(OpenIddictAuthorizationManager<>));
        builder.Services.TryAddScoped(typeof(OpenIddictScopeManager<>));
        builder.Services.TryAddScoped(typeof(OpenIddictTokenManager<>));

        // Note: default factories for the untyped managers are always registered to make debugging
        // easier if no store was configured. It is expected that store implementations replace the
        // registrations with working implementation factories that use the correct entity types.
        builder.Services.TryAddScoped<IOpenIddictApplicationManager>(static provider =>
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0472)));
        builder.Services.TryAddScoped<IOpenIddictAuthorizationManager>(static provider =>
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0472)));
        builder.Services.TryAddScoped<IOpenIddictScopeManager>(static provider =>
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0472)));
        builder.Services.TryAddScoped<IOpenIddictTokenManager>(static provider =>
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0472)));

        // Note: TryAddEnumerable() is used here to ensure the initializer is registered only once.
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IPostConfigureOptions<OpenIddictCoreOptions>, OpenIddictCoreConfiguration>());

        return new OpenIddictCoreBuilder(builder.Services);
    }

    /// <summary>
    /// Registers the OpenIddict core services in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <param name="configuration">The configuration delegate used to configure the core services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictBuilder"/> instance.</returns>
    public static OpenIddictBuilder AddCore(this OpenIddictBuilder builder, Action<OpenIddictCoreBuilder> configuration)
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        configuration(builder.AddCore());

        return builder;
    }
}
