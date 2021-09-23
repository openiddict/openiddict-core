/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.EntityFramework;
using OpenIddict.EntityFramework.Models;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes extensions allowing to register the OpenIddict Entity Framework 6.x services.
/// </summary>
public static class OpenIddictEntityFrameworkExtensions
{
    /// <summary>
    /// Registers the Entity Framework 6.x stores services in the DI container and
    /// configures OpenIddict to use the Entity Framework 6.x entities by default.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictEntityFrameworkBuilder"/>.</returns>
    public static OpenIddictEntityFrameworkBuilder UseEntityFramework(this OpenIddictCoreBuilder builder)
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        // Since Entity Framework 6.x may be used with databases performing case-insensitive
        // or culture-sensitive comparisons, ensure the additional filtering logic is enforced
        // in case case-sensitive stores were registered before this extension was called.
        builder.Configure(options => options.DisableAdditionalFiltering = false);

        builder.SetDefaultApplicationEntity<OpenIddictEntityFrameworkApplication>()
               .SetDefaultAuthorizationEntity<OpenIddictEntityFrameworkAuthorization>()
               .SetDefaultScopeEntity<OpenIddictEntityFrameworkScope>()
               .SetDefaultTokenEntity<OpenIddictEntityFrameworkToken>();

        builder.ReplaceApplicationStoreResolver<OpenIddictEntityFrameworkApplicationStoreResolver>()
               .ReplaceAuthorizationStoreResolver<OpenIddictEntityFrameworkAuthorizationStoreResolver>()
               .ReplaceScopeStoreResolver<OpenIddictEntityFrameworkScopeStoreResolver>()
               .ReplaceTokenStoreResolver<OpenIddictEntityFrameworkTokenStoreResolver>();

        builder.Services.TryAddSingleton<OpenIddictEntityFrameworkApplicationStoreResolver.TypeResolutionCache>();
        builder.Services.TryAddSingleton<OpenIddictEntityFrameworkAuthorizationStoreResolver.TypeResolutionCache>();
        builder.Services.TryAddSingleton<OpenIddictEntityFrameworkScopeStoreResolver.TypeResolutionCache>();
        builder.Services.TryAddSingleton<OpenIddictEntityFrameworkTokenStoreResolver.TypeResolutionCache>();

        builder.Services.TryAddScoped(typeof(OpenIddictEntityFrameworkApplicationStore<,,,,>));
        builder.Services.TryAddScoped(typeof(OpenIddictEntityFrameworkAuthorizationStore<,,,,>));
        builder.Services.TryAddScoped(typeof(OpenIddictEntityFrameworkScopeStore<,,>));
        builder.Services.TryAddScoped(typeof(OpenIddictEntityFrameworkTokenStore<,,,,>));

        return new OpenIddictEntityFrameworkBuilder(builder.Services);
    }

    /// <summary>
    /// Registers the Entity Framework 6.x stores services in the DI container and
    /// configures OpenIddict to use the Entity Framework 6.x entities by default.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <param name="configuration">The configuration delegate used to configure the Entity Framework 6.x services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictCoreBuilder"/>.</returns>
    public static OpenIddictCoreBuilder UseEntityFramework(
        this OpenIddictCoreBuilder builder, Action<OpenIddictEntityFrameworkBuilder> configuration)
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        configuration(builder.UseEntityFramework());

        return builder;
    }
}
