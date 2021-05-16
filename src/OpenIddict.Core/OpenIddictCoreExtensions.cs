﻿/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.Abstractions;
using OpenIddict.Core;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace Microsoft.Extensions.DependencyInjection
{
    using Microsoft.Extensions.Options;

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
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public static OpenIddictCoreBuilder AddCore(this OpenIddictBuilder builder)
        {
            if (builder is null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            builder.Services.AddLogging();
            builder.Services.AddMemoryCache();
            builder.Services.AddOptions();

            builder.Services.TryAddScoped(typeof(OpenIddictApplicationManager<>));
            builder.Services.TryAddScoped(typeof(OpenIddictAuthorizationManager<>));
            builder.Services.TryAddScoped(typeof(OpenIddictScopeManager<>));
            builder.Services.TryAddScoped(typeof(OpenIddictTokenManager<>));

            builder.Services.TryAddScoped(typeof(IOpenIddictApplicationCache<>), typeof(OpenIddictApplicationCache<>));
            builder.Services.TryAddScoped(typeof(IOpenIddictAuthorizationCache<>), typeof(OpenIddictAuthorizationCache<>));
            builder.Services.TryAddScoped(typeof(IOpenIddictScopeCache<>), typeof(OpenIddictScopeCache<>));
            builder.Services.TryAddScoped(typeof(IOpenIddictTokenCache<>), typeof(OpenIddictTokenCache<>));

            builder.Services.TryAddScoped<IOpenIddictApplicationStoreResolver, OpenIddictApplicationStoreResolver>();
            builder.Services.TryAddScoped<IOpenIddictAuthorizationStoreResolver, OpenIddictAuthorizationStoreResolver>();
            builder.Services.TryAddScoped<IOpenIddictScopeStoreResolver, OpenIddictScopeStoreResolver>();
            builder.Services.TryAddScoped<IOpenIddictTokenStoreResolver, OpenIddictTokenStoreResolver>();

            builder.Services.TryAddSingleton<IOpenIddictClientSecretHasher, OpenIddictClientSecretHasher>();

            builder.Services.TryAddScoped(provider =>
            {
                var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictCoreOptions>>().CurrentValue;
                if (options.DefaultApplicationType is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0273));
                }

                return (IOpenIddictApplicationManager) provider.GetRequiredService(
                    typeof(OpenIddictApplicationManager<>).MakeGenericType(options.DefaultApplicationType));
            });

            builder.Services.TryAddScoped(provider =>
            {
                var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictCoreOptions>>().CurrentValue;
                if (options.DefaultAuthorizationType is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0274));
                }

                return (IOpenIddictAuthorizationManager) provider.GetRequiredService(
                    typeof(OpenIddictAuthorizationManager<>).MakeGenericType(options.DefaultAuthorizationType));
            });

            builder.Services.TryAddScoped(provider =>
            {
                var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictCoreOptions>>().CurrentValue;
                if (options.DefaultScopeType is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0275));
                }

                return (IOpenIddictScopeManager) provider.GetRequiredService(
                    typeof(OpenIddictScopeManager<>).MakeGenericType(options.DefaultScopeType));
            });

            builder.Services.TryAddScoped(provider =>
            {
                var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictCoreOptions>>().CurrentValue;
                if (options.DefaultTokenType is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0276));
                }

                return (IOpenIddictTokenManager) provider.GetRequiredService(
                    typeof(OpenIddictTokenManager<>).MakeGenericType(options.DefaultTokenType));
            });

            return new OpenIddictCoreBuilder(builder.Services);
        }

        /// <summary>
        /// Registers the OpenIddict core services in the DI container.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <param name="configuration">The configuration delegate used to configure the core services.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
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
}