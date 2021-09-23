/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Linq;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.Validation;
using static OpenIddict.Validation.OpenIddictValidationHandlerFilters;
using static OpenIddict.Validation.OpenIddictValidationHandlers;

namespace Microsoft.Extensions.DependencyInjection;

using Microsoft.Extensions.Options;

/// <summary>
/// Exposes extensions allowing to register the OpenIddict validation services.
/// </summary>
public static class OpenIddictValidationExtensions
{
    /// <summary>
    /// Registers the OpenIddict token validation services in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
    public static OpenIddictValidationBuilder AddValidation(this OpenIddictBuilder builder)
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        builder.Services.AddLogging();
        builder.Services.AddOptions();

        builder.Services.TryAddSingleton<OpenIddictValidationService>();
        builder.Services.TryAddScoped<IOpenIddictValidationDispatcher, OpenIddictValidationDispatcher>();
        builder.Services.TryAddScoped<IOpenIddictValidationFactory, OpenIddictValidationFactory>();

        // Register the built-in validation event handlers used by the OpenIddict validation components.
        // Note: the order used here is not important, as the actual order is set in the options.
        builder.Services.TryAdd(DefaultHandlers.Select(descriptor => descriptor.ServiceDescriptor));

        // Register the built-in filters used by the default OpenIddict validation event handlers.
        builder.Services.TryAddSingleton<RequireAccessTokenValidated>();
        builder.Services.TryAddSingleton<RequireAuthorizationEntryValidationEnabled>();
        builder.Services.TryAddSingleton<RequireLocalValidation>();
        builder.Services.TryAddSingleton<RequireTokenEntryValidationEnabled>();
        builder.Services.TryAddSingleton<RequireIntrospectionValidation>();

        // Note: TryAddEnumerable() is used here to ensure the initializer is registered only once.
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IPostConfigureOptions<OpenIddictValidationOptions>, OpenIddictValidationConfiguration>());

        return new OpenIddictValidationBuilder(builder.Services);
    }

    /// <summary>
    /// Registers the OpenIddict token validation services in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <param name="configuration">The configuration delegate used to configure the validation services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
    public static OpenIddictBuilder AddValidation(
        this OpenIddictBuilder builder,
        Action<OpenIddictValidationBuilder> configuration)
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        configuration(builder.AddValidation());

        return builder;
    }
}
