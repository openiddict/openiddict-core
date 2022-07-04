/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.Maui.LifecycleEvents;
using OpenIddict.Client;
using OpenIddict.Client.Maui;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes extensions allowing to register the OpenIddict client services.
/// </summary>
public static class OpenIddictClientMauiExtensions
{
    /// <summary>
    /// Registers the OpenIddict client services for MAUI in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictClientMauiBuilder"/>.</returns>
    public static OpenIddictClientMauiBuilder UseMaui(this OpenIddictClientBuilder builder)
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        // Note: LifecycleEventService is typically registered by explicitly calling builder.ConfigureLifecycleEvents()
        // from MauiProgram.cs. To ensure the MAUI event handlers required by OpenIddict for the callbacks to be handled
        // successfully are always registered even if this method is not called, the event service is always added here.
        builder.Services.TryAddSingleton<ILifecycleEventService>(provider =>
            new LifecycleEventService(registrations: provider.GetServices<LifecycleEventRegistration>()));

        // Register the OpenIddict MAUI authenticator.
        builder.Services.TryAddSingleton<OpenIddictClientMauiAuthenticator>();

        // Register the built-in event handlers used by the OpenIddict MAUI client components.
        // Note: the order used here is not important, as the actual order is set in the options.
        builder.Services.TryAdd(OpenIddictClientMauiHandlers.DefaultHandlers.Select(descriptor => descriptor.ServiceDescriptor));

        // Register the built-in filters used by the default OpenIddict MAUI client event handlers.
        builder.Services.TryAddSingleton<RequireMauiApplication>();

        // Register the option initializer and the lifecycle event registration used by the OpenIddict MAUI client integration services.
        // Note: TryAddEnumerable() is used here to ensure the initializers/lifecycle event registrations are only registered once.
        builder.Services.TryAddEnumerable(new[]
        {
            ServiceDescriptor.Singleton<IConfigureOptions<OpenIddictClientOptions>, OpenIddictClientMauiConfiguration>(),

            ServiceDescriptor.Singleton<LifecycleEventRegistration, OpenIddictClientMauiEventRegistration>()
        });

        return new OpenIddictClientMauiBuilder(builder.Services);
    }

    /// <summary>
    /// Registers the OpenIddict client services for MAUI in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <param name="configuration">The configuration delegate used to configure the client services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    public static OpenIddictClientBuilder UseMaui(
        this OpenIddictClientBuilder builder, Action<OpenIddictClientMauiBuilder> configuration)
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        configuration(builder.UseMaui());

        return builder;
    }
}
