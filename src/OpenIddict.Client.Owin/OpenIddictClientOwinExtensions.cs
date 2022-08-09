/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using OpenIddict.Client;
using OpenIddict.Client.Owin;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes extensions allowing to register the OpenIddict client services.
/// </summary>
public static class OpenIddictClientOwinExtensions
{
    /// <summary>
    /// Registers the OpenIddict client services for OWIN in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictClientOwinBuilder"/>.</returns>
    public static OpenIddictClientOwinBuilder UseOwin(this OpenIddictClientBuilder builder)
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        builder.Services.AddWebEncoders();

        // Note: unlike regular OWIN middleware, the OpenIddict client middleware is registered
        // as a scoped service in the DI container. This allows containers that support middleware
        // resolution (like Autofac) to use it without requiring additional configuration.
        builder.Services.TryAddScoped<OpenIddictClientOwinMiddleware>();

        // Register the built-in event handlers used by the OpenIddict OWIN client components.
        // Note: the order used here is not important, as the actual order is set in the options.
        builder.Services.TryAdd(OpenIddictClientOwinHandlers.DefaultHandlers.Select(descriptor => descriptor.ServiceDescriptor));

        // Register the built-in filters used by the default OpenIddict OWIN client event handlers.
        builder.Services.TryAddSingleton<RequireErrorPassthroughEnabled>();
        builder.Services.TryAddSingleton<RequireOwinRequest>();
        builder.Services.TryAddSingleton<RequirePostLogoutRedirectionEndpointPassthroughEnabled>();
        builder.Services.TryAddSingleton<RequireRedirectionEndpointPassthroughEnabled>();

        // Register the option initializer used by the OpenIddict OWIN client integration services.
        // Note: TryAddEnumerable() is used here to ensure the initializers are only registered once.
        builder.Services.TryAddEnumerable(new[]
        {
            ServiceDescriptor.Singleton<IConfigureOptions<OpenIddictClientOptions>, OpenIddictClientOwinConfiguration>(),
            ServiceDescriptor.Singleton<IPostConfigureOptions<OpenIddictClientOwinOptions>, OpenIddictClientOwinConfiguration>()
        });

        return new OpenIddictClientOwinBuilder(builder.Services);
    }

    /// <summary>
    /// Registers the OpenIddict client services for OWIN in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <param name="configuration">The configuration delegate used to configure the client services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    public static OpenIddictClientBuilder UseOwin(
        this OpenIddictClientBuilder builder, Action<OpenIddictClientOwinBuilder> configuration)
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        configuration(builder.UseOwin());

        return builder;
    }
}
