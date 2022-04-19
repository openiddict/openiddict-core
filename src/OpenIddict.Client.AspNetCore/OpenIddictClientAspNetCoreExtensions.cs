/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using OpenIddict.Client;
using OpenIddict.Client.AspNetCore;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes extensions allowing to register the OpenIddict client services.
/// </summary>
public static class OpenIddictClientAspNetCoreExtensions
{
    /// <summary>
    /// Registers the OpenIddict client services for ASP.NET Core in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictClientAspNetCoreBuilder"/>.</returns>
    public static OpenIddictClientAspNetCoreBuilder UseAspNetCore(this OpenIddictClientBuilder builder)
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        builder.Services.AddAuthentication();

        builder.Services.TryAddScoped<OpenIddictClientAspNetCoreHandler>();

        // Register the built-in event handlers used by the OpenIddict ASP.NET Core client components.
        // Note: the order used here is not important, as the actual order is set in the options.
        builder.Services.TryAdd(OpenIddictClientAspNetCoreHandlers.DefaultHandlers.Select(descriptor => descriptor.ServiceDescriptor));

        // Register the built-in filters used by the default OpenIddict ASP.NET Core client event handlers.
        builder.Services.TryAddSingleton<RequireErrorPassthroughEnabled>();
        builder.Services.TryAddSingleton<RequireHttpRequest>();
        builder.Services.TryAddSingleton<RequireRedirectionEndpointPassthroughEnabled>();
        builder.Services.TryAddSingleton<RequireStatusCodePagesIntegrationEnabled>();

        // Register the option initializer used by the OpenIddict ASP.NET Core client integration services.
        // Note: TryAddEnumerable() is used here to ensure the initializers are only registered once.
        builder.Services.TryAddEnumerable(new[]
        {
            ServiceDescriptor.Singleton<IConfigureOptions<AuthenticationOptions>, OpenIddictClientAspNetCoreConfiguration>(),
            ServiceDescriptor.Singleton<IPostConfigureOptions<AuthenticationOptions>, OpenIddictClientAspNetCoreConfiguration>(),

            ServiceDescriptor.Singleton<IConfigureOptions<OpenIddictClientOptions>, OpenIddictClientAspNetCoreConfiguration>()
        });

        return new OpenIddictClientAspNetCoreBuilder(builder.Services);
    }

    /// <summary>
    /// Registers the OpenIddict client services for ASP.NET Core in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <param name="configuration">The configuration delegate used to configure the client services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    public static OpenIddictClientBuilder UseAspNetCore(
        this OpenIddictClientBuilder builder, Action<OpenIddictClientAspNetCoreBuilder> configuration)
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        configuration(builder.UseAspNetCore());

        return builder;
    }
}
