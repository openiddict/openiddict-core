/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics;
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
    /// <returns>The <see cref="OpenIddictClientAspNetCoreBuilder"/> instance.</returns>
    public static OpenIddictClientAspNetCoreBuilder UseAspNetCore(this OpenIddictClientBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Services.AddAuthentication();

        // Decorate the authentication scheme provider to resolve the provider names
        // of dynamic client registrations as forwarded authentication schemes.
        DecorateAuthenticationSchemeProvider(builder.Services);

        builder.Services.TryAddScoped<OpenIddictClientAspNetCoreForwarder>();
        builder.Services.TryAddScoped<OpenIddictClientAspNetCoreHandler>();

        // Register the built-in event handlers used by the OpenIddict ASP.NET Core client components.
        // Note: the order used here is not important, as the actual order is set in the options.
        builder.Services.TryAdd(OpenIddictClientAspNetCoreHandlers.DefaultHandlers.Select(descriptor => descriptor.ServiceDescriptor));

        // Register the built-in filters used by the default OpenIddict ASP.NET Core client event handlers.
        builder.Services.TryAddSingleton<RequireErrorPassthroughEnabled>();
        builder.Services.TryAddSingleton<RequireHttpRequest>();
        builder.Services.TryAddSingleton<RequirePostLogoutRedirectionEndpointPassthroughEnabled>();
        builder.Services.TryAddSingleton<RequireRedirectionEndpointPassthroughEnabled>();
        builder.Services.TryAddSingleton<RequireStatusCodePagesIntegrationEnabled>();
        builder.Services.TryAddSingleton<RequireTransportSecurityRequirementEnabled>();

        // Register the option initializer used by the OpenIddict ASP.NET Core client integration services.
        // Note: TryAddEnumerable() is used here to ensure the initializers are only registered once.
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IConfigureOptions<AuthenticationOptions>, OpenIddictClientAspNetCoreConfiguration>());

        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IConfigureOptions<OpenIddictClientOptions>, OpenIddictClientAspNetCoreConfiguration>());

        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IPostConfigureOptions<AuthenticationOptions>, OpenIddictClientAspNetCoreConfiguration>());

        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IPostConfigureOptions<OpenIddictClientAspNetCoreOptions>, OpenIddictClientAspNetCoreConfiguration>());

        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IValidateOptions<AuthenticationOptions>, OpenIddictClientAspNetCoreConfiguration>());

        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IValidateOptions<OpenIddictClientAspNetCoreOptions>, OpenIddictClientAspNetCoreConfiguration>());

        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IOptionsChangeTokenSource<OpenIddictClientAspNetCoreOptions>, OpenIddictClientAspNetCoreConfiguration>());

        return new OpenIddictClientAspNetCoreBuilder(builder.Services);

        static void DecorateAuthenticationSchemeProvider(IServiceCollection services)
        {
            var descriptor = services.LastOrDefault(static descriptor =>
                descriptor.ServiceType == typeof(IAuthenticationSchemeProvider) && !descriptor.IsKeyedService);

            if (descriptor is null || descriptor.ImplementationFactory?.Target is SchemeProviderFactory)
            {
                return;
            }

            services[services.IndexOf(descriptor)] = ServiceDescriptor.Describe(
                serviceType: typeof(IAuthenticationSchemeProvider),
                implementationFactory: new SchemeProviderFactory(descriptor).Create,
                lifetime: descriptor.Lifetime);
        }
    }

    /// <summary>
    /// Creates <see cref="OpenIddictClientAspNetCoreSchemeProvider"/> instances wrapping the original scheme provider.
    /// </summary>
    private sealed class SchemeProviderFactory(ServiceDescriptor descriptor)
    {
        public object Create(IServiceProvider provider) => new OpenIddictClientAspNetCoreSchemeProvider(
            inner: (IAuthenticationSchemeProvider) (descriptor switch
            {
                { ImplementationInstance: object instance } => instance,
                { ImplementationFactory: Func<IServiceProvider, object> factory } => factory(provider),
                { ImplementationType: Type type } => ActivatorUtilities.CreateInstance(provider, type),

                _ => throw new UnreachableException()
            }),
            provider: provider);
    }

    /// <summary>
    /// Registers the OpenIddict client services for ASP.NET Core in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <param name="configuration">The configuration delegate used to configure the client services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictClientBuilder"/> instance.</returns>
    public static OpenIddictClientBuilder UseAspNetCore(
        this OpenIddictClientBuilder builder, Action<OpenIddictClientAspNetCoreBuilder> configuration)
    {
        ArgumentNullException.ThrowIfNull(builder);

        ArgumentNullException.ThrowIfNull(configuration);

        configuration(builder.UseAspNetCore());

        return builder;
    }
}
