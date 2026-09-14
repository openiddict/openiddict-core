/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using OpenIddict.Client.Saml.AspNetCore;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes extensions allowing to register the OpenIddict SAML service provider ASP.NET Core integration services.
/// </summary>
public static class OpenIddictClientSamlAspNetCoreExtensions
{
    /// <summary>
    /// Registers the OpenIddict SAML service provider ASP.NET Core integration services in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictClientSamlAspNetCoreBuilder"/> instance.</returns>
    public static OpenIddictClientSamlAspNetCoreBuilder UseAspNetCore(this OpenIddictClientSamlBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Services.AddAuthentication();
        builder.Services.AddDataProtection();

        // Decorate the authentication scheme provider to resolve the provider names
        // of the SAML registrations as forwarded authentication schemes.
        DecorateAuthenticationSchemeProvider(builder.Services);

        builder.Services.TryAddScoped<OpenIddictClientSamlAspNetCoreForwarder>();
        builder.Services.TryAddScoped<OpenIddictClientSamlAspNetCoreHandler>();
        builder.Services.TryAddSingleton<OpenIddictClientSamlAspNetCoreStateProtector>();

        // Note: TryAddEnumerable() is used here to ensure the initializers are only registered once.
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IConfigureOptions<AuthenticationOptions>, OpenIddictClientSamlAspNetCoreConfiguration>());

        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IValidateOptions<OpenIddictClientSamlAspNetCoreOptions>, OpenIddictClientSamlAspNetCoreConfiguration>());

        return new OpenIddictClientSamlAspNetCoreBuilder(builder.Services);

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
    /// Registers the OpenIddict SAML service provider ASP.NET Core integration services in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <param name="configuration">The configuration delegate used to configure the SAML ASP.NET Core services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictClientSamlBuilder"/> instance.</returns>
    public static OpenIddictClientSamlBuilder UseAspNetCore(
        this OpenIddictClientSamlBuilder builder, Action<OpenIddictClientSamlAspNetCoreBuilder> configuration)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configuration);

        configuration(builder.UseAspNetCore());

        return builder;
    }

    /// <summary>
    /// Creates <see cref="OpenIddictClientSamlAspNetCoreSchemeProvider"/> instances wrapping the original scheme provider.
    /// </summary>
    private sealed class SchemeProviderFactory(ServiceDescriptor descriptor)
    {
        public object Create(IServiceProvider provider) => new OpenIddictClientSamlAspNetCoreSchemeProvider(
            inner: (IAuthenticationSchemeProvider) (descriptor switch
            {
                { ImplementationInstance: object instance } => instance,
                { ImplementationFactory: Func<IServiceProvider, object> factory } => factory(provider),
                { ImplementationType: Type type } => ActivatorUtilities.CreateInstance(provider, type),

                _ => throw new UnreachableException()
            }),
            provider: provider);
    }
}
