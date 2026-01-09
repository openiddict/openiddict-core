/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using OpenIddict.Client;
using OpenIddict.Client.SystemIntegration;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes extensions allowing to register the OpenIddict client services.
/// </summary>
public static class OpenIddictClientSystemIntegrationExtensions
{
    /// <summary>
    /// Registers the OpenIddict client system integration services in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictClientSystemIntegrationBuilder"/>.</returns>
    public static OpenIddictClientSystemIntegrationBuilder UseSystemIntegration(this OpenIddictClientBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        // Ensure the operating system version is supported.
        if (!OperatingSystem.IsAndroidVersionAtLeast(21)    && !OperatingSystem.IsIOSVersionAtLeast(12)            &&
            !OperatingSystem.IsLinux()                      && !OperatingSystem.IsMacCatalystVersionAtLeast(13, 1) &&
            !OperatingSystem.IsMacOSVersionAtLeast(10, 15)  && !OperatingSystem.IsWindowsVersionAtLeast(7))
        {
            throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0389));
        }

#if !SUPPORTS_ANDROID
        // When running on Android, iOS or Mac Catalyst, ensure the version compiled for these platforms
        // is used to prevent the generic/non-OS specific TFM from being used as launching the system
        // browser cannot be done using Process.Start() and requires using OS-specific APIs that are
        // not available on the portable version of the OpenIddict.Client.SystemIntegration package.
        if (OperatingSystem.IsAndroid())
        {
            throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0449));
        }
#endif

#if !SUPPORTS_UIKIT
        if (OperatingSystem.IsIOS() || OperatingSystem.IsMacCatalyst())
        {
            throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0449));
        }
#endif

        // Note: the OpenIddict activation handler service is deliberately registered as early as possible to
        // ensure protocol activations can be handled before another service can stop the initialization of the
        // application (e.g Dapplo.Microsoft.Extensions.Hosting.AppServices relies on an IHostedService to implement
        // single instantiation, which would prevent the OpenIddict service from handling the protocol activation
        // if the OpenIddict activation handler service was not registered before the Dapplo IHostedService).
        if (!builder.Services.Any(static descriptor =>
            descriptor.ServiceType == typeof(IHostedService) &&
            descriptor.ImplementationType == typeof(OpenIddictClientSystemIntegrationActivationHandler)))
        {
            builder.Services.Insert(0, ServiceDescriptor.Singleton<IHostedService, OpenIddictClientSystemIntegrationActivationHandler>());
        }

        // Register the services responsible for coordinating and managing authentication operations.
        builder.Services.TryAddSingleton<OpenIddictClientSystemIntegrationMarshal>();
        builder.Services.TryAddSingleton<OpenIddictClientSystemIntegrationService>();

        builder.Services.TryAddSingleton(static provider => provider.GetServices<IHostedService>()
            .OfType<OpenIddictClientSystemIntegrationHttpListener>()
            .Single());

        // Register the built-in filters used by the default OpenIddict client system integration event handlers.
        builder.Services.TryAddSingleton<RequireASWebAuthenticationSession>();
        builder.Services.TryAddSingleton<RequireAuthenticationNonce>();
        builder.Services.TryAddSingleton<RequireCustomTabsIntent>();
        builder.Services.TryAddSingleton<RequireEmbeddedWebServerEnabled>();
        builder.Services.TryAddSingleton<RequireHttpListenerContext>();
        builder.Services.TryAddSingleton<RequireInteractiveSession>();
        builder.Services.TryAddSingleton<RequirePlatformCallback>();
        builder.Services.TryAddSingleton<RequireProtocolActivation>();
        builder.Services.TryAddSingleton<RequireSystemBrowser>();
        builder.Services.TryAddSingleton<RequireWebAuthenticationBroker>();

        // Register the built-in event handlers used by the OpenIddict client system integration components.
        // Note: the order used here is not important, as the actual order is set in the options.
        builder.Services.TryAdd(OpenIddictClientSystemIntegrationHandlers.DefaultHandlers.Select(descriptor => descriptor.ServiceDescriptor));

        // Register the background services used by the OpenIddict client system integration services.
        builder.Services.AddHostedService<OpenIddictClientSystemIntegrationHttpListener>();
        builder.Services.AddHostedService<OpenIddictClientSystemIntegrationPipeListener>();

        // Register the option initializer used by the OpenIddict client system integration services.
        // Note: TryAddEnumerable() is used here to ensure the initializers are only registered once.
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IConfigureOptions<OpenIddictClientOptions>, OpenIddictClientSystemIntegrationConfiguration>());

        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IPostConfigureOptions<OpenIddictClientOptions>, OpenIddictClientSystemIntegrationConfiguration>());

        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
            IPostConfigureOptions<OpenIddictClientSystemIntegrationOptions>, OpenIddictClientSystemIntegrationConfiguration>());

        return new OpenIddictClientSystemIntegrationBuilder(builder.Services);
    }

    /// <summary>
    /// Registers the OpenIddict client system integration services in the DI container.
    /// </summary>
    /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
    /// <param name="configuration">The configuration delegate used to configure the client services.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictClientBuilder"/>.</returns>
    public static OpenIddictClientBuilder UseSystemIntegration(
        this OpenIddictClientBuilder builder, Action<OpenIddictClientSystemIntegrationBuilder> configuration)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configuration);

        configuration(builder.UseSystemIntegration());

        return builder;
    }
}
