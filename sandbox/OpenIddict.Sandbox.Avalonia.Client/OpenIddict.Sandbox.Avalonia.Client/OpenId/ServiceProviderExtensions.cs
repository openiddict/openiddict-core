using Microsoft.Extensions.DependencyInjection;
using Microsoft.Maui.Hosting;
using System;

namespace OpenIddict.Sandbox.Avalonia.Client.OpenId
{
    public static class ServiceProviderExtensions
    {
        public static void InitializeMauiInitializeServices(this IServiceProvider provider)
        {
            var initServices = provider.GetServices<IMauiInitializeService>();
            foreach (var service in initServices)
            {
                service.Initialize(provider);
            }
        }

        public static void InitializeMauiInitializeScopedService(this IServiceProvider provider)
        {
            // emulate maui behavior:
            using var scope = provider.CreateScope();

            var initServices = scope.ServiceProvider.GetServices<IMauiInitializeScopedService>();
            foreach (var service in initServices)
            {
                service.Initialize(scope.ServiceProvider);
            }
        }
    }
}
