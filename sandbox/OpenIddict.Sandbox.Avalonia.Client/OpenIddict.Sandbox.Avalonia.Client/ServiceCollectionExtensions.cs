using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Sandbox.Avalonia.Client.ViewModels;
using OpenIddict.Sandbox.Avalonia.Client.Views;

namespace OpenIddict.Sandbox.Avalonia.Client;

public static class ServiceCollectionExtensions
{

    public static IServiceCollection AddApp(this IServiceCollection services)
    {

        return services
            .AddTransient<MainViewModel>();
    }
}