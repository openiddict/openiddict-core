using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Sandbox.Avalonia.Client.OpenId;
using OpenIddict.Sandbox.Avalonia.Client.ViewModels;
using OpenIddict.Sandbox.Avalonia.Client.Views;

namespace OpenIddict.Sandbox.Avalonia.Client;

public partial class App : Application
{
    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public IServiceProvider? Provider { get; set; }

    public void ConfigureServices(IServiceCollection services)
    {
        services.AddAuth();


        services.AddTransient<MainViewModel>();
    }

    public override void OnFrameworkInitializationCompleted()
    {
        var provider = Provider;

        if(provider is null)
            throw new InvalidOperationException("DI initialization failed - provider is null");

        using var s = provider.CreateScope();

        // emulate maui behavior:
        provider.InitializeMauiInitializeServices();

        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var window = new MainWindow();
            window.DataContext = provider.GetRequiredService<MainViewModel>();
            desktop.MainWindow = window;

            // emulate MAUI behavior
            provider.InitializeMauiInitializeScopedService();
        }
        else if (ApplicationLifetime is ISingleViewApplicationLifetime singleViewPlatform)
        {
            var window = new MainView();
            window.DataContext = provider.GetRequiredService<MainViewModel>();
            singleViewPlatform.MainView = window;

            // emulate MAUI behavior
            provider.InitializeMauiInitializeScopedService();
        }



        base.OnFrameworkInitializationCompleted();
    }

}
