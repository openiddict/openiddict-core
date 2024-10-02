using Avalonia;
using Avalonia.iOS;
using Avalonia.ReactiveUI;
using Microsoft.Extensions.DependencyInjection;

namespace OpenIddict.Sandbox.Avalonia.Client.iOS;

// The UIApplicationDelegate for the application. This class is responsible for launching the 
// User Interface of the application, as well as listening (and optionally responding) to 
// application events from iOS.
[Register("AppDelegate")]
#pragma warning disable CA1711 // Identifiers should not have incorrect suffix
public partial class AppDelegate : AvaloniaAppDelegate<App>
#pragma warning restore CA1711 // Identifiers should not have incorrect suffix
{
    protected override AppBuilder CreateAppBuilder()
    {
        return AppBuilder.Configure<App>(() =>
        {
            var services = new ServiceCollection();
            var app = new App();
            app.ConfigureServices(services);
            app.Provider = services.BuildServiceProvider();
            return app;
        }).UseiOS()
        .With(new iOSPlatformOptions { RenderingMode = [iOSRenderingMode.Metal] })
        ;
    }
    protected override AppBuilder CustomizeAppBuilder(AppBuilder builder)
    {
        return base.CustomizeAppBuilder(builder)
            .WithInterFont()
            .UseReactiveUI();
    }
}
