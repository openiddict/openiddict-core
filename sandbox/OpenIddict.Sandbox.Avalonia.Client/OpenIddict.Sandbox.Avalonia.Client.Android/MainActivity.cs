using Android.App;
using Android.Content.PM;
using Android.OS;
using Avalonia;
using Avalonia.Android;
using Avalonia.ReactiveUI;
using Java.Security;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Client.SystemIntegration;
using System;
using Intent = Android.Content.Intent;

namespace OpenIddict.Sandbox.Avalonia.Client.Android;

[Activity(
    Label = "OpenIddict.Sandbox.Avalonia.Client.Android",
    Theme = "@style/MyTheme.NoActionBar",
    Icon = "@drawable/icon",
    MainLauncher = true,
    // LauchMode.SingleTask so that the activity is not recreated
    LaunchMode=LaunchMode.SingleTask,
    ConfigurationChanges = ConfigChanges.Orientation | ConfigChanges.ScreenSize | ConfigChanges.UiMode)]
// Intent filter for custom URI scheme
[IntentFilter(new[] { Intent.ActionView },
    Categories = new[] { Intent.CategoryDefault, Intent.CategoryBrowsable },
    DataScheme = "com.openiddict.sandbox.avalonia.client")]
public class MainActivity : AvaloniaMainActivity<App>
{
    protected override AppBuilder CreateAppBuilder()
    {
        return AppBuilder.Configure<App>(() =>
        {
            var services = new ServiceCollection();
            var app = new App();
            app.ConfigureServices(services);
            var provider = services.BuildServiceProvider();
            app.Provider = provider;
            this.Provider = provider;

            return app;
        }).UseAndroid();
    }

    public IServiceProvider? Provider { get; set; }

    protected override AppBuilder CustomizeAppBuilder(AppBuilder builder)
    {
        return base.CustomizeAppBuilder(builder)
            .WithInterFont()
            .UseReactiveUI();
    }

    protected override async void OnNewIntent(Intent? intent)
    {
        base.OnNewIntent(intent);

        // Handle the custom URL scheme
        if (intent?.Data is not null && Provider is not null)
        {
            var scheme = intent?.Data?.Scheme;
            await Provider.GetRequiredService<OpenIddictClientSystemIntegrationService>().HandleCustomTabsIntentAsync(intent!);
        }
    }
}
