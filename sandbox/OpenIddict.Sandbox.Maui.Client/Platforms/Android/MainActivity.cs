using Android.App;
using Android.Content.PM;
using OpenIddict.Client.SystemIntegration;
using Intent = Android.Content.Intent;

namespace OpenIddict.Sandbox.Maui.Client
{
    [Activity(Theme = "@style/Maui.SplashTheme", MainLauncher = true, 
        LaunchMode = LaunchMode.SingleTop, 
        ConfigurationChanges = ConfigChanges.ScreenSize | ConfigChanges.Orientation | ConfigChanges.UiMode | ConfigChanges.ScreenLayout | ConfigChanges.SmallestScreenSize | ConfigChanges.Density)]
    // Intent filter for custom URI scheme
    [IntentFilter(new[] { Intent.ActionView },
        Categories = new[] { Intent.CategoryDefault, Intent.CategoryBrowsable },
        DataScheme = "com.openiddict.sandbox.maui.client")]
    public class MainActivity : MauiAppCompatActivity
    {

        protected override async void OnNewIntent(Intent? intent)
        {
            base.OnNewIntent(intent);

            // Handle the custom URL scheme
            if (intent?.Data is not null && 
                IPlatformApplication.Current?.Services is IServiceProvider provider)
            {
                var scheme = intent?.Data?.Scheme;
                await provider.GetRequiredService<OpenIddictClientSystemIntegrationService>().HandleCustomTabsIntentAsync(intent!);
            }
        }
    }
}
