using Avalonia;
using Microsoft.Win32;
using System.Runtime.Versioning;

namespace OpenIddict.Sandbox.Avalonia.Client.Desktop
{
    internal static class AppBuilderExtensions
    {
        internal static AppBuilder RegisterAppUrl(this AppBuilder builder)
        { 
            if(IsWindows)
                builder.RegisterWindowsAppUrl();

            return builder;
        }

        [SupportedOSPlatformGuard("windows")]
        private static readonly bool IsWindows = OperatingSystem.IsWindows();

        
        [System.Runtime.Versioning.SupportedOSPlatform("windows")]
        internal static AppBuilder RegisterWindowsAppUrl(this AppBuilder builder)
        {
            // Create the registry entries necessary to handle URI protocol activations.
           //
           // Note: this sample creates the entry under the current user account (as it doesn't
           // require administrator rights), but the registration can also be added globally
           // in HKEY_CLASSES_ROOT (in this case, it should be added by a dedicated installer).
           //
           // Alternatively, the application can be packaged and use windows.protocol to
           // register the protocol handler/custom URI scheme with the operation system.
            using var root = Registry.CurrentUser.CreateSubKey("SOFTWARE\\Classes\\com.openiddict.sandbox.avalonia.client");
            root.SetValue(string.Empty, "URL:com.openiddict.sandbox.avalonia.client");
            root.SetValue("URL Protocol", string.Empty);

            using var command = root.CreateSubKey("shell\\open\\command");
            command.SetValue(string.Empty, string.Format("\"{0}\" \"%1\"",
#if SUPPORTS_ENVIRONMENT_PROCESS_PATH
                Environment.ProcessPath
#else
            Process.GetCurrentProcess().MainModule.FileName
#endif
            ));

            return builder;
        }
    }
}
