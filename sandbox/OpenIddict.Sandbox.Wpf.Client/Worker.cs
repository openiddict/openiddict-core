using System.Diagnostics;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Win32;

namespace OpenIddict.Sandbox.Wpf.Client;

public class Worker : IHostedService
{
    private readonly IServiceProvider _provider;

    public Worker(IServiceProvider provider)
        => _provider = provider;

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        using var scope = _provider.CreateScope();

        var context = scope.ServiceProvider.GetRequiredService<DbContext>();
        await context.Database.EnsureCreatedAsync(cancellationToken);

        // Create the registry entries necessary to handle URI protocol activations.
        //
        // Note: this sample creates the entry under the current user account (as it doesn't
        // require administrator rights), but the registration can also be added globally
        // in HKEY_CLASSES_ROOT (in this case, it should be added by a dedicated installer).
        //
        // Alternatively, the application can be packaged and use windows.protocol to
        // register the protocol handler/custom URI scheme with the operation system.
        using var root = Registry.CurrentUser.CreateSubKey("SOFTWARE\\Classes\\com.openiddict.sandbox.wpf.client");
        root.SetValue(string.Empty, "URL:com.openiddict.sandbox.wpf.client");
        root.SetValue("URL Protocol", string.Empty);

        using var command = root.CreateSubKey("shell\\open\\command");
        command.SetValue(string.Empty, string.Format("\"{0}\" \"%1\"",
#if SUPPORTS_ENVIRONMENT_PROCESS_PATH
            Environment.ProcessPath
#else
            Process.GetCurrentProcess().MainModule.FileName
#endif
        ));
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
