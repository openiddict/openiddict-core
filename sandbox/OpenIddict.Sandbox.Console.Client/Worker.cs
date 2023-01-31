using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Win32;

namespace OpenIddict.Sandbox.Console.Client;

public class Worker : IHostedService
{
    private readonly IServiceProvider _provider;

    public Worker(IServiceProvider provider)
        => _provider = provider;

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        using var scope = _provider.CreateScope();

        var context = scope.ServiceProvider.GetRequiredService<DbContext>();
        await context.Database.EnsureCreatedAsync();

        RegistryKey? root = null;

        // Create the registry entries necessary to handle URI protocol activations.
        // Note: the application MUST be run once as an administrator for this to work,
        // so this should typically be done by a dedicated installer or a setup script.
        // Alternatively, the application can be packaged and use windows.protocol to
        // register the protocol handler/custom URI scheme with the operation system.
        try
        {
            root = Registry.ClassesRoot.OpenSubKey("openiddict-sandbox-console-client");

            if (root is null)
            {
                root = Registry.ClassesRoot.CreateSubKey("openiddict-sandbox-console-client");
                root.SetValue(string.Empty, "URL:openiddict-sandbox-console-client");
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
        }

        finally
        {
            root?.Dispose();
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
