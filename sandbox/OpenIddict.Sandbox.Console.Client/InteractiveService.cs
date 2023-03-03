using Microsoft.Extensions.Hosting;
using OpenIddict.Client;
using Spectre.Console;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Abstractions.OpenIddictExceptions;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;

#if !SUPPORTS_HOST_APPLICATION_LIFETIME
using IHostApplicationLifetime = Microsoft.Extensions.Hosting.IApplicationLifetime;
#endif

namespace OpenIddict.Sandbox.Console.Client;

public class InteractiveService : BackgroundService
{
    private readonly IHostApplicationLifetime _lifetime;
    private readonly OpenIddictClientService _service;

    public InteractiveService(
        IHostApplicationLifetime lifetime,
        OpenIddictClientService service)
    {
        _lifetime = lifetime;
        _service = service;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Wait for the host to confirm that the application has started.
        var source = new TaskCompletionSource<bool>();
        using (_lifetime.ApplicationStarted.Register(static state => ((TaskCompletionSource<bool>) state!).SetResult(true), source))
        {
            await source.Task;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            var provider = await GetSelectedProviderAsync(stoppingToken);

            AnsiConsole.MarkupLine("[cyan]Launching the system browser.[/]");

            try
            {
                // Ask OpenIddict to initiate the authentication flow (typically, by
                // starting the system browser) and wait for the user to complete it.
                var (_, _, principal) = await _service.AuthenticateInteractivelyAsync(
                    provider, cancellationToken: stoppingToken);

                AnsiConsole.MarkupLineInterpolated($"[green]Welcome, {principal.FindFirst(Claims.Name)!.Value}.[/]");
            }

            catch (OperationCanceledException)
            {
                AnsiConsole.MarkupLine("[red]The authentication process was aborted.[/]");
            }

            catch (ProtocolException exception) when (exception.Error is Errors.AccessDenied)
            {
                AnsiConsole.MarkupLine("[yellow]The authorization was denied by the end user.[/]");
            }

            catch
            {
                AnsiConsole.MarkupLine("[red]An error occurred while trying to authenticate the user.[/]");
            }
        }

        static async Task<string> GetSelectedProviderAsync(CancellationToken cancellationToken)
        {
            static string Prompt() => AnsiConsole.Prompt(new SelectionPrompt<string>()
                .Title("Select the authentication provider you'd like to log in with.")
                .AddChoices("Local", Providers.GitHub, Providers.Twitter));

#if SUPPORTS_TASK_WAIT_ASYNC
            return await Task.Run(Prompt, cancellationToken).WaitAsync(cancellationToken);
#else
            var task = Task.Run(Prompt, cancellationToken);
            var source = new TaskCompletionSource<bool>(TaskCreationOptions.None);

            using (cancellationToken.Register(static state => ((TaskCompletionSource<bool>) state!).SetResult(true), source))
            {
                if (await Task.WhenAny(task, source.Task) == source.Task)
                {
                    throw new OperationCanceledException(cancellationToken);
                }

                return await task;
            }
#endif
        }
    }
}
