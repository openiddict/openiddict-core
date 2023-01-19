using Microsoft.Extensions.Hosting;
using OpenIddict.Client;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Abstractions.OpenIddictExceptions;
using static System.Console;

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
        var source = new TaskCompletionSource();
        using (_lifetime.ApplicationStarted.Register(static state => ((TaskCompletionSource) state!).SetResult(), source))
        {
            await source.Task;
        }

        string? provider;

        while (!stoppingToken.IsCancellationRequested)
        {
            do
            {
                await Out.WriteLineAsync("Type '1' + ENTER to log in using the local server or '2' + ENTER to log in using Twitter");

                provider = await In.ReadLineAsync(stoppingToken) switch
                {
                    "1" => "Local",
                    "2" => "Twitter",
                    _ => null
                };
            }

            while (string.IsNullOrEmpty(provider));

            await Out.WriteLineAsync("Launching the system browser.");

            try
            {
                // Ask OpenIddict to initiate the challenge and launch the system browser
                // to allow the user to complete the interactive authentication dance.
                var nonce = await _service.ChallengeWithBrowserAsync(
                    provider, cancellationToken: stoppingToken);

                // Wait until the user approved or rejected the authorization
                // demand and retrieve the resulting claims-based principal.
                var (_, _, principal) = await _service.AuthenticateWithBrowserAsync(
                    nonce, cancellationToken: stoppingToken);

                await Out.WriteLineAsync($"Welcome, {principal.FindFirst(Claims.Name)!.Value}.");
            }

            catch (OperationCanceledException)
            {
                await Error.WriteLineAsync("The authentication process was aborted.");
            }

            catch (ProtocolException exception) when (exception.Error is Errors.AccessDenied)
            {
                await Error.WriteLineAsync("The authorization was denied by the end user.");
            }

            catch
            {
                await Error.WriteLineAsync("An error occurred while trying to authenticate the user.");
            }
        }
    }
}
