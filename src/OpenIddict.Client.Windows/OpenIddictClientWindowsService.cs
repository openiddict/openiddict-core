/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

#if !SUPPORTS_HOST_APPLICATION_LIFETIME
using IHostApplicationLifetime = Microsoft.Extensions.Hosting.IApplicationLifetime;
#endif

namespace OpenIddict.Client.Windows;

/// <summary>
/// Contains the logic necessary to handle initial URI protocol activations.
/// </summary>
/// <remarks>
/// Note: redirected URI protocol activations are handled by <see cref="OpenIddictClientWindowsListener"/>.
/// </remarks>
[EditorBrowsable(EditorBrowsableState.Never)]
public sealed class OpenIddictClientWindowsService : IHostedService
{
    private readonly IServiceProvider _provider;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientWindowsService"/> class.
    /// </summary>
    /// <param name="provider">The service provider.</param>
    /// <exception cref="ArgumentNullException"><paramref name="provider"/> is <see langword="null"/>.</exception>
    public OpenIddictClientWindowsService(IServiceProvider provider)
        => _provider = provider ?? throw new ArgumentNullException(nameof(provider));

    /// <inheritdoc/>
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // Note: initial URI protocol activation handling is implemented as a regular IHostedService
        // rather than as a BackgroundService to allow blocking the initialization of the host until
        // the activation is fully processed by the OpenIddict pipeline. By doing that, the UI thread
        // is not started until redirection requests (like authorization responses) are fully processed,
        // which allows handling these requests transparently and helps avoid the "flashing window effect":
        // once a request has been handled by the OpenIddict pipeline, a dedicated handler is responsible
        // for stopping the application gracefully using the IHostApplicationLifetime.StopApplication() API.

        var scope = _provider.CreateScope();

        try
        {
            var dispatcher = scope.ServiceProvider.GetRequiredService<IOpenIddictClientDispatcher>();
            var factory = scope.ServiceProvider.GetRequiredService<IOpenIddictClientFactory>();

            // Create a client transaction and store the command line arguments so they can be
            // retrieved by the Windows-specific client event handlers that need to access them.
            var transaction = await factory.CreateTransactionAsync();
            transaction.SetProperty(typeof(OpenIddictClientWindowsActivation).FullName!,
                new OpenIddictClientWindowsActivation
                {
                    CommandLineArguments = ImmutableArray.CreateRange(Environment.GetCommandLineArgs()),
                    IsActivationRedirected = false
                });

            var context = new ProcessRequestContext(transaction)
            {
                CancellationToken = cancellationToken
            };

            await dispatcher.DispatchAsync(context);

            if (context.IsRejected)
            {
                await dispatcher.DispatchAsync(new ProcessErrorContext(transaction)
                {
                    CancellationToken = cancellationToken,
                    Error = context.Error ?? Errors.InvalidRequest,
                    ErrorDescription = context.ErrorDescription,
                    ErrorUri = context.ErrorUri,
                    Response = new OpenIddictResponse()
                });
            }
        }

        finally
        {
            if (scope is IAsyncDisposable disposable)
            {
                await disposable.DisposeAsync();
            }

            else
            {
                scope.Dispose();
            }
        }
    }

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
