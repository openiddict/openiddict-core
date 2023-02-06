/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

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
    private readonly IOptionsMonitor<OpenIddictClientWindowsOptions> _options;
    private readonly IServiceProvider _provider;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientWindowsService"/> class.
    /// </summary>
    /// <param name="options">The OpenIddict client Windows integration options.</param>
    /// <param name="provider">The service provider.</param>
    /// <exception cref="ArgumentNullException"><paramref name="provider"/> is <see langword="null"/>.</exception>
    public OpenIddictClientWindowsService(
        IOptionsMonitor<OpenIddictClientWindowsOptions> options,
        IServiceProvider provider)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
    }

    /// <inheritdoc/>
    public Task StartAsync(CancellationToken cancellationToken)
    {
        // Note: initial URI protocol activation handling is implemented as a regular IHostedService
        // rather than as a BackgroundService to allow blocking the initialization of the host until
        // the activation is fully processed by the OpenIddict pipeline. By doing that, the UI thread
        // is not started until redirection requests (like authorization responses) are fully processed,
        // which allows handling these requests transparently and helps avoid the "flashing window effect":
        // once a request has been handled by the OpenIddict pipeline, a dedicated handler is responsible
        // for stopping the application gracefully using the IHostApplicationLifetime.StopApplication() API.

        if (cancellationToken.IsCancellationRequested)
        {
            return Task.FromCanceled(cancellationToken);
        }

        // If the default activation processing logic was disabled in the options, ignore the activation.
        if (_options.CurrentValue.DisableProtocolActivationProcessing)
        {
            return Task.CompletedTask;
        }

        // Determine whether the current instance is initialized to react to a protocol activation.
        // If it's not, return immediately to avoid adding latency to the application startup process.
        if (GetProtocolActivation() is not OpenIddictClientWindowsActivation activation)
        {
            return Task.CompletedTask;
        }

        return HandleProtocolActivationAsync(_provider, activation, cancellationToken);

        [MethodImpl(MethodImplOptions.NoInlining)]
        static OpenIddictClientWindowsActivation? GetProtocolActivation()
        {
#if SUPPORTS_WINDOWS_RUNTIME
            // On platforms that support WinRT, always favor the AppInstance.GetActivatedEventArgs() API.
            if (OpenIddictClientWindowsHelpers.IsWindowsRuntimeSupported() &&
                OpenIddictClientWindowsHelpers.GetProtocolActivationUriWithWindowsRuntime() is Uri uri)
            {
                return new OpenIddictClientWindowsActivation
                {
                    ActivationUri = uri,
                    IsActivationRedirected = false
                };
            }
#endif
            // Otherwise, try to extract the protocol activation from the command line arguments.
            if (OpenIddictClientWindowsHelpers.GetProtocolActivationUriFromCommandLineArguments(
                Environment.GetCommandLineArgs()) is Uri value)
            {
                return new OpenIddictClientWindowsActivation
                {
                    ActivationUri = value,
                    IsActivationRedirected = false
                };
            }

            return null;
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        static async Task HandleProtocolActivationAsync(IServiceProvider provider,
            OpenIddictClientWindowsActivation activation, CancellationToken cancellationToken)
        {
            var scope = provider.CreateScope();

            try
            {
                var dispatcher = scope.ServiceProvider.GetRequiredService<IOpenIddictClientDispatcher>();
                var factory = scope.ServiceProvider.GetRequiredService<IOpenIddictClientFactory>();

                // Create a client transaction and store the protocol activation details so they can be
                // retrieved by the Windows-specific client event handlers that need to access them.
                var transaction = await factory.CreateTransactionAsync();
                transaction.SetProperty(typeof(OpenIddictClientWindowsActivation).FullName!, activation);

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
    }

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
