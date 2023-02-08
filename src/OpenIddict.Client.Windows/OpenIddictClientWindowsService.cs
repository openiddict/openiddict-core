/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.Extensions.DependencyInjection;

namespace OpenIddict.Client.Windows;

/// <summary>
/// Contains the logic necessary to handle URI protocol activations (that
/// are typically resolved when launching the application or redirected
/// by other instances using inter-process communication).
/// </summary>
public sealed class OpenIddictClientWindowsService
{
    private readonly IServiceProvider _provider;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientWindowsService"/> class.
    /// </summary>
    /// <param name="provider">The service provider.</param>
    /// <exception cref="ArgumentNullException"><paramref name="provider"/> is <see langword="null"/>.</exception>
    public OpenIddictClientWindowsService(IServiceProvider provider)
        => _provider = provider ?? throw new ArgumentNullException(nameof(provider));

    /// <summary>
    /// Handles the specified protocol activation.
    /// </summary>
    /// <param name="activation">The protocol activation details.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="activation"/> is <see langword="null"/>.</exception>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public async Task HandleProtocolActivationAsync(
        OpenIddictClientWindowsActivation activation, CancellationToken cancellationToken = default)
    {
        if (activation is null)
        {
            throw new ArgumentNullException(nameof(activation));
        }

        cancellationToken.ThrowIfCancellationRequested();

        var scope = _provider.CreateScope();

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
