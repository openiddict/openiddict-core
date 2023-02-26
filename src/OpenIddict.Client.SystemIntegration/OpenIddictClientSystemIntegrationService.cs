/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.IO.Pipes;
using System.Net;
using System.Security.Principal;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

#if SUPPORTS_WINDOWS_RUNTIME
using Windows.Security.Authentication.Web;
#endif

namespace OpenIddict.Client.SystemIntegration;

/// <summary>
/// Contains the logic necessary to handle URI protocol activations (that
/// are typically resolved when launching the application or redirected
/// by other instances using inter-process communication).
/// </summary>
public sealed class OpenIddictClientSystemIntegrationService
{
    private readonly IOptionsMonitor<OpenIddictClientSystemIntegrationOptions> _options;
    private readonly IServiceProvider _provider;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientSystemIntegrationService"/> class.
    /// </summary>
    /// <param name="options">The OpenIddict client system integration options.</param>
    /// <param name="provider">The service provider.</param>
    /// <exception cref="ArgumentNullException"><paramref name="provider"/> is <see langword="null"/>.</exception>
    public OpenIddictClientSystemIntegrationService(
        IOptionsMonitor<OpenIddictClientSystemIntegrationOptions> options,
        IServiceProvider provider)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
    }

    /// <summary>
    /// Handles the specified protocol activation.
    /// </summary>
    /// <param name="activation">The protocol activation details.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="activation"/> is <see langword="null"/>.</exception>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public Task HandleProtocolActivationAsync(
        OpenIddictClientSystemIntegrationActivation activation, CancellationToken cancellationToken = default)
        => HandleRequestAsync(activation ?? throw new ArgumentNullException(nameof(activation)), cancellationToken);

    /// <summary>
    /// Handles the specified HTTP request.
    /// </summary>
    /// <param name="request">The HTTP request received by the embedded web server.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="request"/> is <see langword="null"/>.</exception>
    internal Task HandleHttpRequestAsync(HttpListenerContext request, CancellationToken cancellationToken = default)
        => HandleRequestAsync(request ?? throw new ArgumentNullException(nameof(request)), cancellationToken);

#if SUPPORTS_WINDOWS_RUNTIME
    /// <summary>
    /// Handles the specified web authentication result.
    /// </summary>
    /// <param name="result">The web authentication result.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="result"/> is <see langword="null"/>.</exception>
    internal Task HandleWebAuthenticationResultAsync(WebAuthenticationResult result, CancellationToken cancellationToken = default)
        => HandleRequestAsync(result ?? throw new ArgumentNullException(nameof(result)), cancellationToken);
#endif

    /// <summary>
    /// Handles the request using the specified property.
    /// </summary>
    /// <param name="property">The property to add to the transaction.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="property"/> is <see langword="null"/>.</exception>
    private async Task HandleRequestAsync<TProperty>(TProperty property, CancellationToken cancellationToken) where TProperty : class
    {
        if (property is null)
        {
            throw new ArgumentNullException(nameof(property));
        }

        cancellationToken.ThrowIfCancellationRequested();

        var scope = _provider.CreateScope();

        try
        {
            var dispatcher = scope.ServiceProvider.GetRequiredService<IOpenIddictClientDispatcher>();
            var factory = scope.ServiceProvider.GetRequiredService<IOpenIddictClientFactory>();

            // Create a client transaction and store the specified instance so
            // it can be retrieved by the event handlers that need to access it.
            var transaction = await factory.CreateTransactionAsync();
            transaction.SetProperty(typeof(TProperty).FullName!, property);

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

    /// <summary>
    /// Redirects a protocol activation to the specified instance.
    /// </summary>
    /// <param name="activation">The protocol activation to redirect.</param>
    /// <param name="identifier">The identifier of the target instance.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="activation"/> is <see langword="null"/>.</exception>
    internal async Task RedirectProtocolActivationAsync(
        OpenIddictClientSystemIntegrationActivation activation,
        string identifier, CancellationToken cancellationToken = default)
    {
        if (activation is null)
        {
            throw new ArgumentNullException(nameof(activation));
        }

        if (string.IsNullOrEmpty(identifier))
        {
            throw new ArgumentException(SR.FormatID0366(nameof(identifier)), nameof(identifier));
        }

        using var buffer = new MemoryStream();
        using var writer = new BinaryWriter(buffer);
        using var stream = new NamedPipeClientStream(
            serverName        : ".",
            pipeName          : $@"{_options.CurrentValue.PipeName}\{identifier}",
            direction         : PipeDirection.Out,
            options           : PipeOptions.Asynchronous,
            impersonationLevel: TokenImpersonationLevel.None,
            inheritability    : HandleInheritability.None);

        // Wait for the target to accept the pipe connection.
        await stream.ConnectAsync(cancellationToken);

        // Write the type of message stored in the shared memory and the
        // version used to identify the binary serialization format.
        writer.Write(0x01);
        writer.Write(0x01);

        // Write the protocol activation URI.
        writer.Write(activation.ActivationUri.AbsoluteUri);

        // Transfer the payload to the target.
        buffer.Seek(0L, SeekOrigin.Begin);
        await buffer.CopyToAsync(stream, bufferSize: 81_920, cancellationToken);
    }
}
