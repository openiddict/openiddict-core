/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

#if !SUPPORTS_HOST_APPLICATION_LIFETIME
using IHostApplicationLifetime = Microsoft.Extensions.Hosting.IApplicationLifetime;
#endif

namespace OpenIddict.Client.Windows;

/// <summary>
/// Contains the logic necessary to handle URI protocol activations that
/// are redirected by other instances using inter-process communication.
/// </summary>
/// <remarks>
/// Note: initial URI protocol activations are handled by <see cref="OpenIddictClientWindowsService"/>.
/// </remarks>
[EditorBrowsable(EditorBrowsableState.Never)]
public sealed class OpenIddictClientWindowsListener : BackgroundService
{
    private readonly ILogger<OpenIddictClientWindowsListener> _logger;
    private readonly IOptionsMonitor<OpenIddictClientWindowsOptions> _options;
    private readonly IServiceProvider _provider;

    public OpenIddictClientWindowsListener(
        ILogger<OpenIddictClientWindowsListener> logger,
        IOptionsMonitor<OpenIddictClientWindowsOptions> options,
        IServiceProvider provider)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
    }

    /// <inheritdoc/>
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        do
        {
            try
            {
                using var buffer = new MemoryStream();
                using var reader = new BinaryReader(buffer);

#if SUPPORTS_NAMED_PIPE_CONSTRUCTOR_WITH_ACL
                using var stream = new NamedPipeServerStream(
#elif SUPPORTS_NAMED_PIPE_STATIC_FACTORY_WITH_ACL
                using var stream = NamedPipeServerStreamAcl.Create(
#else
                using var stream = NamedPipeServerStreamConstructors.New(
#endif
                    pipeName                  : $@"{_options.CurrentValue.PipeName}\{_options.CurrentValue.InstanceIdentifier}",
                    direction                 : PipeDirection.In,
                    maxNumberOfServerInstances: 1,
                    transmissionMode          : PipeTransmissionMode.Message,
                    options                   : PipeOptions.Asynchronous,
                    inBufferSize              : 0,
                    outBufferSize             : 0,
                    pipeSecurity              : _options.CurrentValue.PipeSecurity,
                    inheritability            : HandleInheritability.None,
                    additionalAccessRights    : default);

                // Wait for a writer to connect to the named pipe.
                await stream.WaitForConnectionAsync(stoppingToken);

                // Copy the content to the memory stream asynchronously and rewind it.
                await stream.CopyToAsync(buffer, bufferSize: 81_920, stoppingToken);
                buffer.Seek(0L, SeekOrigin.Begin);

                // Process the inter-process notification based on its declared type.
                await (reader.ReadInt32() switch
                {
                    0x01 when GetProtocolActivation(reader) is OpenIddictClientWindowsActivation activation
                        => HandleProtocolActivationAsync(_provider, activation, stoppingToken),

                    var value => throw new InvalidOperationException(SR.FormatID0387(value))
                });
            }

            // Ignore operation canceled exceptions when the host is shutting down.
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
            }

            // Swallow all exceptions to ensure the service doesn't exit when encountering an exception.
            catch (Exception exception)
            {
                _logger.LogWarning(exception, SR.GetResourceString(SR.ID6213));
            }
        }

        while (!stoppingToken.IsCancellationRequested);

        static OpenIddictClientWindowsActivation? GetProtocolActivation(BinaryReader reader)
        {
            // Ensure the binary serialization format is supported.
            var version = reader.ReadInt32();
            if (version is not 0x01)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0388));
            }

            var value = reader.ReadString();
            if (string.IsNullOrEmpty(value) || !Uri.TryCreate(value, UriKind.Absolute, out Uri? uri))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0388));
            }

            return new OpenIddictClientWindowsActivation
            {
                ActivationUri = uri,
                IsActivationRedirected = true
            };
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
}
