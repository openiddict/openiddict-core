/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace OpenIddict.Server;

[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictServerDispatcher : IOpenIddictServerDispatcher
{
    private readonly ILogger<OpenIddictServerDispatcher> _logger;
    private readonly IOptionsMonitor<OpenIddictServerOptions> _options;
    private readonly IServiceProvider _provider;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictServerDispatcher"/> class.
    /// </summary>
    public OpenIddictServerDispatcher(
        ILogger<OpenIddictServerDispatcher> logger,
        IOptionsMonitor<OpenIddictServerOptions> options,
        IServiceProvider provider)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
    }

    public async ValueTask DispatchAsync<TContext>(TContext context) where TContext : BaseContext
    {
        if (context is null)
        {
            throw new ArgumentNullException(nameof(context));
        }

        await foreach (var handler in GetHandlersAsync())
        {
            try
            {
                await handler.HandleAsync(context);
            }

            catch (Exception exception) when (_logger.IsEnabled(LogLevel.Debug))
            {
                _logger.LogDebug(exception, SR.GetResourceString(SR.ID6132), handler.GetType().FullName, typeof(TContext).FullName);

                throw;
            }

            if (_logger.IsEnabled(LogLevel.Debug))
            {
                _logger.LogDebug(SR.GetResourceString(SR.ID6133), typeof(TContext).FullName, handler.GetType().FullName);
            }

            switch (context)
            {
                case BaseRequestContext { IsRequestHandled: true }:
                    if (_logger.IsEnabled(LogLevel.Debug))
                    {
                        _logger.LogDebug(SR.GetResourceString(SR.ID6134), typeof(TContext).FullName, handler.GetType().FullName);
                    }
                    return;

                case BaseRequestContext { IsRequestSkipped: true }:
                    if (_logger.IsEnabled(LogLevel.Debug))
                    {
                        _logger.LogDebug(SR.GetResourceString(SR.ID6135), typeof(TContext).FullName, handler.GetType().FullName);
                    }
                    return;

                case BaseValidatingContext { IsRejected: true }:
                    if (_logger.IsEnabled(LogLevel.Debug))
                    {
                        _logger.LogDebug(SR.GetResourceString(SR.ID6136), typeof(TContext).FullName, handler.GetType().FullName);
                    }
                    return;

                default: continue;
            }
        }

        async IAsyncEnumerable<IOpenIddictServerHandler<TContext>> GetHandlersAsync()
        {
            // Note: the descriptors collection is sorted during options initialization for performance reasons.
            var descriptors = _options.CurrentValue.Handlers;
            if (descriptors.Count is 0)
            {
                yield break;
            }

            for (var index = 0; index < descriptors.Count; index++)
            {
                var descriptor = descriptors[index];
                if (descriptor.ContextType != typeof(TContext) || !await IsActiveAsync(descriptor))
                {
                    continue;
                }

                yield return descriptor.ServiceDescriptor switch
                {
                    { ImplementationInstance: IOpenIddictServerHandler<TContext> handler } => handler,

                    _ when _provider.GetService(descriptor.ServiceDescriptor.ServiceType)
                        is IOpenIddictServerHandler<TContext> handler => handler,

                    _ => throw new InvalidOperationException(SR.FormatID0098(descriptor.ServiceDescriptor.ServiceType))
                };
            }
        }

        async ValueTask<bool> IsActiveAsync(OpenIddictServerHandlerDescriptor descriptor)
        {
            for (var index = 0; index < descriptor.FilterTypes.Length; index++)
            {
                if (!(_provider.GetService(descriptor.FilterTypes[index]) is IOpenIddictServerHandlerFilter<TContext> filter))
                {
                    throw new InvalidOperationException(SR.FormatID0099(descriptor.FilterTypes[index]));
                }

                if (!await filter.IsActiveAsync(context))
                {
                    return false;
                }
            }

            return true;
        }
    }
}
