/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Server
{
    public class OpenIddictServerDispatcher : IOpenIddictServerDispatcher
    {
        private readonly ILogger<OpenIddictServerDispatcher> _logger;
        private readonly IOptionsMonitor<OpenIddictServerOptions> _options;
        private readonly IServiceProvider _provider;

        /// <summary>
        /// Creates a new instance of the <see cref="OpenIddictServerDispatcher"/> class.
        /// </summary>
        public OpenIddictServerDispatcher(
            [NotNull] ILogger<OpenIddictServerDispatcher> logger,
            [NotNull] IOptionsMonitor<OpenIddictServerOptions> options,
            [NotNull] IServiceProvider provider)
        {
            _logger = logger;
            _options = options;
            _provider = provider;
        }

        public async ValueTask DispatchAsync<TContext>([NotNull] TContext context) where TContext : BaseContext
        {
            if (context == null)
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
                    _logger.LogDebug(exception, "An exception was thrown by {FullName} while handling the {Event} event.",
                        handler.GetType().FullName, typeof(TContext).FullName);

                    throw;
                }

                if (_logger.IsEnabled(LogLevel.Debug))
                {
                    _logger.LogDebug("The event {Event} was successfully processed by {FullName}.",
                        typeof(TContext).FullName, handler.GetType().FullName);
                }

                switch (context)
                {
                    case BaseRequestContext notification when notification.IsRequestHandled:
                        if (_logger.IsEnabled(LogLevel.Debug))
                        {
                            _logger.LogDebug("The event {Event} was marked as handled by {FullName}.",
                                typeof(TContext).FullName, handler.GetType().FullName);
                        }
                        return;

                    case BaseRequestContext notification when notification.IsRequestSkipped:
                        if (_logger.IsEnabled(LogLevel.Debug))
                        {
                            _logger.LogDebug("The event {Event} was marked as skipped by {FullName}.",
                                typeof(TContext).FullName, handler.GetType().FullName);
                        }
                        return;

                    case BaseValidatingContext notification when notification.IsRejected:
                        if (_logger.IsEnabled(LogLevel.Debug))
                        {
                            _logger.LogDebug("The event {Event} was marked as rejected by {FullName}.",
                                typeof(TContext).FullName, handler.GetType().FullName);
                        }
                        return;

                    default: continue;
                }
            }

            async IAsyncEnumerable<IOpenIddictServerHandler<TContext>> GetHandlersAsync()
            {
                // Note: the descriptors collection is sorted during options initialization for performance reasons.
                var descriptors = _options.CurrentValue.Handlers;
                if (descriptors.Count == 0)
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

                    var handler = descriptor.ServiceDescriptor.ImplementationInstance != null ?
                        descriptor.ServiceDescriptor.ImplementationInstance as IOpenIddictServerHandler<TContext> :
                        _provider.GetService(descriptor.ServiceDescriptor.ServiceType) as IOpenIddictServerHandler<TContext>;

                    if (handler == null)
                    {
                        throw new InvalidOperationException(new StringBuilder()
                            .AppendLine($"The event handler of type '{descriptor.ServiceDescriptor.ServiceType}' couldn't be resolved.")
                            .AppendLine("This may indicate that it was not properly registered in the dependency injection container.")
                            .Append("To register an event handler, use 'services.AddOpenIddict().AddServer().AddEventHandler()'.")
                            .ToString());
                    }

                    yield return handler;
                }
            }

            async ValueTask<bool> IsActiveAsync(OpenIddictServerHandlerDescriptor descriptor)
            {
                for (var index = 0; index < descriptor.FilterTypes.Length; index++)
                {
                    if (!(_provider.GetService(descriptor.FilterTypes[index]) is IOpenIddictServerHandlerFilter<TContext> filter))
                    {
                        throw new InvalidOperationException(new StringBuilder()
                            .AppendLine($"The event handler filter of type '{descriptor.FilterTypes[index]}' couldn't be resolved.")
                            .AppendLine("This may indicate that it was not properly registered in the dependency injection container.")
                            .ToString());
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
}
