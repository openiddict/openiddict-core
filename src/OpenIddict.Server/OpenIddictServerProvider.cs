/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Server
{
    public class OpenIddictServerProvider : IOpenIddictServerProvider
    {
        private readonly ILogger<OpenIddictServerProvider> _logger;
        private readonly IOptionsMonitor<OpenIddictServerOptions> _options;
        private readonly IServiceProvider _provider;

        /// <summary>
        /// Creates a new instance of the <see cref="OpenIddictServerProvider"/> class.
        /// </summary>
        public OpenIddictServerProvider(
            [NotNull] ILogger<OpenIddictServerProvider> logger,
            [NotNull] IOptionsMonitor<OpenIddictServerOptions> options,
            [NotNull] IServiceProvider provider)
        {
            _logger = logger;
            _options = options;
            _provider = provider;
        }

        public ValueTask<OpenIddictServerTransaction> CreateTransactionAsync()
            => new ValueTask<OpenIddictServerTransaction>(new OpenIddictServerTransaction
            {
                Issuer = _options.CurrentValue.Issuer,
                Logger = _logger,
                Options = _options.CurrentValue
            });

        public async ValueTask DispatchAsync<TContext>([NotNull] TContext context) where TContext : BaseContext
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            await foreach (var handler in GetHandlersAsync())
            {
                await handler.HandleAsync(context);

                switch (context)
                {
                    case BaseRequestContext notification when notification.IsRequestHandled:
                        _logger.LogDebug("The request was handled in user code.");
                        return;

                    case BaseRequestContext notification when notification.IsRequestSkipped:
                        _logger.LogDebug("The default request handling was skipped from user code.");
                        return;

                    case BaseValidatingContext notification when notification.IsRejected:
                        _logger.LogDebug("The request was rejected in user code.");
                        return;

                    case BaseValidatingTicketContext notification when notification.IsHandled:
                        _logger.LogDebug("Authentication was handled in user code.");
                        return;

                    case BaseDeserializingContext notification when notification.IsHandled:
                        _logger.LogDebug("Token deserialization was handled in user code.");
                        return;

                    case BaseSerializingContext notification when notification.IsHandled:
                        _logger.LogDebug("Token serialization was handled in user code.");
                        return;

                    default: continue;
                }
            }

            async IAsyncEnumerable<IOpenIddictServerHandler<TContext>> GetHandlersAsync()
            {
                var descriptors = new List<OpenIddictServerHandlerDescriptor>(
                    capacity: _options.CurrentValue.CustomHandlers.Count +
                              _options.CurrentValue.DefaultHandlers.Count);

                descriptors.AddRange(_options.CurrentValue.CustomHandlers);
                descriptors.AddRange(_options.CurrentValue.DefaultHandlers);

                foreach (var descriptor in descriptors.OrderBy(descriptor => descriptor.Order))
                {
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
