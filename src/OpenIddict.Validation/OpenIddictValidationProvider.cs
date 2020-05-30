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
using static OpenIddict.Validation.OpenIddictValidationEvents;

namespace OpenIddict.Validation
{
    public class OpenIddictValidationProvider : IOpenIddictValidationProvider
    {
        private readonly ILogger<OpenIddictValidationProvider> _logger;
        private readonly IOptionsMonitor<OpenIddictValidationOptions> _options;
        private readonly IServiceProvider _provider;

        /// <summary>
        /// Creates a new instance of the <see cref="OpenIddictValidationProvider"/> class.
        /// </summary>
        public OpenIddictValidationProvider(
            [NotNull] ILogger<OpenIddictValidationProvider> logger,
            [NotNull] IOptionsMonitor<OpenIddictValidationOptions> options,
            [NotNull] IServiceProvider provider)
        {
            _logger = logger;
            _options = options;
            _provider = provider;
        }

        public ValueTask<OpenIddictValidationTransaction> CreateTransactionAsync()
            => new ValueTask<OpenIddictValidationTransaction>(new OpenIddictValidationTransaction
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
                        if (_logger.IsEnabled(LogLevel.Debug))
                        {
                            _logger.LogDebug("The event context was marked as handled by {Name}.", handler.GetType().FullName);
                        }
                        return;

                    case BaseRequestContext notification when notification.IsRequestSkipped:
                        if (_logger.IsEnabled(LogLevel.Debug))
                        {
                            _logger.LogDebug("The event context was marked as skipped by {Name}.", handler.GetType().FullName);
                        }
                        return;

                    case BaseValidatingContext notification when notification.IsRejected:
                        if (_logger.IsEnabled(LogLevel.Debug))
                        {
                            _logger.LogDebug("The event context was marked as rejected by {Name}.", handler.GetType().FullName);
                        }
                        return;

                    default: continue;
                }
            }

            async IAsyncEnumerable<IOpenIddictValidationHandler<TContext>> GetHandlersAsync()
            {
                var descriptors = new List<OpenIddictValidationHandlerDescriptor>(
                    capacity: _options.CurrentValue.CustomHandlers.Count +
                              _options.CurrentValue.DefaultHandlers.Count);

                descriptors.AddRange(_options.CurrentValue.CustomHandlers);
                descriptors.AddRange(_options.CurrentValue.DefaultHandlers);

                descriptors.Sort((left, right) => left.Order.CompareTo(right.Order));

                for (var index = 0; index < descriptors.Count; index++)
                {
                    var descriptor = descriptors[index];
                    if (descriptor.ContextType != typeof(TContext) || !await IsActiveAsync(descriptor))
                    {
                        continue;
                    }

                    var handler = descriptor.ServiceDescriptor.ImplementationInstance != null ?
                        descriptor.ServiceDescriptor.ImplementationInstance as IOpenIddictValidationHandler<TContext> :
                        _provider.GetService(descriptor.ServiceDescriptor.ServiceType) as IOpenIddictValidationHandler<TContext>;

                    if (handler == null)
                    {
                        throw new InvalidOperationException(new StringBuilder()
                            .AppendLine($"The event handler of type '{descriptor.ServiceDescriptor.ServiceType}' couldn't be resolved.")
                            .AppendLine("This may indicate that it was not properly registered in the dependency injection container.")
                            .Append("To register an event handler, use 'services.AddOpenIddict().AddValidation().AddEventHandler()'.")
                            .ToString());
                    }

                    yield return handler;
                }
            }

            async ValueTask<bool> IsActiveAsync(OpenIddictValidationHandlerDescriptor descriptor)
            {
                for (var index = 0; index < descriptor.FilterTypes.Length; index++)
                {
                    if (!(_provider.GetService(descriptor.FilterTypes[index]) is IOpenIddictValidationHandlerFilter<TContext> filter))
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
