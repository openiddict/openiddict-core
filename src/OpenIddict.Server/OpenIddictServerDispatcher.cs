/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.Extensions.Logging;

namespace OpenIddict.Server;

/// <summary>
/// Represents a service able to dispatch events to a list of handlers.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictServerDispatcher : IOpenIddictServerDispatcher
{
    /// <inheritdoc/>
    public async ValueTask DispatchAsync<TContext>(TContext context) where TContext : BaseContext
    {
        ArgumentNullException.ThrowIfNull(context);

        // Note: the descriptors collection is sorted during options initialization for performance reasons.
        foreach (var descriptor in context.Options.Handlers)
        {
            context.CancellationToken.ThrowIfCancellationRequested();

            if (descriptor.ContextType != typeof(TContext) || !await IsActiveAsync(descriptor))
            {
                continue;
            }

            var handler = descriptor.ServiceDescriptor.ImplementationInstance as IOpenIddictServerHandler<TContext>
                ?? context.ServiceProvider.GetService(descriptor.ServiceDescriptor.ServiceType) as IOpenIddictServerHandler<TContext>
                ?? throw new InvalidOperationException(SR.FormatID0098(descriptor.ServiceDescriptor.ServiceType));

            try
            {
                await handler.HandleAsync(context);
            }

            catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception) && context.Logger.IsEnabled(LogLevel.Debug))
            {
                context.Logger.LogDebug(6132, exception, SR.GetResourceString(SR.ID6132), handler.GetType().FullName, typeof(TContext).FullName);

                throw;
            }

            if (context.Logger.IsEnabled(LogLevel.Debug))
            {
                context.Logger.LogDebug(6133, SR.GetResourceString(SR.ID6133), typeof(TContext).FullName, handler.GetType().FullName);
            }

            switch (context)
            {
                case BaseRequestContext { IsRequestHandled: true }:
                    if (context.Logger.IsEnabled(LogLevel.Debug))
                    {
                        context.Logger.LogDebug(6134, SR.GetResourceString(SR.ID6134), typeof(TContext).FullName, handler.GetType().FullName);
                    }
                    return;

                case BaseRequestContext { IsRequestSkipped: true }:
                    if (context.Logger.IsEnabled(LogLevel.Debug))
                    {
                        context.Logger.LogDebug(6135, SR.GetResourceString(SR.ID6135), typeof(TContext).FullName, handler.GetType().FullName);
                    }
                    return;

                case BaseValidatingContext { IsRejected: true }:
                    if (context.Logger.IsEnabled(LogLevel.Debug))
                    {
                        context.Logger.LogDebug(6136, SR.GetResourceString(SR.ID6136), typeof(TContext).FullName, handler.GetType().FullName);
                    }
                    return;
            }
        }

        async ValueTask<bool> IsActiveAsync(OpenIddictServerHandlerDescriptor descriptor)
        {
            foreach (var type in descriptor.FilterTypes)
            {
                var filter = context.ServiceProvider.GetService(type) as IOpenIddictServerHandlerFilter<TContext>
                    ?? throw new InvalidOperationException(SR.FormatID0099(type));

                if (!await filter.IsActiveAsync(context))
                {
                    return false;
                }
            }

            return true;
        }
    }
}
