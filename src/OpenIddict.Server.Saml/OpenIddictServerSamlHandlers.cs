/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ProcessSessionTerminationContext = OpenIddict.Server.OpenIddictServerEvents.ProcessSessionTerminationContext;

namespace OpenIddict.Server.Saml;

/// <summary>
/// Contains the server event handlers used by the OpenIddict SAML 2.0 identity provider.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Never)]
public static class OpenIddictServerSamlHandlers
{
    /// <summary>
    /// Gets the default handlers registered in the server options by the SAML identity provider.
    /// </summary>
    public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } =
    [
        NotifyServiceProviderSessions.Descriptor
    ];

    /// <summary>
    /// Contains the logic responsible for notifying the SAML service providers whose sessions are terminated, when single
    /// logout is enabled. This handler is invoked for all the session terminations (single logout endpoint, OpenID Connect
    /// end session endpoint and <see cref="OpenIddictServerService.TerminateSessionAsync(string, CancellationToken)"/>).
    /// </summary>
    public sealed class NotifyServiceProviderSessions : IOpenIddictServerHandler<ProcessSessionTerminationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSessionTerminationContext>()
                .UseSingletonHandler<NotifyServiceProviderSessions>()
                .SetOrder(OpenIddictServerHandlers.Logout.AttachFrontchannelLogoutUris.Descriptor.Order + 500)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSessionTerminationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            if (context.IsRejected || context.Sessions.Count is 0 ||
                context.ServiceProvider.GetService<IOptionsMonitor<OpenIddictServerSamlOptions>>()?.CurrentValue is not { EnableSingleLogout: true } ||
                context.ServiceProvider.GetService<OpenIddictServerSamlLogoutService>() is not { } service)
            {
                return ValueTask.CompletedTask;
            }

            return service.ProcessSessionTerminationAsync(context);
        }
    }
}
