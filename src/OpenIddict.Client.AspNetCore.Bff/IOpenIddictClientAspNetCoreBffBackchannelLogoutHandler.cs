/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using static OpenIddict.Client.AspNetCore.Bff.OpenIddictClientAspNetCoreBffModels;

namespace OpenIddict.Client.AspNetCore.Bff;

/// <summary>
/// Represents a handler invoked when a valid back-channel logout notification is received.
/// All the registered handlers are invoked, in registration order.
/// </summary>
public interface IOpenIddictClientAspNetCoreBffBackchannelLogoutHandler
{
    /// <summary>
    /// Handles the specified back-channel logout notification.
    /// </summary>
    /// <param name="notification">The back-channel logout notification.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask HandleAsync(BackchannelLogoutNotification notification, CancellationToken cancellationToken);
}
