/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using static OpenIddict.Abstractions.OpenIddictExceptions;
using static OpenIddict.Client.OpenIddictClientModels;

namespace OpenIddict.Client;

public partial class OpenIddictClientService
{
    /// <summary>
    /// Validates the specified logout token, as defined by
    /// <see href="https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation">OpenID Connect
    /// Back-Channel Logout 1.0, section 2.6</see> (the replay protection included).
    /// </summary>
    /// <remarks>
    /// Note: this method is typically used by custom back-channel logout endpoints. Logout requests sent to the
    /// endpoints registered using <see cref="OpenIddictClientOptions.BackchannelLogoutEndpointUris"/> are
    /// automatically validated by the OpenIddict client host integrations.
    /// </remarks>
    /// <param name="request">The logout token authentication request.</param>
    /// <returns>The logout token authentication result.</returns>
    /// <exception cref="ProtocolException">The logout token is invalid.</exception>
    public async ValueTask<LogoutTokenAuthenticationResult> AuthenticateWithLogoutTokenAsync(LogoutTokenAuthenticationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (string.IsNullOrEmpty(request.LogoutToken))
        {
            throw new ArgumentException(SR.FormatID0366(nameof(request.LogoutToken)), nameof(request));
        }

        request.CancellationToken.ThrowIfCancellationRequested();

        await using var scope = _provider.CreateAsyncScope();

        var dispatcher = scope.ServiceProvider.GetRequiredService<IOpenIddictClientDispatcher>();
        var options = scope.ServiceProvider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>();

        var transaction = new OpenIddictClientTransaction
        {
            CancellationToken = request.CancellationToken,
            EndpointType = OpenIddictClientEndpointType.BackchannelLogout,
            Options = options.CurrentValue,
            ServiceProvider = scope.ServiceProvider
        };

        if (!string.IsNullOrEmpty(request.RegistrationId))
        {
            transaction.Registration = await GetClientRegistrationByIdAsync(request.RegistrationId, request.CancellationToken);
        }

        var context = new ProcessAuthenticationContext(transaction)
        {
            LogoutToken = request.LogoutToken,
            Request = new()
        };

        if (request.Properties is { Count: > 0 })
        {
            foreach (var property in request.Properties)
            {
                context.Properties[property.Key] = property.Value;
            }
        }

        await dispatcher.DispatchAsync(context);

        if (context.IsRejected)
        {
            throw new ProtocolException(
                SR.FormatID0319(context.Error, context.ErrorDescription, context.ErrorUri),
                context.Error, context.ErrorDescription, context.ErrorUri);
        }

        Debug.Assert(context.Registration.Issuer is { IsAbsoluteUri: true }, SR.GetResourceString(SR.ID4013));
        Debug.Assert(context.LogoutTokenPrincipal is not null, SR.GetResourceString(SR.ID4006));

        return new()
        {
            Issuer = context.Registration.Issuer,
            LogoutTokenPrincipal = context.LogoutTokenPrincipal,
            Principal = context.MergedPrincipal,
            Properties = context.Properties,
            Registration = context.Registration,
            SessionId = context.SessionId,
            Subject = context.Subject
        };
    }
}
