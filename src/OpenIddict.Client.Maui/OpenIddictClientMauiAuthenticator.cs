/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Concurrent;
using System.Security.Claims;
using Microsoft.Extensions.Options;

namespace OpenIddict.Client.Maui;

/// <summary>
/// Contains the APIs needed to start OpenIddict-driven authentication flows.
/// </summary>
public class OpenIddictClientMauiAuthenticator : IWebAuthenticator
{
    private readonly IOptionsMonitor<OpenIddictClientMauiOptions> _options;
    private readonly IServiceProvider _provider;
    private readonly ConcurrentDictionary<string, Lazy<TaskCompletionSource<OpenIddictClientMauiAuthenticatorResult>>> _sources = new();

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientMauiAuthenticator"/> class.
    /// </summary>
    /// <param name="options">The OpenIddict client MAUI options.</param>
    /// <param name="provider">The service provider used by this instance.</param>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="provider"/> is <see langword="null"/>.</exception>
    public OpenIddictClientMauiAuthenticator(
        IOptionsMonitor<OpenIddictClientMauiOptions> options,
        IServiceProvider provider)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
    }

    /// <summary>
    /// Starts a new authentication flow and returns the tokens and claims extracted from the response.
    /// </summary>
    /// <param name="options">The authenticator options.</param>
    /// <returns>The tokens and claims extracted from the response.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is <see langword="null"/>.</exception>
    public async Task<OpenIddictClientMauiAuthenticatorResult> AuthenticateAsync(WebAuthenticatorOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        await using var scope = _provider.CreateAsyncScope();
        var dispatcher = scope.ServiceProvider.GetRequiredService<IOpenIddictClientDispatcher>();
        var factory = scope.ServiceProvider.GetRequiredService<IOpenIddictClientFactory>();

        var transaction = await factory.CreateTransactionAsync();

        var context = new ProcessChallengeContext(transaction)
        {
            Issuer = options.Url,
            RedirectUri = options.CallbackUrl?.AbsoluteUri,
            Principal = new ClaimsPrincipal(new ClaimsIdentity()),
            Request = new OpenIddictRequest()
        };

        await dispatcher.DispatchAsync(context);

        if (context.IsRejected)
        {
            await dispatcher.DispatchAsync(new ProcessErrorContext(transaction)
            {
                Error = context.Error ?? Errors.InvalidRequest,
                ErrorDescription = context.ErrorDescription,
                ErrorUri = context.ErrorUri,
                Response = new OpenIddictResponse()
            });
        }

        if (string.IsNullOrEmpty(context.RequestForgeryProtection))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0343));
        }

        // At this point, the authentication operation cannot complete until the authorization response has been
        // returned to the redirection endpoint (materialized as a registered protocol activation URI) and handled
        // by OpenIddict via the ProcessRequest event. Since it is asynchronous by nature, this process requires
        // using a signal mechanism to unblock the authentication operation once it is complete. For that, this
        // class uses a TaskCompletionSource (one per authentication demand) that will be automatically completed
        // or aborted by a specialized event handler as part of the ProcessRequest/ProcessError events processing.
        var source = _sources.GetOrAdd(context.RequestForgeryProtection, _ => new(() => new()));

        try
        {
            return await source.Value.Task.WaitAsync(_options.CurrentValue.AuthenticationTimeout);
        }

        catch (TimeoutException)
        {
            // If the operation failed due to the timeout, it's likely none of the TryAbort/TryComplete methods
            // will ever be called, so the TaskCompletionSource instance is manually removed before re-throwing.
            _sources.TryRemove(context.RequestForgeryProtection, out _);

            throw;
        }
    }

    /// <inheritdoc/>
    async Task<WebAuthenticatorResult> IWebAuthenticator.AuthenticateAsync(WebAuthenticatorOptions webAuthenticatorOptions)
        => await AuthenticateAsync(webAuthenticatorOptions);

    /// <summary>
    /// Validates the specified authentication demand.
    /// </summary>
    /// <param name="identifier">The request forgery protection claim, used as a unique identifier.</param>
    /// <returns><see langword="true"/> if the operation could be validated, <see langword="false"/> otherwise.</returns>
    internal bool TryValidate(string identifier) => _sources.ContainsKey(identifier);

    /// <summary>
    /// Tries to abort the specified authentication demand.
    /// </summary>
    /// <param name="identifier">The request forgery protection claim, used as a unique identifier.</param>
    /// <param name="exception">The exception causing the failure.</param>
    /// <returns><see langword="true"/> if the operation could be aborted, <see langword="false"/> otherwise.</returns>
    internal bool TryAbort(string identifier, Exception exception)
    {
        if (_sources.TryRemove(identifier, out Lazy<TaskCompletionSource<OpenIddictClientMauiAuthenticatorResult>>? source))
        {
            return source.Value.TrySetException(exception);
        }

        return false;
    }

    /// <summary>
    /// Tries to complete the specified authentication demand.
    /// </summary>
    /// <param name="identifier">The request forgery protection claim, used as a unique identifier.</param>
    /// <param name="result">The authentication result that will be returned to the caller.</param>
    /// <returns><see langword="true"/> if the operation could be completed, <see langword="false"/> otherwise.</returns>
    internal bool TryComplete(string identifier, OpenIddictClientMauiAuthenticatorResult result)
    {
        if (_sources.TryRemove(identifier, out Lazy<TaskCompletionSource<OpenIddictClientMauiAuthenticatorResult>>? source))
        {
            return source.Value.TrySetResult(result);
        }

        return false;
    }
}
