/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Extensions;
using static OpenIddict.Abstractions.OpenIddictExceptions;

namespace OpenIddict.Client;

public sealed class OpenIddictClientService
{
    private readonly IServiceProvider _provider;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientService"/> class.
    /// </summary>
    /// <param name="provider">The service provider.</param>
    public OpenIddictClientService(IServiceProvider provider)
        => _provider = provider ?? throw new ArgumentNullException(nameof(provider));

    /// <summary>
    /// Resolves the client registration associated with the specified <paramref name="issuer"/>.
    /// </summary>
    /// <param name="issuer">The issuer.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The <see cref="OpenIddictClientRegistration"/> associated with the specified <paramref name="issuer"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="issuer"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">
    /// No <see cref="OpenIddictClientRegistration"/> was registered with the specified <paramref name="issuer"/>.
    /// </exception>
    public ValueTask<OpenIddictClientRegistration> GetClientRegistrationAsync(
        Uri issuer, CancellationToken cancellationToken = default)
    {
        if (issuer is null)
        {
            throw new ArgumentNullException(nameof(issuer));
        }

        if (cancellationToken.IsCancellationRequested)
        {
            return new(Task.FromCanceled<OpenIddictClientRegistration>(cancellationToken));
        }

        var options = _provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>();

        return new(options.CurrentValue.Registrations.Find(registration => registration.Issuer == issuer) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0292)));
    }

    /// <summary>
    /// Resolves the client registration associated with the specified <paramref name="provider"/>.
    /// </summary>
    /// <param name="provider">The provider name.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The <see cref="OpenIddictClientRegistration"/> associated with the specified <paramref name="provider"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="provider"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">
    /// No <see cref="OpenIddictClientRegistration"/> was registered with the specified <paramref name="provider"/>.
    /// </exception>
    public ValueTask<OpenIddictClientRegistration> GetClientRegistrationAsync(
        string provider, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(provider))
        {
            throw new ArgumentException(SR.FormatID0366(nameof(provider)), nameof(provider));
        }

        if (cancellationToken.IsCancellationRequested)
        {
            return new(Task.FromCanceled<OpenIddictClientRegistration>(cancellationToken));
        }

        var options = _provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>();

        return new(options.CurrentValue.Registrations.Find(registration => string.Equals(
            registration.ProviderName, provider, StringComparison.Ordinal)) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0397)));
    }

    /// <summary>
    /// Resolves the server configuration associated with the specified <paramref name="issuer"/>.
    /// </summary>
    /// <param name="issuer">The issuer.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The <see cref="OpenIddictConfiguration"/> associated with the specified <paramref name="issuer"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="issuer"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">
    /// No <see cref="OpenIddictClientRegistration"/> was registered with the specified <paramref name="issuer"/>.
    /// </exception>
    public async ValueTask<OpenIddictConfiguration> GetServerConfigurationAsync(
        Uri issuer, CancellationToken cancellationToken = default)
    {
        if (issuer is null)
        {
            throw new ArgumentNullException(nameof(issuer));
        }

        var registration = await GetClientRegistrationAsync(issuer, cancellationToken);
        return await registration.ConfigurationManager
            .GetConfigurationAsync(cancellationToken)
            .WaitAsync(cancellationToken) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0140));
    }

    /// <summary>
    /// Resolves the server configuration associated with the specified <paramref name="provider"/>.
    /// </summary>
    /// <param name="provider">The provider name.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The <see cref="OpenIddictConfiguration"/> associated with the specified <paramref name="provider"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="provider"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">
    /// No <see cref="OpenIddictClientRegistration"/> was registered with the specified <paramref name="provider"/>.
    /// </exception>
    public async ValueTask<OpenIddictConfiguration> GetServerConfigurationAsync(
        string provider, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(provider))
        {
            throw new ArgumentException(SR.FormatID0366(nameof(provider)), nameof(provider));
        }

        var registration = await GetClientRegistrationAsync(provider, cancellationToken);
        return await registration.ConfigurationManager
            .GetConfigurationAsync(cancellationToken)
            .WaitAsync(cancellationToken) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0140));
    }

    /// <summary>
    /// Initiates an interactive user authentication demand.
    /// </summary>
    /// <param name="issuer">The issuer.</param>
    /// <param name="scopes">The scopes to request to the authorization server.</param>
    /// <param name="parameters">The additional parameters to send as part of the token request.</param>
    /// <param name="properties">The application-specific properties that will be added to the authentication context.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The response and a merged principal containing the claims extracted from the tokens and userinfo response.</returns>
    [RequiresPreviewFeatures]
    public async ValueTask<(OpenIddictResponse AuthorizationResponse, OpenIddictResponse TokenResponse, ClaimsPrincipal Principal)> AuthenticateInteractivelyAsync(
        Uri issuer, string[]? scopes = null,
        Dictionary<string, OpenIddictParameter>? parameters = null,
        Dictionary<string, string>? properties = null, CancellationToken cancellationToken = default)
    {
        if (issuer is null)
        {
            throw new ArgumentNullException(nameof(issuer));
        }

        var registration = await GetClientRegistrationAsync(issuer, cancellationToken);
        var nonce = await ChallengeInteractivelyAsync(registration, scopes, parameters, properties, cancellationToken);
        return await AuthenticateInteractivelyAsync(nonce, cancellationToken);
    }

    /// <summary>
    /// Initiates an interactive user authentication demand.
    /// </summary>
    /// <param name="provider">The name of the provider (see <see cref="OpenIddictClientRegistration.ProviderName"/>).</param>
    /// <param name="scopes">The scopes to request to the authorization server.</param>
    /// <param name="parameters">The additional parameters to send as part of the token request.</param>
    /// <param name="properties">The application-specific properties that will be added to the authentication context.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The response and a merged principal containing the claims extracted from the tokens and userinfo response.</returns>
    [RequiresPreviewFeatures]
    public async ValueTask<(OpenIddictResponse AuthorizationResponse, OpenIddictResponse TokenResponse, ClaimsPrincipal Principal)> AuthenticateInteractivelyAsync(
        string provider, string[]? scopes = null,
        Dictionary<string, OpenIddictParameter>? parameters = null,
        Dictionary<string, string>? properties = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(provider))
        {
            throw new ArgumentException(SR.FormatID0366(nameof(provider)), nameof(provider));
        }

        var registration = await GetClientRegistrationAsync(provider, cancellationToken);
        var nonce = await ChallengeInteractivelyAsync(registration, scopes, parameters, properties, cancellationToken);
        return await AuthenticateInteractivelyAsync(nonce, cancellationToken);
    }

    /// <summary>
    /// Completes the interactive authentication demand corresponding to the specified nonce.
    /// </summary>
    /// <param name="nonce">The nonce obtained after a challenge operation.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The response and a merged principal containing the claims extracted from the tokens and userinfo response.</returns>
    [RequiresPreviewFeatures]
    private async ValueTask<(OpenIddictResponse AuthorizationResponse, OpenIddictResponse TokenResponse, ClaimsPrincipal Principal)> AuthenticateInteractivelyAsync(
        string nonce, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // Note: this service is registered as a singleton service. As such, it cannot
        // directly depend on scoped services like the validation provider. To work around
        // this limitation, a scope is manually created for each method to this service.
        var scope = _provider.CreateScope();

        // Note: a try/finally block is deliberately used here to ensure the service scope
        // can be disposed of asynchronously if it implements IAsyncDisposable.
        try
        {
            var dispatcher = scope.ServiceProvider.GetRequiredService<IOpenIddictClientDispatcher>();
            var factory = scope.ServiceProvider.GetRequiredService<IOpenIddictClientFactory>();

            var transaction = await factory.CreateTransactionAsync();

            var context = new ProcessAuthenticationContext(transaction)
            {
                CancellationToken = cancellationToken,
                Nonce = nonce
            };

            await dispatcher.DispatchAsync(context);

            if (context.IsRejected)
            {
                throw new ProtocolException(
                    message: SR.GetResourceString(SR.ID0374),
                    context.Error, context.ErrorDescription, context.ErrorUri);
            }

            else
            {
                Debug.Assert(context.Issuer is { IsAbsoluteUri: true }, SR.GetResourceString(SR.ID4013));

                var principal = OpenIddictHelpers.CreateMergedPrincipal(
                    context.FrontchannelIdentityTokenPrincipal,
                    context.BackchannelIdentityTokenPrincipal,
                    context.UserinfoTokenPrincipal) ?? new ClaimsPrincipal(new ClaimsIdentity());

                // Attach the identity of the authorization server to the returned principal to allow resolving it even if no other
                // claim was added to the principal (e.g when no id_token was returned and no userinfo endpoint is available).
                principal.SetClaim(Claims.AuthorizationServer, context.Issuer.AbsoluteUri)
                         .SetClaim(Claims.Private.ProviderName, context.Registration.ProviderName);

                return (
                    AuthorizationResponse: context.Request is not null ? new(context.Request.GetParameters()) : new(),
                    TokenResponse        : context.TokenResponse ?? new(),
                    Principal            : principal);
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

    /// <summary>
    /// Initiates an interactive user authentication demand.
    /// </summary>
    /// <param name="registration">The client registration.</param>
    /// <param name="scopes">The scopes to request to the authorization server.</param>
    /// <param name="parameters">The additional parameters to send as part of the token request.</param>
    /// <param name="properties">The application-specific properties that will be added to the authentication context.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The response and a merged principal containing the claims extracted from the tokens and userinfo response.</returns>
    [RequiresPreviewFeatures]
    private async ValueTask<string> ChallengeInteractivelyAsync(
        OpenIddictClientRegistration registration, string[]? scopes = null,
        Dictionary<string, OpenIddictParameter>? parameters = null,
        Dictionary<string, string>? properties = null, CancellationToken cancellationToken = default)
    {
        if (registration is null)
        {
            throw new ArgumentNullException(nameof(registration));
        }

        if (scopes is not null && Array.Exists(scopes, string.IsNullOrEmpty))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0074), nameof(scopes));
        }

        var configuration = await registration.ConfigurationManager
            .GetConfigurationAsync(cancellationToken)
            .WaitAsync(cancellationToken) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0140));

        cancellationToken.ThrowIfCancellationRequested();

        // Note: this service is registered as a singleton service. As such, it cannot
        // directly depend on scoped services like the validation provider. To work around
        // this limitation, a scope is manually created for each method to this service.
        var scope = _provider.CreateScope();

        // Note: a try/finally block is deliberately used here to ensure the service scope
        // can be disposed of asynchronously if it implements IAsyncDisposable.
        try
        {
            var dispatcher = scope.ServiceProvider.GetRequiredService<IOpenIddictClientDispatcher>();
            var factory = scope.ServiceProvider.GetRequiredService<IOpenIddictClientFactory>();

            var transaction = await factory.CreateTransactionAsync();

            var context = new ProcessChallengeContext(transaction)
            {
                CancellationToken = cancellationToken,
                Configuration = configuration,
                Issuer = registration.Issuer,
                Principal = new ClaimsPrincipal(new ClaimsIdentity()),
                Registration = registration,
                Request = parameters is not null ? new(parameters) : new(),
            };

            if (scopes is { Length: > 0 })
            {
                context.Scopes.UnionWith(scopes);
            }

            if (properties is { Count: > 0 })
            {
                foreach (var property in properties)
                {
                    context.Properties[property.Key] = property.Value;
                }
            }

            await dispatcher.DispatchAsync(context);

            if (context.IsRejected)
            {
                throw new ProtocolException(
                    message: SR.GetResourceString(SR.ID0374),
                    context.Error, context.ErrorDescription, context.ErrorUri);
            }

            if (string.IsNullOrEmpty(context.Nonce))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0352));
            }

            return context.Nonce;
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

    /// <summary>
    /// Authenticates using the client credentials grant and resolves the corresponding tokens.
    /// </summary>
    /// <param name="issuer">The issuer.</param>
    /// <param name="scopes">The scopes to request to the authorization server.</param>
    /// <param name="parameters">The additional parameters to send as part of the token request.</param>
    /// <param name="properties">The application-specific properties that will be added to the authentication context.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The response and a merged principal containing the claims extracted from the tokens and userinfo response.</returns>
    public async ValueTask<(OpenIddictResponse Response, ClaimsPrincipal Principal)> AuthenticateWithClientCredentialsAsync(
        Uri issuer, string[]? scopes = null,
        Dictionary<string, OpenIddictParameter>? parameters = null,
        Dictionary<string, string>? properties = null, CancellationToken cancellationToken = default)
    {
        if (issuer is null)
        {
            throw new ArgumentNullException(nameof(issuer));
        }

        var registration = await GetClientRegistrationAsync(issuer, cancellationToken);
        return await AuthenticateWithClientCredentialsAsync(registration, scopes, parameters, properties, cancellationToken);
    }

    /// <summary>
    /// Authenticates using the client credentials grant and resolves the corresponding tokens.
    /// </summary>
    /// <param name="provider">The name of the provider (see <see cref="OpenIddictClientRegistration.ProviderName"/>).</param>
    /// <param name="scopes">The scopes to request to the authorization server.</param>
    /// <param name="parameters">The additional parameters to send as part of the token request.</param>
    /// <param name="properties">The application-specific properties that will be added to the authentication context.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The response and a merged principal containing the claims extracted from the tokens and userinfo response.</returns>
    public async ValueTask<(OpenIddictResponse Response, ClaimsPrincipal Principal)> AuthenticateWithClientCredentialsAsync(
        string provider, string[]? scopes = null,
        Dictionary<string, OpenIddictParameter>? parameters = null,
        Dictionary<string, string>? properties = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(provider))
        {
            throw new ArgumentException(SR.FormatID0366(nameof(provider)), nameof(provider));
        }

        var registration = await GetClientRegistrationAsync(provider, cancellationToken);
        return await AuthenticateWithClientCredentialsAsync(registration, scopes, parameters, properties, cancellationToken);
    }

    /// <summary>
    /// Authenticates using the client credentials grant and resolves the corresponding tokens.
    /// </summary>
    /// <param name="registration">The client registration.</param>
    /// <param name="scopes">The scopes to request to the authorization server.</param>
    /// <param name="parameters">The additional parameters to send as part of the token request.</param>
    /// <param name="properties">The application-specific properties that will be added to the authentication context.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The response and a merged principal containing the claims extracted from the tokens and userinfo response.</returns>
    private async ValueTask<(OpenIddictResponse Response, ClaimsPrincipal Principal)> AuthenticateWithClientCredentialsAsync(
        OpenIddictClientRegistration registration, string[]? scopes = null,
        Dictionary<string, OpenIddictParameter>? parameters = null,
        Dictionary<string, string>? properties = null, CancellationToken cancellationToken = default)
    {
        if (registration is null)
        {
            throw new ArgumentNullException(nameof(registration));
        }

        if (scopes is not null && Array.Exists(scopes, string.IsNullOrEmpty))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0074), nameof(scopes));
        }

        var configuration = await registration.ConfigurationManager
            .GetConfigurationAsync(cancellationToken)
            .WaitAsync(cancellationToken) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0140));

        if (configuration.TokenEndpoint is not { IsAbsoluteUri: true } uri || !uri.IsWellFormedOriginalString())
        {
            throw new InvalidOperationException(SR.FormatID0301(Metadata.TokenEndpoint));
        }

        cancellationToken.ThrowIfCancellationRequested();

        // Note: this service is registered as a singleton service. As such, it cannot
        // directly depend on scoped services like the validation provider. To work around
        // this limitation, a scope is manually created for each method to this service.
        var scope = _provider.CreateScope();

        // Note: a try/finally block is deliberately used here to ensure the service scope
        // can be disposed of asynchronously if it implements IAsyncDisposable.
        try
        {
            var dispatcher = scope.ServiceProvider.GetRequiredService<IOpenIddictClientDispatcher>();
            var factory = scope.ServiceProvider.GetRequiredService<IOpenIddictClientFactory>();
            var transaction = await factory.CreateTransactionAsync();

            var context = new ProcessAuthenticationContext(transaction)
            {
                CancellationToken = cancellationToken,
                Configuration = configuration,
                GrantType = GrantTypes.ClientCredentials,
                Issuer = registration.Issuer,
                Registration = registration,
                TokenEndpoint = uri,
                TokenRequest = parameters is not null ? new(parameters) : null,
            };

            if (scopes is { Length: > 0 })
            {
                context.Scopes.UnionWith(scopes);
            }

            if (properties is { Count: > 0 })
            {
                foreach (var property in properties)
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

            Debug.Assert(context.TokenResponse is not null, SR.GetResourceString(SR.ID4007));

            // Create a composite principal containing claims resolved from the
            // backchannel identity token and the userinfo token, if available.
            return (context.TokenResponse, OpenIddictHelpers.CreateMergedPrincipal(
                context.BackchannelIdentityTokenPrincipal,
                context.UserinfoTokenPrincipal));
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

    /// <summary>
    /// Authenticates using the specified device authorization code and resolves the corresponding tokens.
    /// </summary>
    /// <param name="issuer">The issuer.</param>
    /// <param name="code">The device authorization code returned by the server during the challenge process.</param>
    /// <param name="interval">The interval at which the token requests are sent (by default, 5 seconds).</param>
    /// <param name="parameters">The additional parameters to send as part of the token request.</param>
    /// <param name="properties">The application-specific properties that will be added to the authentication context.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The response and a merged principal containing the claims extracted from the tokens and userinfo response.</returns>
    [RequiresPreviewFeatures]
    public async ValueTask<(OpenIddictResponse TokenResponse, ClaimsPrincipal Principal)> AuthenticateWithDeviceAsync(
        Uri issuer, string code, TimeSpan? interval = null,
        Dictionary<string, OpenIddictParameter>? parameters = null,
        Dictionary<string, string>? properties = null, CancellationToken cancellationToken = default)
    {
        if (issuer is null)
        {
            throw new ArgumentNullException(nameof(issuer));
        }

        var registration = await GetClientRegistrationAsync(issuer, cancellationToken);

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                return await AuthenticateWithDeviceAsync(registration, code, parameters, properties, cancellationToken);
            }

            catch (ProtocolException exception) when (exception.Error is Errors.AuthorizationPending)
            {
                // Default to a standard 5-second interval if no explicit value was configured.
                // See https://www.rfc-editor.org/rfc/rfc8628#section-3.5 for more information.
                await Task.Delay(interval ?? TimeSpan.FromSeconds(5), cancellationToken);
            }

            catch (ProtocolException exception) when (exception.Error is Errors.SlowDown)
            {
                // When the error indicates that token requests are sent too frequently,
                // slow down the token redeeming process by increasing the interval.
                //
                // See https://www.rfc-editor.org/rfc/rfc8628#section-3.5 for more information.
                interval = (interval ?? TimeSpan.FromSeconds(5)) + TimeSpan.FromSeconds(5);

                await Task.Delay(interval.GetValueOrDefault(), cancellationToken);
            }
        }
    }

    /// <summary>
    /// Authenticates using the specified device authorization code and resolves the corresponding tokens.
    /// </summary>
    /// <param name="provider">The name of the provider (see <see cref="OpenIddictClientRegistration.ProviderName"/>).</param>
    /// <param name="code">The device authorization code returned by the server during the challenge process.</param>
    /// <param name="interval">The interval at which the token requests are sent (by default, 5 seconds).</param>
    /// <param name="parameters">The additional parameters to send as part of the token request.</param>
    /// <param name="properties">The application-specific properties that will be added to the authentication context.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The response and a merged principal containing the claims extracted from the tokens and userinfo response.</returns>
    [RequiresPreviewFeatures]
    public async ValueTask<(OpenIddictResponse TokenResponse, ClaimsPrincipal Principal)> AuthenticateWithDeviceAsync(
        string provider, string code, TimeSpan? interval = null,
        Dictionary<string, OpenIddictParameter>? parameters = null,
        Dictionary<string, string>? properties = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(provider))
        {
            throw new ArgumentException(SR.FormatID0366(nameof(provider)), nameof(provider));
        }

        var registration = await GetClientRegistrationAsync(provider, cancellationToken);

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                return await AuthenticateWithDeviceAsync(registration, code, parameters, properties, cancellationToken);
            }

            catch (ProtocolException exception) when (exception.Error is Errors.AuthorizationPending)
            {
                // Default to a standard 5-second interval if no explicit value was configured.
                // See https://www.rfc-editor.org/rfc/rfc8628#section-3.5 for more information.
                await Task.Delay(interval ?? TimeSpan.FromSeconds(5), cancellationToken);
            }

            catch (ProtocolException exception) when (exception.Error is Errors.SlowDown)
            {
                // When the error indicates that token requests are sent too frequently,
                // slow down the token redeeming process by increasing the interval.
                //
                // See https://www.rfc-editor.org/rfc/rfc8628#section-3.5 for more information.
                interval = (interval ?? TimeSpan.FromSeconds(5)) + TimeSpan.FromSeconds(5);

                await Task.Delay(interval.GetValueOrDefault(), cancellationToken);
            }
        }
    }

    /// <summary>
    /// Authenticates using the specified device authorization code and resolves the corresponding tokens.
    /// </summary>
    /// <param name="registration">The client registration.</param>
    /// <param name="code">The device code obtained after a challenge operation.</param>
    /// <param name="parameters">The additional parameters to send as part of the token request.</param>
    /// <param name="properties">The application-specific properties that will be added to the authentication context.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The response and a merged principal containing the claims extracted from the tokens and userinfo response.</returns>
    [RequiresPreviewFeatures]
    private async ValueTask<(OpenIddictResponse TokenResponse, ClaimsPrincipal Principal)> AuthenticateWithDeviceAsync(
        OpenIddictClientRegistration registration, string code,
        Dictionary<string, OpenIddictParameter>? parameters = null,
        Dictionary<string, string>? properties = null, CancellationToken cancellationToken = default)
    {
        if (registration is null)
        {
            throw new ArgumentNullException(nameof(registration));
        }

        if (string.IsNullOrEmpty(code))
        {
            throw new ArgumentException(SR.FormatID0366(nameof(code)), nameof(code));
        }

        var configuration = await registration.ConfigurationManager
            .GetConfigurationAsync(cancellationToken)
            .WaitAsync(cancellationToken) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0140));

        if (configuration.TokenEndpoint is not { IsAbsoluteUri: true } uri || !uri.IsWellFormedOriginalString())
        {
            throw new InvalidOperationException(SR.FormatID0301(Metadata.TokenEndpoint));
        }

        cancellationToken.ThrowIfCancellationRequested();

        // Note: this service is registered as a singleton service. As such, it cannot
        // directly depend on scoped services like the validation provider. To work around
        // this limitation, a scope is manually created for each method to this service.
        var scope = _provider.CreateScope();

        // Note: a try/finally block is deliberately used here to ensure the service scope
        // can be disposed of asynchronously if it implements IAsyncDisposable.
        try
        {
            var dispatcher = scope.ServiceProvider.GetRequiredService<IOpenIddictClientDispatcher>();
            var factory = scope.ServiceProvider.GetRequiredService<IOpenIddictClientFactory>();

            var transaction = await factory.CreateTransactionAsync();

            var context = new ProcessAuthenticationContext(transaction)
            {
                CancellationToken = cancellationToken,
                Configuration = configuration,
                DeviceCode = code,
                GrantType = GrantTypes.DeviceCode,
                Issuer = registration.Issuer,
                TokenEndpoint = uri,
                TokenRequest = parameters is not null ? new(parameters) : null
            };

            if (properties is { Count: > 0 })
            {
                foreach (var property in properties)
                {
                    context.Properties[property.Key] = property.Value;
                }
            }

            await dispatcher.DispatchAsync(context);

            if (context.IsRejected)
            {
                throw new ProtocolException(
                    message: SR.GetResourceString(SR.ID0374),
                    context.Error, context.ErrorDescription, context.ErrorUri);
            }

            else
            {
                Debug.Assert(context.Issuer is { IsAbsoluteUri: true }, SR.GetResourceString(SR.ID4013));

                var principal = OpenIddictHelpers.CreateMergedPrincipal(
                    context.FrontchannelIdentityTokenPrincipal,
                    context.BackchannelIdentityTokenPrincipal,
                    context.UserinfoTokenPrincipal) ?? new ClaimsPrincipal(new ClaimsIdentity());

                // Attach the identity of the authorization server to the returned principal to allow resolving it even if no other
                // claim was added to the principal (e.g when no id_token was returned and no userinfo endpoint is available).
                principal.SetClaim(Claims.AuthorizationServer, context.Issuer.AbsoluteUri)
                         .SetClaim(Claims.Private.ProviderName, context.Registration.ProviderName);

                return (TokenResponse: context.TokenResponse ?? new(), Principal: principal);
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

    /// <summary>
    /// Initiates a device authorization demand.
    /// </summary>
    /// <param name="issuer">The issuer.</param>
    /// <param name="scopes">The scopes to request to the authorization server.</param>
    /// <param name="parameters">The additional parameters to send as part of the token request.</param>
    /// <param name="properties">The application-specific properties that will be added to the authentication context.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The device authorization parameters.</returns>
    [RequiresPreviewFeatures]
    public async ValueTask<(string DeviceCode, string UserCode, Uri VerificationUri, Uri? VerificationUriComplete, TimeSpan ExpiresIn, TimeSpan Interval)> ChallengeUsingDeviceAsync(
        Uri issuer, string[]? scopes = null,
        Dictionary<string, OpenIddictParameter>? parameters = null,
        Dictionary<string, string>? properties = null, CancellationToken cancellationToken = default)
    {
        if (issuer is null)
        {
            throw new ArgumentNullException(nameof(issuer));
        }

        var registration = await GetClientRegistrationAsync(issuer, cancellationToken);
        return await ChallengeUsingDeviceAsync(registration, scopes, parameters, properties, cancellationToken);
    }

    /// <summary>
    /// Initiates a device authorization demand.
    /// </summary>
    /// <param name="provider">The name of the provider (see <see cref="OpenIddictClientRegistration.ProviderName"/>).</param>
    /// <param name="scopes">The scopes to request to the authorization server.</param>
    /// <param name="parameters">The additional parameters to send as part of the token request.</param>
    /// <param name="properties">The application-specific properties that will be added to the authentication context.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The device authorization parameters.</returns>
    [RequiresPreviewFeatures]
    public async ValueTask<(string DeviceCode, string UserCode, Uri VerificationUri, Uri? VerificationUriComplete, TimeSpan ExpiresIn, TimeSpan Interval)> ChallengeUsingDeviceAsync(
        string provider, string[]? scopes = null,
        Dictionary<string, OpenIddictParameter>? parameters = null,
        Dictionary<string, string>? properties = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(provider))
        {
            throw new ArgumentException(SR.FormatID0366(nameof(provider)), nameof(provider));
        }

        var registration = await GetClientRegistrationAsync(provider, cancellationToken);
        return await ChallengeUsingDeviceAsync(registration, scopes, parameters, properties, cancellationToken);
    }

    /// <summary>
    /// Initiates a device authorization demand.
    /// </summary>
    /// <param name="registration">The client registration.</param>
    /// <param name="scopes">The scopes to request to the authorization server.</param>
    /// <param name="parameters">The additional parameters to send as part of the token request.</param>
    /// <param name="properties">The application-specific properties that will be added to the authentication context.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The device authorization parameters.</returns>
    [RequiresPreviewFeatures]
    private async ValueTask<(string DeviceCode, string UserCode, Uri VerificationUri, Uri? VerificationUriComplete, TimeSpan ExpiresIn, TimeSpan Interval)> ChallengeUsingDeviceAsync(
        OpenIddictClientRegistration registration, string[]? scopes = null,
        Dictionary<string, OpenIddictParameter>? parameters = null,
        Dictionary<string, string>? properties = null, CancellationToken cancellationToken = default)
    {
        if (registration is null)
        {
            throw new ArgumentNullException(nameof(registration));
        }

        if (scopes is not null && Array.Exists(scopes, string.IsNullOrEmpty))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0074), nameof(scopes));
        }

        var configuration = await registration.ConfigurationManager
            .GetConfigurationAsync(cancellationToken)
            .WaitAsync(cancellationToken) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0140));

        cancellationToken.ThrowIfCancellationRequested();

        // Note: this service is registered as a singleton service. As such, it cannot
        // directly depend on scoped services like the validation provider. To work around
        // this limitation, a scope is manually created for each method to this service.
        var scope = _provider.CreateScope();

        // Note: a try/finally block is deliberately used here to ensure the service scope
        // can be disposed of asynchronously if it implements IAsyncDisposable.
        try
        {
            var dispatcher = scope.ServiceProvider.GetRequiredService<IOpenIddictClientDispatcher>();
            var factory = scope.ServiceProvider.GetRequiredService<IOpenIddictClientFactory>();

            var transaction = await factory.CreateTransactionAsync();

            var context = new ProcessChallengeContext(transaction)
            {
                CancellationToken = cancellationToken,
                Configuration = configuration,
                GrantType = GrantTypes.DeviceCode,
                Issuer = registration.Issuer,
                Principal = new ClaimsPrincipal(new ClaimsIdentity()),
                Registration = registration,
                Request = parameters is not null ? new(parameters) : new(),
            };

            if (scopes is { Length: > 0 })
            {
                context.Scopes.UnionWith(scopes);
            }

            if (properties is { Count: > 0 })
            {
                foreach (var property in properties)
                {
                    context.Properties[property.Key] = property.Value;
                }
            }

            await dispatcher.DispatchAsync(context);

            if (context.IsRejected)
            {
                throw new ProtocolException(
                    message: SR.GetResourceString(SR.ID0374),
                    context.Error, context.ErrorDescription, context.ErrorUri);
            }

            return (DeviceCode: context.DeviceCode!,
                    UserCode: context.UserCode!,
                    VerificationUri: new Uri(context.DeviceAuthorizationResponse?.VerificationUri!, UriKind.Absolute),
                    VerificationUriComplete: context.DeviceAuthorizationResponse?.VerificationUriComplete
                        is string value ? new Uri(value, UriKind.Absolute) : null,
                    ExpiresIn: TimeSpan.FromSeconds((double) context.DeviceAuthorizationResponse?.ExpiresIn!),
                    Interval: TimeSpan.FromSeconds((long?) context.DeviceAuthorizationResponse[Parameters.Interval] ?? 5));
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

    /// <summary>
    /// Authenticates using the resource owner password credentials grant and resolves the corresponding tokens.
    /// </summary>
    /// <param name="issuer">The issuer.</param>
    /// <param name="username">The username to use.</param>
    /// <param name="password">The password to use.</param>
    /// <param name="scopes">The scopes to request to the authorization server.</param>
    /// <param name="parameters">The additional parameters to send as part of the token request.</param>
    /// <param name="properties">The application-specific properties that will be added to the authentication context.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The response and a merged principal containing the claims extracted from the tokens and userinfo response.</returns>
    public async ValueTask<(OpenIddictResponse Response, ClaimsPrincipal Principal)> AuthenticateWithPasswordAsync(
        Uri issuer, string username, string password, string[]? scopes = null,
        Dictionary<string, OpenIddictParameter>? parameters = null,
        Dictionary<string, string>? properties = null, CancellationToken cancellationToken = default)
    {
        if (issuer is null)
        {
            throw new ArgumentNullException(nameof(issuer));
        }

        var registration = await GetClientRegistrationAsync(issuer, cancellationToken);
        return await AuthenticateWithPasswordAsync(registration, username, password, scopes, parameters, properties, cancellationToken);
    }

    /// <summary>
    /// Authenticates using the resource owner password credentials grant and resolves the corresponding tokens.
    /// </summary>
    /// <param name="provider">The name of the provider (see <see cref="OpenIddictClientRegistration.ProviderName"/>).</param>
    /// <param name="username">The username to use.</param>
    /// <param name="password">The password to use.</param>
    /// <param name="scopes">The scopes to request to the authorization server.</param>
    /// <param name="parameters">The additional parameters to send as part of the token request.</param>
    /// <param name="properties">The application-specific properties that will be added to the authentication context.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The response and a merged principal containing the claims extracted from the tokens and userinfo response.</returns>
    public async ValueTask<(OpenIddictResponse Response, ClaimsPrincipal Principal)> AuthenticateWithPasswordAsync(
        string provider, string username, string password, string[]? scopes = null,
        Dictionary<string, OpenIddictParameter>? parameters = null,
        Dictionary<string, string>? properties = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(provider))
        {
            throw new ArgumentException(SR.FormatID0366(nameof(provider)), nameof(provider));
        }

        var registration = await GetClientRegistrationAsync(provider, cancellationToken);
        return await AuthenticateWithPasswordAsync(registration, username, password, scopes, parameters, properties, cancellationToken);
    }

    /// <summary>
    /// Authenticates using the resource owner password credentials grant and resolves the corresponding tokens.
    /// </summary>
    /// <param name="registration">The client registration.</param>
    /// <param name="username">The username to use.</param>
    /// <param name="password">The password to use.</param>
    /// <param name="scopes">The scopes to request to the authorization server.</param>
    /// <param name="parameters">The additional parameters to send as part of the token request.</param>
    /// <param name="properties">The application-specific properties that will be added to the authentication context.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The response and a merged principal containing the claims extracted from the tokens and userinfo response.</returns>
    private async ValueTask<(OpenIddictResponse Response, ClaimsPrincipal Principal)> AuthenticateWithPasswordAsync(
        OpenIddictClientRegistration registration, string username, string password, string[]? scopes = null,
        Dictionary<string, OpenIddictParameter>? parameters = null,
        Dictionary<string, string>? properties = null, CancellationToken cancellationToken = default)
    {
        if (registration is null)
        {
            throw new ArgumentNullException(nameof(registration));
        }

        if (string.IsNullOrEmpty(username))
        {
            throw new ArgumentException(SR.FormatID0366(nameof(username)), nameof(username));
        }

        if (string.IsNullOrEmpty(password))
        {
            throw new ArgumentException(SR.FormatID0366(nameof(password)), nameof(password));
        }

        if (scopes is not null && Array.Exists(scopes, string.IsNullOrEmpty))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0074), nameof(scopes));
        }

        var configuration = await registration.ConfigurationManager
            .GetConfigurationAsync(cancellationToken)
            .WaitAsync(cancellationToken) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0140));

        if (configuration.TokenEndpoint is not { IsAbsoluteUri: true } uri || !uri.IsWellFormedOriginalString())
        {
            throw new InvalidOperationException(SR.FormatID0301(Metadata.TokenEndpoint));
        }

        cancellationToken.ThrowIfCancellationRequested();

        // Note: this service is registered as a singleton service. As such, it cannot
        // directly depend on scoped services like the validation provider. To work around
        // this limitation, a scope is manually created for each method to this service.
        var scope = _provider.CreateScope();

        // Note: a try/finally block is deliberately used here to ensure the service scope
        // can be disposed of asynchronously if it implements IAsyncDisposable.
        try
        {
            var dispatcher = scope.ServiceProvider.GetRequiredService<IOpenIddictClientDispatcher>();
            var factory = scope.ServiceProvider.GetRequiredService<IOpenIddictClientFactory>();
            var transaction = await factory.CreateTransactionAsync();

            var context = new ProcessAuthenticationContext(transaction)
            {
                CancellationToken = cancellationToken,
                Configuration = configuration,
                GrantType = GrantTypes.Password,
                Issuer = registration.Issuer,
                Password = password,
                Registration = registration,
                TokenEndpoint = uri,
                TokenRequest = parameters is not null ? new(parameters) : null,
                Username = username
            };

            if (scopes is { Length: > 0 })
            {
                context.Scopes.UnionWith(scopes);
            }

            if (properties is { Count: > 0 })
            {
                foreach (var property in properties)
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

            Debug.Assert(context.TokenResponse is not null, SR.GetResourceString(SR.ID4007));

            // Create a composite principal containing claims resolved from the
            // backchannel identity token and the userinfo token, if available.
            return (context.TokenResponse, OpenIddictHelpers.CreateMergedPrincipal(
                context.BackchannelIdentityTokenPrincipal,
                context.UserinfoTokenPrincipal));
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

    /// <summary>
    /// Authenticates using the specified refresh token and resolves the corresponding tokens.
    /// </summary>
    /// <param name="issuer">The issuer.</param>
    /// <param name="token">The refresh token to use.</param>
    /// <param name="scopes">The scopes to request to the authorization server.</param>
    /// <param name="parameters">The additional parameters to send as part of the token request.</param>
    /// <param name="properties">The application-specific properties that will be added to the authentication context.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The response and a merged principal containing the claims extracted from the tokens and userinfo response.</returns>
    public async ValueTask<(OpenIddictResponse Response, ClaimsPrincipal Principal)> AuthenticateWithRefreshTokenAsync(
        Uri issuer, string token, string[]? scopes = null,
        Dictionary<string, OpenIddictParameter>? parameters = null,
        Dictionary<string, string>? properties = null, CancellationToken cancellationToken = default)
    {
        if (issuer is null)
        {
            throw new ArgumentNullException(nameof(issuer));
        }

        var registration = await GetClientRegistrationAsync(issuer, cancellationToken);
        return await AuthenticateWithRefreshTokenAsync(registration, token, scopes, parameters, properties, cancellationToken);
    }

    /// <summary>
    /// Authenticates using the specified refresh token and resolves the corresponding tokens.
    /// </summary>
    /// <param name="provider">The name of the provider (see <see cref="OpenIddictClientRegistration.ProviderName"/>).</param>
    /// <param name="token">The refresh token to use.</param>
    /// <param name="scopes">The scopes to request to the authorization server.</param>
    /// <param name="parameters">The additional parameters to send as part of the token request.</param>
    /// <param name="properties">The application-specific properties that will be added to the authentication context.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The response and a merged principal containing the claims extracted from the tokens and userinfo response.</returns>
    public async ValueTask<(OpenIddictResponse Response, ClaimsPrincipal Principal)> AuthenticateWithRefreshTokenAsync(
        string provider, string token, string[]? scopes = null,
        Dictionary<string, OpenIddictParameter>? parameters = null,
        Dictionary<string, string>? properties = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(provider))
        {
            throw new ArgumentException(SR.FormatID0366(nameof(provider)), nameof(provider));
        }

        var registration = await GetClientRegistrationAsync(provider, cancellationToken);
        return await AuthenticateWithRefreshTokenAsync(registration, token, scopes, parameters, properties, cancellationToken);
    }

    /// <summary>
    /// Authenticates using the specified refresh token and resolves the corresponding tokens.
    /// </summary>
    /// <param name="registration">The client registration.</param>
    /// <param name="token">The refresh token to use.</param>
    /// <param name="scopes">The scopes to request to the authorization server.</param>
    /// <param name="parameters">The additional parameters to send as part of the token request.</param>
    /// <param name="properties">The application-specific properties that will be added to the authentication context.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The response and a merged principal containing the claims extracted from the tokens and userinfo response.</returns>
    private async ValueTask<(OpenIddictResponse Response, ClaimsPrincipal Principal)> AuthenticateWithRefreshTokenAsync(
        OpenIddictClientRegistration registration, string token, string[]? scopes = null,
        Dictionary<string, OpenIddictParameter>? parameters = null,
        Dictionary<string, string>? properties = null, CancellationToken cancellationToken = default)
    {
        if (registration is null)
        {
            throw new ArgumentNullException(nameof(registration));
        }

        if (string.IsNullOrEmpty(token))
        {
            throw new ArgumentException(SR.FormatID0366(nameof(token)), nameof(token));
        }

        if (scopes is not null && Array.Exists(scopes, string.IsNullOrEmpty))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0074), nameof(scopes));
        }

        var configuration = await registration.ConfigurationManager
            .GetConfigurationAsync(cancellationToken)
            .WaitAsync(cancellationToken) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0140));

        if (configuration.TokenEndpoint is not { IsAbsoluteUri: true } uri || !uri.IsWellFormedOriginalString())
        {
            throw new InvalidOperationException(SR.FormatID0301(Metadata.TokenEndpoint));
        }

        cancellationToken.ThrowIfCancellationRequested();

        // Note: this service is registered as a singleton service. As such, it cannot
        // directly depend on scoped services like the validation provider. To work around
        // this limitation, a scope is manually created for each method to this service.
        var scope = _provider.CreateScope();

        // Note: a try/finally block is deliberately used here to ensure the service scope
        // can be disposed of asynchronously if it implements IAsyncDisposable.
        try
        {
            var dispatcher = scope.ServiceProvider.GetRequiredService<IOpenIddictClientDispatcher>();
            var factory = scope.ServiceProvider.GetRequiredService<IOpenIddictClientFactory>();
            var transaction = await factory.CreateTransactionAsync();

            var context = new ProcessAuthenticationContext(transaction)
            {
                CancellationToken = cancellationToken,
                Configuration = configuration,
                GrantType = GrantTypes.RefreshToken,
                Issuer = registration.Issuer,
                RefreshToken = token,
                Registration = registration,
                TokenEndpoint = uri,
                TokenRequest = parameters is not null ? new(parameters) : null,
            };

            if (scopes is { Length: > 0 })
            {
                context.Scopes.UnionWith(scopes);
            }

            if (properties is { Count: > 0 })
            {
                foreach (var property in properties)
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

            Debug.Assert(context.TokenResponse is not null, SR.GetResourceString(SR.ID4007));

            // Create a composite principal containing claims resolved from the
            // backchannel identity token and the userinfo token, if available.
            return (context.TokenResponse, OpenIddictHelpers.CreateMergedPrincipal(
                context.BackchannelIdentityTokenPrincipal,
                context.UserinfoTokenPrincipal));
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

    /// <summary>
    /// Retrieves the OpenID Connect server configuration from the specified uri.
    /// </summary>
    /// <param name="registration">The client registration.</param>
    /// <param name="uri">The uri of the remote metadata endpoint.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The OpenID Connect server configuration retrieved from the remote server.</returns>
    internal async ValueTask<OpenIddictConfiguration> GetConfigurationAsync(
        OpenIddictClientRegistration registration, Uri uri, CancellationToken cancellationToken = default)
    {
        if (registration is null)
        {
            throw new ArgumentNullException(nameof(uri));
        }

        if (uri is null)
        {
            throw new ArgumentNullException(nameof(uri));
        }

        if (!uri.IsAbsoluteUri || !uri.IsWellFormedOriginalString())
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0144), nameof(uri));
        }

        cancellationToken.ThrowIfCancellationRequested();

        // Note: this service is registered as a singleton service. As such, it cannot
        // directly depend on scoped services like the validation provider. To work around
        // this limitation, a scope is manually created for each method to this service.
        var scope = _provider.CreateScope();

        // Note: a try/finally block is deliberately used here to ensure the service scope
        // can be disposed of asynchronously if it implements IAsyncDisposable.
        try
        {
            var dispatcher = scope.ServiceProvider.GetRequiredService<IOpenIddictClientDispatcher>();
            var factory = scope.ServiceProvider.GetRequiredService<IOpenIddictClientFactory>();
            var transaction = await factory.CreateTransactionAsync();

            var request = new OpenIddictRequest();
            request = await PrepareConfigurationRequestAsync();
            request = await ApplyConfigurationRequestAsync();
            var response = await ExtractConfigurationResponseAsync();

            return await HandleConfigurationResponseAsync() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0145));

            async ValueTask<OpenIddictRequest> PrepareConfigurationRequestAsync()
            {
                var context = new PrepareConfigurationRequestContext(transaction)
                {
                    CancellationToken = cancellationToken,
                    RemoteUri = uri,
                    Registration = registration,
                    Request = request
                };

                await dispatcher.DispatchAsync(context);

                if (context.IsRejected)
                {
                    throw new ProtocolException(
                        SR.FormatID0148(context.Error, context.ErrorDescription, context.ErrorUri),
                        context.Error, context.ErrorDescription, context.ErrorUri);
                }

                return context.Request;
            }

            async ValueTask<OpenIddictRequest> ApplyConfigurationRequestAsync()
            {
                var context = new ApplyConfigurationRequestContext(transaction)
                {
                    CancellationToken = cancellationToken,
                    RemoteUri = uri,
                    Registration = registration,
                    Request = request
                };

                await dispatcher.DispatchAsync(context);

                if (context.IsRejected)
                {
                    throw new ProtocolException(
                        SR.FormatID0149(context.Error, context.ErrorDescription, context.ErrorUri),
                        context.Error, context.ErrorDescription, context.ErrorUri);
                }

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6186), context.RemoteUri, context.Request);

                return context.Request;
            }

            async ValueTask<OpenIddictResponse> ExtractConfigurationResponseAsync()
            {
                var context = new ExtractConfigurationResponseContext(transaction)
                {
                    CancellationToken = cancellationToken,
                    RemoteUri = uri,
                    Registration = registration,
                    Request = request
                };

                await dispatcher.DispatchAsync(context);

                if (context.IsRejected)
                {
                    throw new ProtocolException(
                        SR.FormatID0150(context.Error, context.ErrorDescription, context.ErrorUri),
                        context.Error, context.ErrorDescription, context.ErrorUri);
                }

                Debug.Assert(context.Response is not null, SR.GetResourceString(SR.ID4007));

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6187), context.RemoteUri, context.Response);

                return context.Response;
            }

            async ValueTask<OpenIddictConfiguration> HandleConfigurationResponseAsync()
            {
                var context = new HandleConfigurationResponseContext(transaction)
                {
                    CancellationToken = cancellationToken,
                    RemoteUri = uri,
                    Registration = registration,
                    Request = request,
                    Response = response
                };

                await dispatcher.DispatchAsync(context);

                if (context.IsRejected)
                {
                    throw new ProtocolException(
                        SR.FormatID0151(context.Error, context.ErrorDescription, context.ErrorUri),
                        context.Error, context.ErrorDescription, context.ErrorUri);
                }

                return context.Configuration;
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

    /// <summary>
    /// Retrieves the security keys exposed by the specified JWKS endpoint.
    /// </summary>
    /// <param name="registration">The client registration.</param>
    /// <param name="uri">The uri of the remote metadata endpoint.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The security keys retrieved from the remote server.</returns>
    internal async ValueTask<JsonWebKeySet> GetSecurityKeysAsync(
        OpenIddictClientRegistration registration, Uri uri, CancellationToken cancellationToken = default)
    {
        if (registration is null)
        {
            throw new ArgumentNullException(nameof(registration));
        }

        if (uri is null)
        {
            throw new ArgumentNullException(nameof(uri));
        }

        if (!uri.IsAbsoluteUri || !uri.IsWellFormedOriginalString())
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0144), nameof(uri));
        }

        cancellationToken.ThrowIfCancellationRequested();

        // Note: this service is registered as a singleton service. As such, it cannot
        // directly depend on scoped services like the validation provider. To work around
        // this limitation, a scope is manually created for each method to this service.
        var scope = _provider.CreateScope();

        // Note: a try/finally block is deliberately used here to ensure the service scope
        // can be disposed of asynchronously if it implements IAsyncDisposable.
        try
        {
            var dispatcher = scope.ServiceProvider.GetRequiredService<IOpenIddictClientDispatcher>();
            var factory = scope.ServiceProvider.GetRequiredService<IOpenIddictClientFactory>();
            var transaction = await factory.CreateTransactionAsync();

            var request = new OpenIddictRequest();
            request = await PrepareCryptographyRequestAsync();
            request = await ApplyCryptographyRequestAsync();

            var response = await ExtractCryptographyResponseAsync();

            return await HandleCryptographyResponseAsync() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0147));

            async ValueTask<OpenIddictRequest> PrepareCryptographyRequestAsync()
            {
                var context = new PrepareCryptographyRequestContext(transaction)
                {
                    CancellationToken = cancellationToken,
                    RemoteUri = uri,
                    Registration = registration,
                    Request = request
                };

                await dispatcher.DispatchAsync(context);

                if (context.IsRejected)
                {
                    throw new ProtocolException(
                        SR.FormatID0152(context.Error, context.ErrorDescription, context.ErrorUri),
                        context.Error, context.ErrorDescription, context.ErrorUri);
                }

                return context.Request;
            }

            async ValueTask<OpenIddictRequest> ApplyCryptographyRequestAsync()
            {
                var context = new ApplyCryptographyRequestContext(transaction)
                {
                    CancellationToken = cancellationToken,
                    RemoteUri = uri,
                    Registration = registration,
                    Request = request
                };

                await dispatcher.DispatchAsync(context);

                if (context.IsRejected)
                {
                    throw new ProtocolException(
                        SR.FormatID0153(context.Error, context.ErrorDescription, context.ErrorUri),
                        context.Error, context.ErrorDescription, context.ErrorUri);
                }

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6188), context.RemoteUri, context.Request);

                return context.Request;
            }

            async ValueTask<OpenIddictResponse> ExtractCryptographyResponseAsync()
            {
                var context = new ExtractCryptographyResponseContext(transaction)
                {
                    CancellationToken = cancellationToken,
                    RemoteUri = uri,
                    Registration = registration,
                    Request = request
                };

                await dispatcher.DispatchAsync(context);

                if (context.IsRejected)
                {
                    throw new ProtocolException(
                        SR.FormatID0154(context.Error, context.ErrorDescription, context.ErrorUri),
                        context.Error, context.ErrorDescription, context.ErrorUri);
                }

                Debug.Assert(context.Response is not null, SR.GetResourceString(SR.ID4007));

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6189), context.RemoteUri, context.Response);

                return context.Response;
            }

            async ValueTask<JsonWebKeySet> HandleCryptographyResponseAsync()
            {
                var context = new HandleCryptographyResponseContext(transaction)
                {
                    CancellationToken = cancellationToken,
                    RemoteUri = uri,
                    Registration = registration,
                    Request = request,
                    Response = response
                };

                await dispatcher.DispatchAsync(context);

                if (context.IsRejected)
                {
                    throw new ProtocolException(
                        SR.FormatID0155(context.Error, context.ErrorDescription, context.ErrorUri),
                        context.Error, context.ErrorDescription, context.ErrorUri);
                }

                return context.SecurityKeys;
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

    /// <summary>
    /// Sends the device authorization request and retrieves the corresponding response.
    /// </summary>
    /// <param name="registration">The client registration.</param>
    /// <param name="request">The device authorization request.</param>
    /// <param name="uri">The uri of the remote device authorization endpoint.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The token response.</returns>
    internal async ValueTask<OpenIddictResponse> SendDeviceAuthorizationRequestAsync(
        OpenIddictClientRegistration registration, OpenIddictRequest request,
        Uri? uri = null, CancellationToken cancellationToken = default)
    {
        if (registration is null)
        {
            throw new ArgumentNullException(nameof(registration));
        }

        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        if (uri is null)
        {
            throw new ArgumentNullException(nameof(uri));
        }

        if (!uri.IsAbsoluteUri || !uri.IsWellFormedOriginalString())
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0144), nameof(uri));
        }

        var configuration = await registration.ConfigurationManager
            .GetConfigurationAsync(cancellationToken)
            .WaitAsync(cancellationToken) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0140));

        cancellationToken.ThrowIfCancellationRequested();

        // Note: this service is registered as a singleton service. As such, it cannot
        // directly depend on scoped services like the validation provider. To work around
        // this limitation, a scope is manually created for each method to this service.
        var scope = _provider.CreateScope();

        // Note: a try/finally block is deliberately used here to ensure the service scope
        // can be disposed of asynchronously if it implements IAsyncDisposable.
        try
        {
            var dispatcher = scope.ServiceProvider.GetRequiredService<IOpenIddictClientDispatcher>();
            var factory = scope.ServiceProvider.GetRequiredService<IOpenIddictClientFactory>();
            var transaction = await factory.CreateTransactionAsync();

            request = await PrepareDeviceAuthorizationRequestAsync();
            request = await ApplyDeviceAuthorizationRequestAsync();

            var response = await ExtractDeviceAuthorizationResponseAsync();

            return await HandleDeviceAuthorizationResponseAsync();

            async ValueTask<OpenIddictRequest> PrepareDeviceAuthorizationRequestAsync()
            {
                var context = new PrepareDeviceAuthorizationRequestContext(transaction)
                {
                    CancellationToken = cancellationToken,
                    RemoteUri = uri,
                    Configuration = configuration,
                    Registration = registration,
                    Request = request
                };

                await dispatcher.DispatchAsync(context);

                if (context.IsRejected)
                {
                    throw new ProtocolException(
                        SR.FormatID0398(context.Error, context.ErrorDescription, context.ErrorUri),
                        context.Error, context.ErrorDescription, context.ErrorUri);
                }

                return context.Request;
            }

            async ValueTask<OpenIddictRequest> ApplyDeviceAuthorizationRequestAsync()
            {
                var context = new ApplyDeviceAuthorizationRequestContext(transaction)
                {
                    CancellationToken = cancellationToken,
                    RemoteUri = uri,
                    Configuration = configuration,
                    Registration = registration,
                    Request = request
                };

                await dispatcher.DispatchAsync(context);

                if (context.IsRejected)
                {
                    throw new ProtocolException(
                        SR.FormatID0399(context.Error, context.ErrorDescription, context.ErrorUri),
                        context.Error, context.ErrorDescription, context.ErrorUri);
                }

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6217), context.RemoteUri, context.Request);

                return context.Request;
            }

            async ValueTask<OpenIddictResponse> ExtractDeviceAuthorizationResponseAsync()
            {
                var context = new ExtractDeviceAuthorizationResponseContext(transaction)
                {
                    CancellationToken = cancellationToken,
                    RemoteUri = uri,
                    Configuration = configuration,
                    Registration = registration,
                    Request = request
                };

                await dispatcher.DispatchAsync(context);

                if (context.IsRejected)
                {
                    throw new ProtocolException(
                        SR.FormatID0400(context.Error, context.ErrorDescription, context.ErrorUri),
                        context.Error, context.ErrorDescription, context.ErrorUri);
                }

                Debug.Assert(context.Response is not null, SR.GetResourceString(SR.ID4007));

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6218), context.RemoteUri, context.Response);

                return context.Response;
            }

            async ValueTask<OpenIddictResponse> HandleDeviceAuthorizationResponseAsync()
            {
                var context = new HandleDeviceAuthorizationResponseContext(transaction)
                {
                    CancellationToken = cancellationToken,
                    RemoteUri = uri,
                    Configuration = configuration,
                    Registration = registration,
                    Request = request,
                    Response = response
                };

                await dispatcher.DispatchAsync(context);

                if (context.IsRejected)
                {
                    throw new ProtocolException(
                        SR.FormatID0401(context.Error, context.ErrorDescription, context.ErrorUri),
                        context.Error, context.ErrorDescription, context.ErrorUri);
                }

                return context.Response;
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

    /// <summary>
    /// Sends the token request and retrieves the corresponding response.
    /// </summary>
    /// <param name="registration">The client registration.</param>
    /// <param name="request">The token request.</param>
    /// <param name="uri">The uri of the remote token endpoint.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The token response.</returns>
    internal async ValueTask<OpenIddictResponse> SendTokenRequestAsync(
        OpenIddictClientRegistration registration, OpenIddictRequest request,
        Uri? uri = null, CancellationToken cancellationToken = default)
    {
        if (registration is null)
        {
            throw new ArgumentNullException(nameof(registration));
        }

        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        if (uri is null)
        {
            throw new ArgumentNullException(nameof(uri));
        }

        if (!uri.IsAbsoluteUri || !uri.IsWellFormedOriginalString())
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0144), nameof(uri));
        }

        var configuration = await registration.ConfigurationManager
            .GetConfigurationAsync(cancellationToken)
            .WaitAsync(cancellationToken) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0140));

        cancellationToken.ThrowIfCancellationRequested();

        // Note: this service is registered as a singleton service. As such, it cannot
        // directly depend on scoped services like the validation provider. To work around
        // this limitation, a scope is manually created for each method to this service.
        var scope = _provider.CreateScope();

        // Note: a try/finally block is deliberately used here to ensure the service scope
        // can be disposed of asynchronously if it implements IAsyncDisposable.
        try
        {
            var dispatcher = scope.ServiceProvider.GetRequiredService<IOpenIddictClientDispatcher>();
            var factory = scope.ServiceProvider.GetRequiredService<IOpenIddictClientFactory>();
            var transaction = await factory.CreateTransactionAsync();

            request = await PrepareTokenRequestAsync();
            request = await ApplyTokenRequestAsync();

            var response = await ExtractTokenResponseAsync();

            return await HandleTokenResponseAsync();

            async ValueTask<OpenIddictRequest> PrepareTokenRequestAsync()
            {
                var context = new PrepareTokenRequestContext(transaction)
                {
                    CancellationToken = cancellationToken,
                    RemoteUri = uri,
                    Configuration = configuration,
                    Registration = registration,
                    Request = request
                };

                await dispatcher.DispatchAsync(context);

                if (context.IsRejected)
                {
                    throw new ProtocolException(
                        SR.FormatID0320(context.Error, context.ErrorDescription, context.ErrorUri),
                        context.Error, context.ErrorDescription, context.ErrorUri);
                }

                return context.Request;
            }

            async ValueTask<OpenIddictRequest> ApplyTokenRequestAsync()
            {
                var context = new ApplyTokenRequestContext(transaction)
                {
                    CancellationToken = cancellationToken,
                    RemoteUri = uri,
                    Configuration = configuration,
                    Registration = registration,
                    Request = request
                };

                await dispatcher.DispatchAsync(context);

                if (context.IsRejected)
                {
                    throw new ProtocolException(
                        SR.FormatID0321(context.Error, context.ErrorDescription, context.ErrorUri),
                        context.Error, context.ErrorDescription, context.ErrorUri);
                }

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6192), context.RemoteUri, context.Request);

                return context.Request;
            }

            async ValueTask<OpenIddictResponse> ExtractTokenResponseAsync()
            {
                var context = new ExtractTokenResponseContext(transaction)
                {
                    CancellationToken = cancellationToken,
                    RemoteUri = uri,
                    Configuration = configuration,
                    Registration = registration,
                    Request = request
                };

                await dispatcher.DispatchAsync(context);

                if (context.IsRejected)
                {
                    throw new ProtocolException(
                        SR.FormatID0322(context.Error, context.ErrorDescription, context.ErrorUri),
                        context.Error, context.ErrorDescription, context.ErrorUri);
                }

                Debug.Assert(context.Response is not null, SR.GetResourceString(SR.ID4007));

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6193), context.RemoteUri, context.Response);

                return context.Response;
            }

            async ValueTask<OpenIddictResponse> HandleTokenResponseAsync()
            {
                var context = new HandleTokenResponseContext(transaction)
                {
                    CancellationToken = cancellationToken,
                    RemoteUri = uri,
                    Configuration = configuration,
                    Registration = registration,
                    Request = request,
                    Response = response
                };

                await dispatcher.DispatchAsync(context);

                if (context.IsRejected)
                {
                    throw new ProtocolException(
                        SR.FormatID0323(context.Error, context.ErrorDescription, context.ErrorUri),
                        context.Error, context.ErrorDescription, context.ErrorUri);
                }

                return context.Response;
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

    /// <summary>
    /// Sends the userinfo request and retrieves the corresponding response.
    /// </summary>
    /// <param name="registration">The client registration.</param>
    /// <param name="request">The userinfo request.</param>
    /// <param name="uri">The uri of the remote userinfo endpoint.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The response and the principal extracted from the userinfo response or the userinfo token.</returns>
    internal async ValueTask<(OpenIddictResponse Response, (ClaimsPrincipal? Principal, string? Token))> SendUserinfoRequestAsync(
        OpenIddictClientRegistration registration, OpenIddictRequest request, Uri uri, CancellationToken cancellationToken = default)
    {
        if (registration is null)
        {
            throw new ArgumentNullException(nameof(registration));
        }

        if (uri is null)
        {
            throw new ArgumentNullException(nameof(uri));
        }

        if (!uri.IsAbsoluteUri || !uri.IsWellFormedOriginalString())
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0144), nameof(uri));
        }

        var configuration = await registration.ConfigurationManager
            .GetConfigurationAsync(cancellationToken)
            .WaitAsync(cancellationToken) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0140));

        cancellationToken.ThrowIfCancellationRequested();

        // Note: this service is registered as a singleton service. As such, it cannot
        // directly depend on scoped services like the validation provider. To work around
        // this limitation, a scope is manually created for each method to this service.
        var scope = _provider.CreateScope();

        // Note: a try/finally block is deliberately used here to ensure the service scope
        // can be disposed of asynchronously if it implements IAsyncDisposable.
        try
        {
            var dispatcher = scope.ServiceProvider.GetRequiredService<IOpenIddictClientDispatcher>();
            var factory = scope.ServiceProvider.GetRequiredService<IOpenIddictClientFactory>();
            var transaction = await factory.CreateTransactionAsync();

            request = await PrepareUserinfoRequestAsync();
            request = await ApplyUserinfoRequestAsync();

            var (response, token) = await ExtractUserinfoResponseAsync();

            return await HandleUserinfoResponseAsync();

            async ValueTask<OpenIddictRequest> PrepareUserinfoRequestAsync()
            {
                var context = new PrepareUserinfoRequestContext(transaction)
                {
                    CancellationToken = cancellationToken,
                    RemoteUri = uri,
                    Configuration = configuration,
                    Registration = registration,
                    Request = request
                };

                await dispatcher.DispatchAsync(context);

                if (context.IsRejected)
                {
                    throw new ProtocolException(
                        SR.FormatID0324(context.Error, context.ErrorDescription, context.ErrorUri),
                        context.Error, context.ErrorDescription, context.ErrorUri);
                }

                return context.Request;
            }

            async ValueTask<OpenIddictRequest> ApplyUserinfoRequestAsync()
            {
                var context = new ApplyUserinfoRequestContext(transaction)
                {
                    CancellationToken = cancellationToken,
                    RemoteUri = uri,
                    Configuration = configuration,
                    Registration = registration,
                    Request = request
                };

                await dispatcher.DispatchAsync(context);

                if (context.IsRejected)
                {
                    throw new ProtocolException(
                        SR.FormatID0325(context.Error, context.ErrorDescription, context.ErrorUri),
                        context.Error, context.ErrorDescription, context.ErrorUri);
                }

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6194), context.RemoteUri, context.Request);

                return context.Request;
            }

            async ValueTask<(OpenIddictResponse, string?)> ExtractUserinfoResponseAsync()
            {
                var context = new ExtractUserinfoResponseContext(transaction)
                {
                    CancellationToken = cancellationToken,
                    RemoteUri = uri,
                    Configuration = configuration,
                    Registration = registration,
                    Request = request
                };

                await dispatcher.DispatchAsync(context);

                if (context.IsRejected)
                {
                    throw new ProtocolException(
                        SR.FormatID0326(context.Error, context.ErrorDescription, context.ErrorUri),
                        context.Error, context.ErrorDescription, context.ErrorUri);
                }

                Debug.Assert(context.Response is not null, SR.GetResourceString(SR.ID4007));

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6195), context.RemoteUri, context.Response);

                return (context.Response, context.UserinfoToken);
            }

            async ValueTask<(OpenIddictResponse, (ClaimsPrincipal?, string?))> HandleUserinfoResponseAsync()
            {
                var context = new HandleUserinfoResponseContext(transaction)
                {
                    CancellationToken = cancellationToken,
                    RemoteUri = uri,
                    Configuration = configuration,
                    Registration = registration,
                    Request = request,
                    Response = response,
                    UserinfoToken = token
                };

                await dispatcher.DispatchAsync(context);

                if (context.IsRejected)
                {
                    throw new ProtocolException(
                        SR.FormatID0327(context.Error, context.ErrorDescription, context.ErrorUri),
                        context.Error, context.ErrorDescription, context.ErrorUri);
                }

                return (context.Response, (context.Principal, context.UserinfoToken));
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
