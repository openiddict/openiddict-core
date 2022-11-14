/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics;
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

        if (scopes is not null && scopes.Any(string.IsNullOrEmpty))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0074), nameof(scopes));
        }

        var options = _provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>();
        var registration = options.CurrentValue.Registrations.Find(registration => registration.Issuer == issuer) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0292));

        var configuration = await registration.ConfigurationManager.GetConfigurationAsync(default) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0140));

        if (configuration.TokenEndpoint is not { IsAbsoluteUri: true } address || !address.IsWellFormedOriginalString())
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
                Configuration = configuration,
                GrantType = GrantTypes.ClientCredentials,
                Issuer = registration.Issuer,
                Registration = registration,
                TokenEndpoint = address,
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

        if (string.IsNullOrEmpty(username))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0335), nameof(username));
        }

        if (string.IsNullOrEmpty(password))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0336), nameof(password));
        }

        if (scopes is not null && scopes.Any(string.IsNullOrEmpty))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0074), nameof(scopes));
        }

        var options = _provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>();
        var registration = options.CurrentValue.Registrations.Find(registration => registration.Issuer == issuer) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0292));

        var configuration = await registration.ConfigurationManager.GetConfigurationAsync(default) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0140));

        if (configuration.TokenEndpoint is not { IsAbsoluteUri: true } address || !address.IsWellFormedOriginalString())
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
                Configuration = configuration,
                GrantType = GrantTypes.Password,
                Issuer = registration.Issuer,
                Password = password,
                Registration = registration,
                TokenEndpoint = address,
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
    /// Authenticates using the resource owner password credentials grant and resolves the corresponding tokens.
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

        if (string.IsNullOrEmpty(token))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0156), nameof(token));
        }

        if (scopes is not null && scopes.Any(string.IsNullOrEmpty))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0074), nameof(scopes));
        }

        var options = _provider.GetRequiredService<IOptionsMonitor<OpenIddictClientOptions>>();
        var registration = options.CurrentValue.Registrations.Find(registration => registration.Issuer == issuer) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0292));

        var configuration = await registration.ConfigurationManager.GetConfigurationAsync(default) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0140));

        if (configuration.TokenEndpoint is not { IsAbsoluteUri: true } address || !address.IsWellFormedOriginalString())
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
                Configuration = configuration,
                GrantType = GrantTypes.RefreshToken,
                Issuer = registration.Issuer,
                RefreshToken = token,
                Registration = registration,
                TokenEndpoint = address,
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
    /// Retrieves the OpenID Connect server configuration from the specified address.
    /// </summary>
    /// <param name="registration">The client registration.</param>
    /// <param name="address">The address of the remote metadata endpoint.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The OpenID Connect server configuration retrieved from the remote server.</returns>
    internal async ValueTask<OpenIddictConfiguration> GetConfigurationAsync(
        OpenIddictClientRegistration registration, Uri address, CancellationToken cancellationToken = default)
    {
        if (registration is null)
        {
            throw new ArgumentNullException(nameof(address));
        }

        if (address is null)
        {
            throw new ArgumentNullException(nameof(address));
        }

        if (!address.IsAbsoluteUri || !address.IsWellFormedOriginalString())
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0144), nameof(address));
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
                    Address = address,
                    Issuer = registration.Issuer,
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
                    Address = address,
                    Issuer = registration.Issuer,
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

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6186), context.Address, context.Request);

                return context.Request;
            }

            async ValueTask<OpenIddictResponse> ExtractConfigurationResponseAsync()
            {
                var context = new ExtractConfigurationResponseContext(transaction)
                {
                    Address = address,
                    Issuer = registration.Issuer,
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

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6187), context.Address, context.Response);

                return context.Response;
            }

            async ValueTask<OpenIddictConfiguration> HandleConfigurationResponseAsync()
            {
                var context = new HandleConfigurationResponseContext(transaction)
                {
                    Address = address,
                    Issuer = registration.Issuer,
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
    /// <param name="address">The address of the remote metadata endpoint.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The security keys retrieved from the remote server.</returns>
    internal async ValueTask<JsonWebKeySet> GetSecurityKeysAsync(
        OpenIddictClientRegistration registration, Uri address, CancellationToken cancellationToken = default)
    {
        if (registration is null)
        {
            throw new ArgumentNullException(nameof(registration));
        }

        if (address is null)
        {
            throw new ArgumentNullException(nameof(address));
        }

        if (!address.IsAbsoluteUri || !address.IsWellFormedOriginalString())
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0144), nameof(address));
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
                    Address = address,
                    Issuer = registration.Issuer,
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
                    Address = address,
                    Issuer = registration.Issuer,
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

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6188), context.Address, context.Request);

                return context.Request;
            }

            async ValueTask<OpenIddictResponse> ExtractCryptographyResponseAsync()
            {
                var context = new ExtractCryptographyResponseContext(transaction)
                {
                    Address = address,
                    Issuer = registration.Issuer,
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

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6189), context.Address, context.Response);

                return context.Response;
            }

            async ValueTask<JsonWebKeySet> HandleCryptographyResponseAsync()
            {
                var context = new HandleCryptographyResponseContext(transaction)
                {
                    Address = address,
                    Issuer = registration.Issuer,
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
    /// Sends the token request and retrieves the corresponding response.
    /// </summary>
    /// <param name="registration">The client registration.</param>
    /// <param name="request">The token request.</param>
    /// <param name="address">The address of the remote token endpoint.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The token response.</returns>
    internal async ValueTask<OpenIddictResponse> SendTokenRequestAsync(
        OpenIddictClientRegistration registration, OpenIddictRequest request,
        Uri? address = null, CancellationToken cancellationToken = default)
    {
        if (registration is null)
        {
            throw new ArgumentNullException(nameof(registration));
        }

        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        if (address is null)
        {
            throw new ArgumentNullException(nameof(address));
        }

        if (!address.IsAbsoluteUri || !address.IsWellFormedOriginalString())
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0144), nameof(address));
        }

        var configuration = await registration.ConfigurationManager.GetConfigurationAsync(default) ??
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
                    Address = address,
                    Configuration = configuration,
                    Issuer = registration.Issuer,
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
                    Address = address,
                    Configuration = configuration,
                    Issuer = registration.Issuer,
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

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6192), context.Address, context.Request);

                return context.Request;
            }

            async ValueTask<OpenIddictResponse> ExtractTokenResponseAsync()
            {
                var context = new ExtractTokenResponseContext(transaction)
                {
                    Address = address,
                    Configuration = configuration,
                    Issuer = registration.Issuer,
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

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6193), context.Address, context.Response);

                return context.Response;
            }

            async ValueTask<OpenIddictResponse> HandleTokenResponseAsync()
            {
                var context = new HandleTokenResponseContext(transaction)
                {
                    Address = address,
                    Configuration = configuration,
                    Issuer = registration.Issuer,
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
    /// <param name="address">The address of the remote userinfo endpoint.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The response and the principal extracted from the userinfo response or the userinfo token.</returns>
    internal async ValueTask<(OpenIddictResponse Response, (ClaimsPrincipal? Principal, string? Token))> SendUserinfoRequestAsync(
        OpenIddictClientRegistration registration, OpenIddictRequest request, Uri address, CancellationToken cancellationToken = default)
    {
        if (registration is null)
        {
            throw new ArgumentNullException(nameof(registration));
        }

        if (address is null)
        {
            throw new ArgumentNullException(nameof(address));
        }

        if (!address.IsAbsoluteUri || !address.IsWellFormedOriginalString())
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0144), nameof(address));
        }

        var configuration = await registration.ConfigurationManager.GetConfigurationAsync(default) ??
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
                    Address = address,
                    Configuration = configuration,
                    Issuer = registration.Issuer,
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
                    Address = address,
                    Configuration = configuration,
                    Issuer = registration.Issuer,
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

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6194), context.Address, context.Request);

                return context.Request;
            }

            async ValueTask<(OpenIddictResponse, string?)> ExtractUserinfoResponseAsync()
            {
                var context = new ExtractUserinfoResponseContext(transaction)
                {
                    Address = address,
                    Configuration = configuration,
                    Issuer = registration.Issuer,
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

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6195), context.Address, context.Response);

                return (context.Response, context.UserinfoToken);
            }

            async ValueTask<(OpenIddictResponse, (ClaimsPrincipal?, string?))> HandleUserinfoResponseAsync()
            {
                var context = new HandleUserinfoResponseContext(transaction)
                {
                    Address = address,
                    Configuration = configuration,
                    Issuer = registration.Issuer,
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
