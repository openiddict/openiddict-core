/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics;
using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Validation;

public class OpenIddictValidationService
{
    private readonly IServiceProvider _provider;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictValidationService"/> class.
    /// </summary>
    /// <param name="provider">The service provider.</param>
    public OpenIddictValidationService(IServiceProvider provider!!)
        => _provider = provider;

    /// <summary>
    /// Retrieves the OpenID Connect server configuration from the specified address.
    /// </summary>
    /// <param name="address">The address of the remote metadata endpoint.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The OpenID Connect server configuration retrieved from the remote server.</returns>
    public async ValueTask<OpenIddictConfiguration> GetConfigurationAsync(Uri address!!, CancellationToken cancellationToken = default)
    {
        if (!address.IsAbsoluteUri)
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
            var dispatcher = scope.ServiceProvider.GetRequiredService<IOpenIddictValidationDispatcher>();
            var factory = scope.ServiceProvider.GetRequiredService<IOpenIddictValidationFactory>();
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
                    Request = request
                };

                await dispatcher.DispatchAsync(context);

                if (context.IsRejected)
                {
                    throw new OpenIddictExceptions.GenericException(
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
                    Request = request
                };

                await dispatcher.DispatchAsync(context);

                if (context.IsRejected)
                {
                    throw new OpenIddictExceptions.GenericException(
                        SR.FormatID0149(context.Error, context.ErrorDescription, context.ErrorUri),
                        context.Error, context.ErrorDescription, context.ErrorUri);
                }

                return context.Request;
            }

            async ValueTask<OpenIddictResponse> ExtractConfigurationResponseAsync()
            {
                var context = new ExtractConfigurationResponseContext(transaction)
                {
                    Address = address,
                    Request = request
                };

                await dispatcher.DispatchAsync(context);

                if (context.IsRejected)
                {
                    throw new OpenIddictExceptions.GenericException(
                        SR.FormatID0150(context.Error, context.ErrorDescription, context.ErrorUri),
                        context.Error, context.ErrorDescription, context.ErrorUri);
                }

                Debug.Assert(context.Response is not null, SR.GetResourceString(SR.ID4007));

                return context.Response;
            }

            async ValueTask<OpenIddictConfiguration> HandleConfigurationResponseAsync()
            {
                var context = new HandleConfigurationResponseContext(transaction)
                {
                    Address = address,
                    Request = request,
                    Response = response
                };

                await dispatcher.DispatchAsync(context);

                if (context.IsRejected)
                {
                    throw new OpenIddictExceptions.GenericException(
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
    /// <param name="address">The address of the remote metadata endpoint.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The security keys retrieved from the remote server.</returns>
    public async ValueTask<JsonWebKeySet> GetSecurityKeysAsync(Uri address!!, CancellationToken cancellationToken = default)
    {
        if (!address.IsAbsoluteUri)
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
            var dispatcher = scope.ServiceProvider.GetRequiredService<IOpenIddictValidationDispatcher>();
            var factory = scope.ServiceProvider.GetRequiredService<IOpenIddictValidationFactory>();
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
                    Request = request
                };

                await dispatcher.DispatchAsync(context);

                if (context.IsRejected)
                {
                    throw new OpenIddictExceptions.GenericException(
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
                    Request = request
                };

                await dispatcher.DispatchAsync(context);

                if (context.IsRejected)
                {
                    throw new OpenIddictExceptions.GenericException(
                        SR.FormatID0153(context.Error, context.ErrorDescription, context.ErrorUri),
                        context.Error, context.ErrorDescription, context.ErrorUri);
                }

                return context.Request;
            }

            async ValueTask<OpenIddictResponse> ExtractCryptographyResponseAsync()
            {
                var context = new ExtractCryptographyResponseContext(transaction)
                {
                    Address = address,
                    Request = request
                };

                await dispatcher.DispatchAsync(context);

                if (context.IsRejected)
                {
                    throw new OpenIddictExceptions.GenericException(
                        SR.FormatID0154(context.Error, context.ErrorDescription, context.ErrorUri),
                        context.Error, context.ErrorDescription, context.ErrorUri);
                }

                Debug.Assert(context.Response is not null, SR.GetResourceString(SR.ID4007));

                return context.Response;
            }

            async ValueTask<JsonWebKeySet> HandleCryptographyResponseAsync()
            {
                var context = new HandleCryptographyResponseContext(transaction)
                {
                    Request = request,
                    Response = response
                };

                await dispatcher.DispatchAsync(context);

                if (context.IsRejected)
                {
                    throw new OpenIddictExceptions.GenericException(
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
    /// Sends an introspection request to the specified address and returns the corresponding principal.
    /// </summary>
    /// <param name="address">The address of the remote metadata endpoint.</param>
    /// <param name="token">The token to introspect.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The claims principal created from the claim retrieved from the remote server.</returns>
    public ValueTask<ClaimsPrincipal> IntrospectTokenAsync(Uri address, string token, CancellationToken cancellationToken = default)
        => IntrospectTokenAsync(address, token, hint: null, cancellationToken);

    /// <summary>
    /// Sends an introspection request to the specified address and returns the corresponding principal.
    /// </summary>
    /// <param name="address">The address of the remote metadata endpoint.</param>
    /// <param name="token">The token to introspect.</param>
    /// <param name="hint">The token type to introspect, used as a hint by the authorization server.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The claims principal created from the claim retrieved from the remote server.</returns>
    public async ValueTask<ClaimsPrincipal> IntrospectTokenAsync(
        Uri address!!, string token, string? hint, CancellationToken cancellationToken = default)
    {
        if (!address.IsAbsoluteUri || !address.IsWellFormedOriginalString())
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0144), nameof(address));
        }

        if (string.IsNullOrEmpty(token))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0156), nameof(token));
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
            var dispatcher = scope.ServiceProvider.GetRequiredService<IOpenIddictValidationDispatcher>();
            var factory = scope.ServiceProvider.GetRequiredService<IOpenIddictValidationFactory>();
            var transaction = await factory.CreateTransactionAsync();

            var request = new OpenIddictRequest();
            request = await PrepareIntrospectionRequestAsync();
            request = await ApplyIntrospectionRequestAsync();
            var response = await ExtractIntrospectionResponseAsync();

            return await HandleIntrospectionResponseAsync() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0157));

            async ValueTask<OpenIddictRequest> PrepareIntrospectionRequestAsync()
            {
                var context = new PrepareIntrospectionRequestContext(transaction)
                {
                    Address = address,
                    Request = request,
                    Token = token,
                    TokenTypeHint = hint
                };

                await dispatcher.DispatchAsync(context);

                if (context.IsRejected)
                {
                    throw new OpenIddictExceptions.GenericException(
                        SR.FormatID0158(context.Error, context.ErrorDescription, context.ErrorUri),
                        context.Error, context.ErrorDescription, context.ErrorUri);
                }

                return context.Request;
            }

            async ValueTask<OpenIddictRequest> ApplyIntrospectionRequestAsync()
            {
                var context = new ApplyIntrospectionRequestContext(transaction)
                {
                    Address = address,
                    Request = request
                };

                await dispatcher.DispatchAsync(context);

                if (context.IsRejected)
                {
                    throw new OpenIddictExceptions.GenericException(
                        SR.FormatID0159(context.Error, context.ErrorDescription, context.ErrorUri),
                        context.Error, context.ErrorDescription, context.ErrorUri);
                }

                return context.Request;
            }

            async ValueTask<OpenIddictResponse> ExtractIntrospectionResponseAsync()
            {
                var context = new ExtractIntrospectionResponseContext(transaction)
                {
                    Address = address,
                    Request = request
                };

                await dispatcher.DispatchAsync(context);

                if (context.IsRejected)
                {
                    throw new OpenIddictExceptions.GenericException(
                        SR.FormatID0160(context.Error, context.ErrorDescription, context.ErrorUri),
                        context.Error, context.ErrorDescription, context.ErrorUri);
                }

                Debug.Assert(context.Response is not null, SR.GetResourceString(SR.ID4007));

                return context.Response;
            }

            async ValueTask<ClaimsPrincipal> HandleIntrospectionResponseAsync()
            {
                var context = new HandleIntrospectionResponseContext(transaction)
                {
                    Address = address,
                    Request = request,
                    Response = response,
                    Token = token
                };

                await dispatcher.DispatchAsync(context);

                if (context.IsRejected)
                {
                    throw new OpenIddictExceptions.GenericException(
                        SR.FormatID0161(context.Error, context.ErrorDescription, context.ErrorUri),
                        context.Error, context.ErrorDescription, context.ErrorUri);
                }

                Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

                return context.Principal;
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
    /// Validates the specified access token and returns the principal extracted from the token.
    /// </summary>
    /// <param name="token">The access token to validate.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The principal containing the claims extracted from the token.</returns>
    public async ValueTask<ClaimsPrincipal> ValidateAccessTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(token))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0162), nameof(token));
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
            var dispatcher = scope.ServiceProvider.GetRequiredService<IOpenIddictValidationDispatcher>();
            var factory = scope.ServiceProvider.GetRequiredService<IOpenIddictValidationFactory>();
            var transaction = await factory.CreateTransactionAsync();

            var context = new ValidateTokenContext(transaction)
            {
                Token = token,
                ValidTokenTypes = { TokenTypeHints.AccessToken }
            };

            await dispatcher.DispatchAsync(context);

            if (context.IsRejected)
            {
                throw new OpenIddictExceptions.GenericException(
                    SR.FormatID0163(context.Error, context.ErrorDescription, context.ErrorUri),
                    context.Error, context.ErrorDescription, context.ErrorUri);
            }

            Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            return context.Principal;
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
