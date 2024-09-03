/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics;
using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Extensions;
using static OpenIddict.Abstractions.OpenIddictExceptions;

namespace OpenIddict.Validation;

/// <summary>
/// Provides high-level APIs for performing various authentication operations.
/// </summary>
public class OpenIddictValidationService
{
    private readonly IServiceProvider _provider;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictValidationService"/> class.
    /// </summary>
    /// <param name="provider">The service provider.</param>
    public OpenIddictValidationService(IServiceProvider provider)
        => _provider = provider ?? throw new ArgumentNullException(nameof(provider));

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

            var context = new ProcessAuthenticationContext(transaction)
            {
                AccessToken = token
            };

            await dispatcher.DispatchAsync(context);

            if (context.IsRejected)
            {
                throw new ProtocolException(
                    SR.FormatID0163(context.Error, context.ErrorDescription, context.ErrorUri),
                    context.Error, context.ErrorDescription, context.ErrorUri);
            }

            Debug.Assert(context.AccessTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            return context.AccessTokenPrincipal;
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
    /// Retrieves the OpenID Connect server configuration from the specified URI.
    /// </summary>
    /// <param name="uri">The URI of the remote metadata endpoint.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The OpenID Connect server configuration retrieved from the remote server.</returns>
    internal async ValueTask<OpenIddictConfiguration> GetConfigurationAsync(Uri uri, CancellationToken cancellationToken = default)
    {
        if (uri is null)
        {
            throw new ArgumentNullException(nameof(uri));
        }

        if (!uri.IsAbsoluteUri)
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
                    RemoteUri = uri,
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
                    RemoteUri = uri,
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
                    RemoteUri = uri,
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
                    RemoteUri = uri,
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
    /// Retrieves the security keys exposed by the specified JSON Web Key Set endpoint.
    /// </summary>
    /// <param name="uri">The URI of the remote metadata endpoint.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The security keys retrieved from the remote server.</returns>
    internal async ValueTask<JsonWebKeySet> GetSecurityKeysAsync(Uri uri, CancellationToken cancellationToken = default)
    {
        if (uri is null)
        {
            throw new ArgumentNullException(nameof(uri));
        }

        if (!uri.IsAbsoluteUri)
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
            var dispatcher = scope.ServiceProvider.GetRequiredService<IOpenIddictValidationDispatcher>();
            var factory = scope.ServiceProvider.GetRequiredService<IOpenIddictValidationFactory>();
            var transaction = await factory.CreateTransactionAsync();

            var request = new OpenIddictRequest();
            request = await PrepareJsonWebKeySetRequestAsync();
            request = await ApplyJsonWebKeySetRequestAsync();

            var response = await ExtractJsonWebKeySetResponseAsync();

            return await HandleJsonWebKeySetResponseAsync() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0147));

            async ValueTask<OpenIddictRequest> PrepareJsonWebKeySetRequestAsync()
            {
                var context = new PrepareJsonWebKeySetRequestContext(transaction)
                {
                    RemoteUri = uri,
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

            async ValueTask<OpenIddictRequest> ApplyJsonWebKeySetRequestAsync()
            {
                var context = new ApplyJsonWebKeySetRequestContext(transaction)
                {
                    RemoteUri = uri,
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

            async ValueTask<OpenIddictResponse> ExtractJsonWebKeySetResponseAsync()
            {
                var context = new ExtractJsonWebKeySetResponseContext(transaction)
                {
                    RemoteUri = uri,
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

            async ValueTask<JsonWebKeySet> HandleJsonWebKeySetResponseAsync()
            {
                var context = new HandleJsonWebKeySetResponseContext(transaction)
                {
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
    /// Sends the introspection request and retrieves the corresponding response.
    /// </summary>
    /// <param name="configuration">The server configuration.</param>
    /// <param name="request">The token request.</param>
    /// <param name="uri">The uri of the remote token endpoint.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The response and the principal extracted from the introspection response.</returns>
    internal async ValueTask<(OpenIddictResponse, ClaimsPrincipal)> SendIntrospectionRequestAsync(
        OpenIddictConfiguration configuration, OpenIddictRequest request,
        Uri? uri = null, CancellationToken cancellationToken = default)
    {
        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        if (uri is null)
        {
            throw new ArgumentNullException(nameof(uri));
        }

        if (!uri.IsAbsoluteUri || OpenIddictHelpers.IsImplicitFileUri(uri))
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
            var dispatcher = scope.ServiceProvider.GetRequiredService<IOpenIddictValidationDispatcher>();
            var factory = scope.ServiceProvider.GetRequiredService<IOpenIddictValidationFactory>();
            var transaction = await factory.CreateTransactionAsync();

            request = await PrepareIntrospectionRequestAsync();
            request = await ApplyIntrospectionRequestAsync();

            var response = await ExtractIntrospectionResponseAsync();

            return await HandleIntrospectionResponseAsync();

            async ValueTask<OpenIddictRequest> PrepareIntrospectionRequestAsync()
            {
                var context = new PrepareIntrospectionRequestContext(transaction)
                {
                    CancellationToken = cancellationToken,
                    RemoteUri = uri,
                    Configuration = configuration,
                    Request = request
                };

                await dispatcher.DispatchAsync(context);

                if (context.IsRejected)
                {
                    throw new ProtocolException(
                        SR.FormatID0158(context.Error, context.ErrorDescription, context.ErrorUri),
                        context.Error, context.ErrorDescription, context.ErrorUri);
                }

                return context.Request;
            }

            async ValueTask<OpenIddictRequest> ApplyIntrospectionRequestAsync()
            {
                var context = new ApplyIntrospectionRequestContext(transaction)
                {
                    CancellationToken = cancellationToken,
                    RemoteUri = uri,
                    Configuration = configuration,
                    Request = request
                };

                await dispatcher.DispatchAsync(context);

                if (context.IsRejected)
                {
                    throw new ProtocolException(
                        SR.FormatID0159(context.Error, context.ErrorDescription, context.ErrorUri),
                        context.Error, context.ErrorDescription, context.ErrorUri);
                }

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6192), context.RemoteUri, context.Request);

                return context.Request;
            }

            async ValueTask<OpenIddictResponse> ExtractIntrospectionResponseAsync()
            {
                var context = new ExtractIntrospectionResponseContext(transaction)
                {
                    CancellationToken = cancellationToken,
                    RemoteUri = uri,
                    Configuration = configuration,
                    Request = request
                };

                await dispatcher.DispatchAsync(context);

                if (context.IsRejected)
                {
                    throw new ProtocolException(
                        SR.FormatID0160(context.Error, context.ErrorDescription, context.ErrorUri),
                        context.Error, context.ErrorDescription, context.ErrorUri);
                }

                Debug.Assert(context.Response is not null, SR.GetResourceString(SR.ID4007));

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6193), context.RemoteUri, context.Response);

                return context.Response;
            }

            async ValueTask<(OpenIddictResponse, ClaimsPrincipal)> HandleIntrospectionResponseAsync()
            {
                var context = new HandleIntrospectionResponseContext(transaction)
                {
                    CancellationToken = cancellationToken,
                    RemoteUri = uri,
                    Configuration = configuration,
                    Request = request,
                    Response = response
                };

                await dispatcher.DispatchAsync(context);

                if (context.IsRejected)
                {
                    throw new ProtocolException(
                        SR.FormatID0161(context.Error, context.ErrorDescription, context.ErrorUri),
                        context.Error, context.ErrorDescription, context.ErrorUri);
                }

                Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

                return (context.Response, context.Principal);
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
