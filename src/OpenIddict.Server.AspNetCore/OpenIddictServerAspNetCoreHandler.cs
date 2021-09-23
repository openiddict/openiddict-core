/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using Properties = OpenIddict.Server.AspNetCore.OpenIddictServerAspNetCoreConstants.Properties;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.Server.AspNetCore;

/// <summary>
/// Provides the logic necessary to extract, validate and handle OpenID Connect requests.
/// </summary>
public class OpenIddictServerAspNetCoreHandler : AuthenticationHandler<OpenIddictServerAspNetCoreOptions>,
    IAuthenticationRequestHandler,
    IAuthenticationSignInHandler,
    IAuthenticationSignOutHandler
{
    private readonly IOpenIddictServerDispatcher _dispatcher;
    private readonly IOpenIddictServerFactory _factory;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictServerAspNetCoreHandler"/> class.
    /// </summary>
    public OpenIddictServerAspNetCoreHandler(
        IOpenIddictServerDispatcher dispatcher,
        IOpenIddictServerFactory factory,
        IOptionsMonitor<OpenIddictServerAspNetCoreOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock)
        : base(options, logger, encoder, clock)
    {
        _dispatcher = dispatcher;
        _factory = factory;
    }

    /// <inheritdoc/>
    public async Task<bool> HandleRequestAsync()
    {
        // Note: the transaction may be already attached when replaying an ASP.NET Core request
        // (e.g when using the built-in status code pages middleware with the re-execute mode).
        var transaction = Context.Features.Get<OpenIddictServerAspNetCoreFeature>()?.Transaction;
        if (transaction is null)
        {
            // Create a new transaction and attach the HTTP request to make it available to the ASP.NET Core handlers.
            transaction = await _factory.CreateTransactionAsync();
            transaction.Properties[typeof(HttpRequest).FullName!] = new WeakReference<HttpRequest>(Request);

            // Attach the OpenIddict server transaction to the ASP.NET Core features
            // so that it can retrieved while performing sign-in/sign-out operations.
            Context.Features.Set(new OpenIddictServerAspNetCoreFeature { Transaction = transaction });
        }

        var context = new ProcessRequestContext(transaction);
        await _dispatcher.DispatchAsync(context);

        if (context.IsRequestHandled)
        {
            return true;
        }

        else if (context.IsRequestSkipped)
        {
            return false;
        }

        else if (context.IsRejected)
        {
            var notification = new ProcessErrorContext(transaction)
            {
                Error = context.Error ?? Errors.InvalidRequest,
                ErrorDescription = context.ErrorDescription,
                ErrorUri = context.ErrorUri,
                Response = new OpenIddictResponse()
            };

            await _dispatcher.DispatchAsync(notification);

            if (notification.IsRequestHandled)
            {
                return true;
            }

            else if (notification.IsRequestSkipped)
            {
                return false;
            }

            throw new InvalidOperationException(SR.GetResourceString(SR.ID0111));
        }

        return false;
    }

    /// <inheritdoc/>
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var transaction = Context.Features.Get<OpenIddictServerAspNetCoreFeature>()?.Transaction ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0112));

        // Note: in many cases, the authentication token was already validated by the time this action is called
        // (generally later in the pipeline, when using the pass-through mode). To avoid having to re-validate it,
        // the authentication context is resolved from the transaction. If it's not available, a new one is created.
        var context = transaction.GetProperty<ProcessAuthenticationContext>(typeof(ProcessAuthenticationContext).FullName!);
        if (context is null)
        {
            context = new ProcessAuthenticationContext(transaction);
            await _dispatcher.DispatchAsync(context);

            // Store the context object in the transaction so it can be later retrieved by handlers
            // that want to access the authentication result without triggering a new authentication flow.
            transaction.SetProperty(typeof(ProcessAuthenticationContext).FullName!, context);
        }

        if (context.IsRequestHandled || context.IsRequestSkipped)
        {
            return AuthenticateResult.NoResult();
        }

        else if (context.IsRejected)
        {
            // Note: the missing_token error is special-cased to indicate to ASP.NET Core
            // that no authentication result could be produced due to the lack of token.
            // This also helps reducing the logging noise when no token is specified.
            if (string.Equals(context.Error, Errors.MissingToken, StringComparison.Ordinal))
            {
                return AuthenticateResult.NoResult();
            }

            var properties = new AuthenticationProperties(new Dictionary<string, string?>
            {
                [Properties.Error] = context.Error,
                [Properties.ErrorDescription] = context.ErrorDescription,
                [Properties.ErrorUri] = context.ErrorUri
            });

            return AuthenticateResult.Fail(SR.GetResourceString(SR.ID0113), properties);
        }

        else
        {
            // A single main claims-based principal instance can be attached to an authentication ticket.
            // To return the most appropriate one, the principal is selected based on the endpoint type.
            // Independently of the selected main principal, all principals resolved from validated tokens
            // are attached to the authentication properties bag so they can be accessed from user code.
            var principal = context.EndpointType switch
            {
                OpenIddictServerEndpointType.Authorization or OpenIddictServerEndpointType.Logout
                    => context.IdentityTokenPrincipal,

                OpenIddictServerEndpointType.Introspection or OpenIddictServerEndpointType.Revocation
                    => context.AccessTokenPrincipal       ??
                       context.RefreshTokenPrincipal      ??
                       context.IdentityTokenPrincipal     ??
                       context.AuthorizationCodePrincipal ??
                       context.DeviceCodePrincipal        ??
                       context.UserCodePrincipal,

                OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType()
                    => context.AuthorizationCodePrincipal,
                OpenIddictServerEndpointType.Token when context.Request.IsDeviceCodeGrantType()
                    => context.DeviceCodePrincipal,
                OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                    => context.RefreshTokenPrincipal,

                OpenIddictServerEndpointType.Userinfo => context.AccessTokenPrincipal,

                OpenIddictServerEndpointType.Verification => context.UserCodePrincipal,

                _ => null
            };

            if (principal is null)
            {
                return AuthenticateResult.NoResult();
            }

            var properties = new AuthenticationProperties
            {
                ExpiresUtc = principal.GetExpirationDate(),
                IssuedUtc = principal.GetCreationDate()
            };

            List<AuthenticationToken>? tokens = null;

            // Attach the tokens to allow any ASP.NET Core component (e.g a controller)
            // to retrieve them (e.g to make an API request to another application).

            if (context.AccessTokenPrincipal is not null && !string.IsNullOrEmpty(context.AccessToken))
            {
                tokens ??= new(capacity: 1);
                tokens.Add(new AuthenticationToken
                {
                    Name = TokenTypeHints.AccessToken,
                    Value = context.AccessToken
                });

                properties.SetParameter(Properties.AccessTokenPrincipal, context.AccessTokenPrincipal);
            }

            if (context.AuthorizationCodePrincipal is not null && !string.IsNullOrEmpty(context.AuthorizationCode))
            {
                tokens ??= new(capacity: 1);
                tokens.Add(new AuthenticationToken
                {
                    Name = TokenTypeHints.AuthorizationCode,
                    Value = context.AuthorizationCode
                });

                properties.SetParameter(Properties.AuthorizationCodePrincipal, context.AuthorizationCodePrincipal);
            }

            if (context.DeviceCodePrincipal is not null && !string.IsNullOrEmpty(context.DeviceCode))
            {
                tokens ??= new(capacity: 1);
                tokens.Add(new AuthenticationToken
                {
                    Name = TokenTypeHints.DeviceCode,
                    Value = context.DeviceCode
                });

                properties.SetParameter(Properties.DeviceCodePrincipal, context.DeviceCodePrincipal);
            }

            if (context.IdentityTokenPrincipal is not null && !string.IsNullOrEmpty(context.IdentityToken))
            {
                tokens ??= new(capacity: 1);
                tokens.Add(new AuthenticationToken
                {
                    Name = TokenTypeHints.IdToken,
                    Value = context.IdentityToken
                });

                properties.SetParameter(Properties.IdentityTokenPrincipal, context.IdentityTokenPrincipal);
            }

            if (context.RefreshTokenPrincipal is not null && !string.IsNullOrEmpty(context.RefreshToken))
            {
                tokens ??= new(capacity: 1);
                tokens.Add(new AuthenticationToken
                {
                    Name = TokenTypeHints.RefreshToken,
                    Value = context.RefreshToken
                });

                properties.SetParameter(Properties.RefreshTokenPrincipal, context.RefreshTokenPrincipal);
            }

            if (context.UserCodePrincipal is not null && !string.IsNullOrEmpty(context.UserCode))
            {
                tokens ??= new(capacity: 1);
                tokens.Add(new AuthenticationToken
                {
                    Name = TokenTypeHints.UserCode,
                    Value = context.UserCode
                });

                properties.SetParameter(Properties.UserCodePrincipal, context.UserCodePrincipal);
            }

            if (tokens is { Count: > 0 })
            {
                properties.StoreTokens(tokens);
            }

            return AuthenticateResult.Success(new AuthenticationTicket(principal, properties,
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme));
        }
    }

    /// <inheritdoc/>
    protected override async Task HandleChallengeAsync(AuthenticationProperties? properties)
    {
        var transaction = Context.Features.Get<OpenIddictServerAspNetCoreFeature>()?.Transaction ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0112));

        transaction.Properties[typeof(AuthenticationProperties).FullName!] = properties ?? new AuthenticationProperties();

        var context = new ProcessChallengeContext(transaction)
        {
            Response = new OpenIddictResponse()
        };

        await _dispatcher.DispatchAsync(context);

        if (context.IsRequestHandled || context.IsRequestSkipped)
        {
            return;
        }

        else if (context.IsRejected)
        {
            var notification = new ProcessErrorContext(transaction)
            {
                Error = context.Error ?? Errors.InvalidRequest,
                ErrorDescription = context.ErrorDescription,
                ErrorUri = context.ErrorUri,
                Response = new OpenIddictResponse()
            };

            await _dispatcher.DispatchAsync(notification);

            if (notification.IsRequestHandled || context.IsRequestSkipped)
            {
                return;
            }

            throw new InvalidOperationException(SR.GetResourceString(SR.ID0111));
        }
    }

    /// <inheritdoc/>
    protected override Task HandleForbiddenAsync(AuthenticationProperties? properties)
        => HandleChallengeAsync(properties);

    /// <inheritdoc/>
    public async Task SignInAsync(ClaimsPrincipal user, AuthenticationProperties? properties)
    {
        if (user is null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        var transaction = Context.Features.Get<OpenIddictServerAspNetCoreFeature>()?.Transaction ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0112));

        transaction.Properties[typeof(AuthenticationProperties).FullName!] = properties ?? new AuthenticationProperties();

        var context = new ProcessSignInContext(transaction)
        {
            Principal = user,
            Response = new OpenIddictResponse()
        };

        await _dispatcher.DispatchAsync(context);

        if (context.IsRequestHandled || context.IsRequestSkipped)
        {
            return;
        }

        else if (context.IsRejected)
        {
            var notification = new ProcessErrorContext(transaction)
            {
                Error = context.Error ?? Errors.InvalidRequest,
                ErrorDescription = context.ErrorDescription,
                ErrorUri = context.ErrorUri,
                Response = new OpenIddictResponse()
            };

            await _dispatcher.DispatchAsync(notification);

            if (notification.IsRequestHandled || context.IsRequestSkipped)
            {
                return;
            }

            throw new InvalidOperationException(SR.GetResourceString(SR.ID0111));
        }
    }

    /// <inheritdoc/>
    public async Task SignOutAsync(AuthenticationProperties? properties)
    {
        var transaction = Context.Features.Get<OpenIddictServerAspNetCoreFeature>()?.Transaction ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0112));

        var context = new ProcessSignOutContext(transaction)
        {
            Response = new OpenIddictResponse()
        };

        transaction.Properties[typeof(AuthenticationProperties).FullName!] = properties ?? new AuthenticationProperties();

        await _dispatcher.DispatchAsync(context);

        if (context.IsRequestHandled || context.IsRequestSkipped)
        {
            return;
        }

        else if (context.IsRejected)
        {
            var notification = new ProcessErrorContext(transaction)
            {
                Error = context.Error ?? Errors.InvalidRequest,
                ErrorDescription = context.ErrorDescription,
                ErrorUri = context.ErrorUri,
                Response = new OpenIddictResponse()
            };

            await _dispatcher.DispatchAsync(notification);

            if (notification.IsRequestHandled || context.IsRequestSkipped)
            {
                return;
            }

            throw new InvalidOperationException(SR.GetResourceString(SR.ID0111));
        }
    }
}
