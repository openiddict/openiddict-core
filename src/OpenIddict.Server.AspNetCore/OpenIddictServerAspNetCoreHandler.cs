/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using Properties = OpenIddict.Server.AspNetCore.OpenIddictServerAspNetCoreConstants.Properties;

namespace OpenIddict.Server.AspNetCore
{
    /// <summary>
    /// Provides the logic necessary to extract, validate and handle OpenID Connect requests.
    /// </summary>
    public class OpenIddictServerAspNetCoreHandler : AuthenticationHandler<OpenIddictServerAspNetCoreOptions>,
        IAuthenticationRequestHandler,
        IAuthenticationSignInHandler,
        IAuthenticationSignOutHandler
    {
        private readonly IOpenIddictServerProvider _provider;

        /// <summary>
        /// Creates a new instance of the <see cref="OpenIddictServerAspNetCoreHandler"/> class.
        /// </summary>
        public OpenIddictServerAspNetCoreHandler(
            [NotNull] IOpenIddictServerProvider provider,
            [NotNull] IOptionsMonitor<OpenIddictServerAspNetCoreOptions> options,
            [NotNull] ILoggerFactory logger,
            [NotNull] UrlEncoder encoder,
            [NotNull] ISystemClock clock)
            : base(options, logger, encoder, clock)
            => _provider = provider;

        public async Task<bool> HandleRequestAsync()
        {
            // Note: the transaction may be already attached when replaying an ASP.NET Core request
            // (e.g when using the built-in status code pages middleware with the re-execute mode).
            var transaction = Context.Features.Get<OpenIddictServerAspNetCoreFeature>()?.Transaction;
            if (transaction == null)
            {
                // Create a new transaction and attach the HTTP request to make it available to the ASP.NET Core handlers.
                transaction = await _provider.CreateTransactionAsync();
                transaction.Properties[typeof(HttpRequest).FullName] = new WeakReference<HttpRequest>(Request);

                // Attach the OpenIddict server transaction to the ASP.NET Core features
                // so that it can retrieved while performing sign-in/sign-out operations.
                Context.Features.Set(new OpenIddictServerAspNetCoreFeature { Transaction = transaction });
            }

            var context = new ProcessRequestContext(transaction);
            await _provider.DispatchAsync(context);

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
                var notification = new ProcessErrorResponseContext(transaction)
                {
                    Response = new OpenIddictResponse
                    {
                        Error = context.Error ?? Errors.InvalidRequest,
                        ErrorDescription = context.ErrorDescription,
                        ErrorUri = context.ErrorUri
                    }
                };

                await _provider.DispatchAsync(notification);

                if (notification.IsRequestHandled)
                {
                    return true;
                }

                else if (notification.IsRequestSkipped)
                {
                    return false;
                }

                throw new InvalidOperationException(new StringBuilder()
                    .Append("The OpenID Connect response was not correctly processed. This may indicate ")
                    .Append("that the event handler responsible of processing OpenID Connect responses ")
                    .Append("was not registered or was explicitly removed from the handlers list.")
                    .ToString());
            }

            return false;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var transaction = Context.Features.Get<OpenIddictServerAspNetCoreFeature>()?.Transaction;
            if (transaction?.Request == null)
            {
                throw new InvalidOperationException("An identity cannot be extracted from this request.");
            }

            switch (transaction.EndpointType)
            {
                case OpenIddictServerEndpointType.Authorization:
                case OpenIddictServerEndpointType.Logout:
                {
                    if (string.IsNullOrEmpty(transaction.Request.IdTokenHint))
                    {
                        return AuthenticateResult.NoResult();
                    }

                    var notification = new DeserializeIdentityTokenContext(transaction)
                    {
                        Token = transaction.Request.IdTokenHint
                    };

                    await _provider.DispatchAsync(notification);

                    if (!notification.IsHandled)
                    {
                        throw new InvalidOperationException(new StringBuilder()
                            .Append("The identity token was not correctly processed. This may indicate ")
                            .Append("that the event handler responsible of validating identity tokens ")
                            .Append("was not registered or was explicitly removed from the handlers list.")
                            .ToString());
                    }

                    if (notification.Principal == null)
                    {
                        Logger.LogWarning("The identity token extracted from the 'id_token_hint' " +
                                          "parameter was invalid or malformed and was ignored.");

                        return AuthenticateResult.NoResult();
                    }

                    // Note: tickets are returned even if they are considered invalid (e.g expired).

                    return AuthenticateResult.Success(new AuthenticationTicket(
                        notification.Principal,
                        OpenIddictServerAspNetCoreDefaults.AuthenticationScheme));
                }

                case OpenIddictServerEndpointType.Token when transaction.Request.IsAuthorizationCodeGrantType():
                {
                    // Note: this method can be called from the ApplyTokenResponse event,
                    // which may be invoked for a missing authorization code/refresh token.
                    if (string.IsNullOrEmpty(transaction.Request.Code))
                    {
                        return AuthenticateResult.NoResult();
                    }

                    var notification = new DeserializeAuthorizationCodeContext(transaction)
                    {
                        Token = transaction.Request.Code
                    };

                    await _provider.DispatchAsync(notification);

                    if (!notification.IsHandled)
                    {
                        throw new InvalidOperationException(new StringBuilder()
                            .Append("The authorization code was not correctly processed. This may indicate ")
                            .Append("that the event handler responsible of validating authorization codes ")
                            .Append("was not registered or was explicitly removed from the handlers list.")
                            .ToString());
                    }

                    if (notification.Principal == null)
                    {
                        Logger.LogWarning("The authorization code extracted from the token request was invalid and was ignored.");

                        return AuthenticateResult.NoResult();
                    }

                    // Note: tickets are returned even if they are considered invalid (e.g expired).

                    return AuthenticateResult.Success(new AuthenticationTicket(
                        notification.Principal,
                        OpenIddictServerAspNetCoreDefaults.AuthenticationScheme));
                }

                case OpenIddictServerEndpointType.Token when transaction.Request.IsRefreshTokenGrantType():
                {
                    if (string.IsNullOrEmpty(transaction.Request.RefreshToken))
                    {
                        return AuthenticateResult.NoResult();
                    }

                    var notification = new DeserializeRefreshTokenContext(transaction)
                    {
                        Token = transaction.Request.RefreshToken
                    };

                    await _provider.DispatchAsync(notification);

                    if (!notification.IsHandled)
                    {
                        throw new InvalidOperationException(new StringBuilder()
                            .Append("The refresh token was not correctly processed. This may indicate ")
                            .Append("that the event handler responsible of validating refresh tokens ")
                            .Append("was not registered or was explicitly removed from the handlers list.")
                            .ToString());
                    }

                    if (notification.Principal == null)
                    {
                        Logger.LogWarning("The refresh token extracted from the token request was invalid and was ignored.");

                        return AuthenticateResult.NoResult();
                    }

                    // Note: tickets are returned even if they are considered invalid (e.g expired).

                    return AuthenticateResult.Success(new AuthenticationTicket(
                        notification.Principal,
                        OpenIddictServerAspNetCoreDefaults.AuthenticationScheme));
                }

                default: throw new InvalidOperationException("An identity cannot be extracted from this request.");
            }
        }

        protected override async Task HandleChallengeAsync([CanBeNull] AuthenticationProperties properties)
        {
            var transaction = Context.Features.Get<OpenIddictServerAspNetCoreFeature>()?.Transaction;
            if (transaction == null)
            {
                throw new InvalidOperationException("An OpenID Connect response cannot be returned from this endpoint.");
            }

            var context = new ProcessChallengeResponseContext(transaction)
            {
                Response = new OpenIddictResponse
                {
                    Error = GetProperty(properties, Properties.Error),
                    ErrorDescription = GetProperty(properties, Properties.ErrorDescription),
                    ErrorUri = GetProperty(properties, Properties.ErrorUri)
                }
            };

            await _provider.DispatchAsync(context);

            if (context.IsRequestHandled || context.IsRequestSkipped)
            {
                return;
            }

            else if (context.IsRejected)
            {
                var notification = new ProcessErrorResponseContext(transaction)
                {
                    Response = new OpenIddictResponse
                    {
                        Error = context.Error ?? Errors.InvalidRequest,
                        ErrorDescription = context.ErrorDescription,
                        ErrorUri = context.ErrorUri
                    }
                };

                await _provider.DispatchAsync(notification);

                if (notification.IsRequestHandled || context.IsRequestSkipped)
                {
                    return;
                }

                throw new InvalidOperationException(new StringBuilder()
                    .Append("The OpenID Connect response was not correctly processed. This may indicate ")
                    .Append("that the event handler responsible of processing OpenID Connect responses ")
                    .Append("was not registered or was explicitly removed from the handlers list.")
                    .ToString());
            }

            static string GetProperty(AuthenticationProperties properties, string name)
                => properties != null && properties.Items.TryGetValue(name, out string value) ? value : null;
        }

        protected override Task HandleForbiddenAsync([CanBeNull] AuthenticationProperties properties)
            => HandleChallengeAsync(properties);

        public async Task SignInAsync([NotNull] ClaimsPrincipal user, [CanBeNull] AuthenticationProperties properties)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var transaction = Context.Features.Get<OpenIddictServerAspNetCoreFeature>()?.Transaction;
            if (transaction == null)
            {
                throw new InvalidOperationException("An OpenID Connect response cannot be returned from this endpoint.");
            }

            var context = new ProcessSigninResponseContext(transaction)
            {
                Principal = user,
                Response = new OpenIddictResponse()
            };

            await _provider.DispatchAsync(context);

            if (context.IsRequestHandled || context.IsRequestSkipped)
            {
                return;
            }

            else if (context.IsRejected)
            {
                var notification = new ProcessErrorResponseContext(transaction)
                {
                    Response = new OpenIddictResponse
                    {
                        Error = context.Error ?? Errors.InvalidRequest,
                        ErrorDescription = context.ErrorDescription,
                        ErrorUri = context.ErrorUri
                    }
                };

                await _provider.DispatchAsync(notification);

                if (notification.IsRequestHandled || context.IsRequestSkipped)
                {
                    return;
                }

                throw new InvalidOperationException(new StringBuilder()
                    .Append("The OpenID Connect response was not correctly processed. This may indicate ")
                    .Append("that the event handler responsible of processing OpenID Connect responses ")
                    .Append("was not registered or was explicitly removed from the handlers list.")
                    .ToString());
            }
        }

        public async Task SignOutAsync([CanBeNull] AuthenticationProperties properties)
        {
            var transaction = Context.Features.Get<OpenIddictServerAspNetCoreFeature>()?.Transaction;
            if (transaction == null)
            {
                throw new InvalidOperationException("An OpenID Connect response cannot be returned from this endpoint.");
            }

            var context = new ProcessSignoutResponseContext(transaction)
            {
                Response = new OpenIddictResponse()
            };

            await _provider.DispatchAsync(context);

            if (context.IsRequestHandled || context.IsRequestSkipped)
            {
                return;
            }

            else if (context.IsRejected)
            {
                var notification = new ProcessErrorResponseContext(transaction)
                {
                    Response = new OpenIddictResponse
                    {
                        Error = context.Error ?? Errors.InvalidRequest,
                        ErrorDescription = context.ErrorDescription,
                        ErrorUri = context.ErrorUri
                    }
                };

                await _provider.DispatchAsync(notification);

                if (notification.IsRequestHandled || context.IsRequestSkipped)
                {
                    return;
                }

                throw new InvalidOperationException(new StringBuilder()
                    .Append("The OpenID Connect response was not correctly processed. This may indicate ")
                    .Append("that the event handler responsible of processing OpenID Connect responses ")
                    .Append("was not registered or was explicitly removed from the handlers list.")
                    .ToString());
            }
        }
    }
}
