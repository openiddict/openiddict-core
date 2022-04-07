/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using static OpenIddict.Client.AspNetCore.OpenIddictClientAspNetCoreConstants;
using Properties = OpenIddict.Client.AspNetCore.OpenIddictClientAspNetCoreConstants.Properties;

namespace OpenIddict.Client.AspNetCore;

/// <summary>
/// Provides the logic necessary to extract, validate and handle OpenID Connect requests.
/// </summary>
public class OpenIddictClientAspNetCoreHandler : AuthenticationHandler<OpenIddictClientAspNetCoreOptions>,
    IAuthenticationRequestHandler
{
    private readonly IOpenIddictClientDispatcher _dispatcher;
    private readonly IOpenIddictClientFactory _factory;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientAspNetCoreHandler"/> class.
    /// </summary>
    public OpenIddictClientAspNetCoreHandler(
        IOpenIddictClientDispatcher dispatcher!!,
        IOpenIddictClientFactory factory!!,
        IOptionsMonitor<OpenIddictClientAspNetCoreOptions> options!!,
        ILoggerFactory logger!!,
        UrlEncoder encoder!!,
        ISystemClock clock!!)
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
        var transaction = Context.Features.Get<OpenIddictClientAspNetCoreFeature>()?.Transaction;
        if (transaction is null)
        {
            // Create a new transaction and attach the HTTP request to make it available to the ASP.NET Core handlers.
            transaction = await _factory.CreateTransactionAsync();
            transaction.Properties[typeof(HttpRequest).FullName!] = new WeakReference<HttpRequest>(Request);

            // Attach the OpenIddict client transaction to the ASP.NET Core features
            // so that it can retrieved while performing sign-in/sign-out operations.
            Context.Features.Set(new OpenIddictClientAspNetCoreFeature { Transaction = transaction });
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
        var transaction = Context.Features.Get<OpenIddictClientAspNetCoreFeature>()?.Transaction ??
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
                // Create a composite principal containing claims resolved from the frontchannel
                // and backchannel identity tokens and the userinfo token principal, if available.
                OpenIddictClientEndpointType.Redirection => CreatePrincipal(
                    context.FrontchannelIdentityTokenPrincipal,
                    context.BackchannelIdentityTokenPrincipal,
                    context.UserinfoTokenPrincipal),

                _ => null
            };

            if (principal is null)
            {
                return AuthenticateResult.NoResult();
            }

            var properties = new AuthenticationProperties
            {
                ExpiresUtc = principal.GetExpirationDate(),
                IssuedUtc = principal.GetCreationDate(),

                // Restore the return URL using the "target_link_uri" that was stored
                // in the state token when the challenge operation started, if available.
                RedirectUri = context.StateTokenPrincipal?.GetClaim(Claims.TargetLinkUri)
            };

            List<AuthenticationToken>? tokens = null;

            // Attach the tokens to allow any ASP.NET Core component (e.g a controller)
            // to retrieve them (e.g to make an API request to another application).

            if (!string.IsNullOrEmpty(context.AuthorizationCode))
            {
                tokens ??= new(capacity: 1);
                tokens.Add(new AuthenticationToken
                {
                    Name = Tokens.AuthorizationCode,
                    Value = context.AuthorizationCode
                });
            }

            if (!string.IsNullOrEmpty(context.BackchannelAccessToken))
            {
                tokens ??= new(capacity: 1);
                tokens.Add(new AuthenticationToken
                {
                    Name = Tokens.BackchannelAccessToken,
                    Value = context.BackchannelAccessToken
                });
            }

            if (!string.IsNullOrEmpty(context.BackchannelIdentityToken))
            {
                tokens ??= new(capacity: 1);
                tokens.Add(new AuthenticationToken
                {
                    Name = Tokens.BackchannelIdentityToken,
                    Value = context.BackchannelIdentityToken
                });
            }

            if (!string.IsNullOrEmpty(context.FrontchannelAccessToken))
            {
                tokens ??= new(capacity: 1);
                tokens.Add(new AuthenticationToken
                {
                    Name = Tokens.FrontchannelAccessToken,
                    Value = context.FrontchannelAccessToken
                });
            }

            if (!string.IsNullOrEmpty(context.FrontchannelIdentityToken))
            {
                tokens ??= new(capacity: 1);
                tokens.Add(new AuthenticationToken
                {
                    Name = Tokens.FrontchannelIdentityToken,
                    Value = context.FrontchannelIdentityToken
                });
            }

            if (!string.IsNullOrEmpty(context.RefreshToken))
            {
                tokens ??= new(capacity: 1);
                tokens.Add(new AuthenticationToken
                {
                    Name = Tokens.RefreshToken,
                    Value = context.RefreshToken
                });
            }

            if (!string.IsNullOrEmpty(context.StateToken))
            {
                tokens ??= new(capacity: 1);
                tokens.Add(new AuthenticationToken
                {
                    Name = Tokens.StateToken,
                    Value = context.StateToken
                });
            }

            if (!string.IsNullOrEmpty(context.UserinfoToken))
            {
                tokens ??= new(capacity: 1);
                tokens.Add(new AuthenticationToken
                {
                    Name = Tokens.UserinfoToken,
                    Value = context.UserinfoToken
                });
            }

            if (tokens is { Count: > 0 })
            {
                properties.StoreTokens(tokens);
            }

            if (context.AuthorizationCodePrincipal is not null)
            {
                properties.SetParameter(Properties.AuthorizationCodePrincipal, context.AuthorizationCodePrincipal);
            }

            if (context.BackchannelAccessTokenPrincipal is not null)
            {
                properties.SetParameter(Properties.BackchannelAccessTokenPrincipal, context.BackchannelAccessTokenPrincipal);
            }

            if (context.BackchannelIdentityTokenPrincipal is not null)
            {
                properties.SetParameter(Properties.BackchannelIdentityTokenPrincipal, context.BackchannelIdentityTokenPrincipal);
            }

            if (context.FrontchannelAccessTokenPrincipal is not null)
            {
                properties.SetParameter(Properties.FrontchannelAccessTokenPrincipal, context.FrontchannelAccessTokenPrincipal);
            }

            if (context.FrontchannelIdentityTokenPrincipal is not null)
            {
                properties.SetParameter(Properties.FrontchannelIdentityTokenPrincipal, context.FrontchannelIdentityTokenPrincipal);
            }

            if (context.RefreshTokenPrincipal is not null)
            {
                properties.SetParameter(Properties.RefreshTokenPrincipal, context.RefreshTokenPrincipal);
            }

            if (context.StateTokenPrincipal is not null)
            {
                properties.SetParameter(Properties.StateTokenPrincipal, context.StateTokenPrincipal);
            }

            if (context.UserinfoTokenPrincipal is not null)
            {
                properties.SetParameter(Properties.UserinfoTokenPrincipal, context.UserinfoTokenPrincipal);
            }

            return AuthenticateResult.Success(new AuthenticationTicket(principal, properties,
                OpenIddictClientAspNetCoreDefaults.AuthenticationScheme));

            static ClaimsPrincipal CreatePrincipal(params ClaimsPrincipal?[] principals)
            {
                // Note: the OpenIddict client handler can be used as a pure OAuth 2.0-only stack for
                // delegation scenarios where the identity of the user is not needed. In this case,
                // since no principal can be resolved from a token or a userinfo response to construct
                // a user identity, a fake one containing an "unauthenticated" identity (i.e with its
                // AuthenticationType property deliberately left to null) is used to allow ASP.NET Core
                // to return a "successful" authentication result for these delegation-only scenarios.
                if (!principals.Any(principal => principal?.Identity is ClaimsIdentity { IsAuthenticated: true }))
                {
                    return new ClaimsPrincipal(new ClaimsIdentity());
                }

                // Create a new composite identity containing the claims of all the principals.
                var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType);

                foreach (var principal in principals)
                {
                    // Note: the principal may be null if no value was extracted from the corresponding token.
                    if (principal is null)
                    {
                        continue;
                    }

                    foreach (var claim in principal.Claims)
                    {
                        // If a claim with the same type and the same value already exist, skip it.
                        if (identity.HasClaim(claim.Type, claim.Value))
                        {
                            continue;
                        }

                        identity.AddClaim(claim);
                    }
                }

                return new ClaimsPrincipal(identity);
            }
        }
    }

    /// <inheritdoc/>
    protected override async Task HandleChallengeAsync(AuthenticationProperties? properties)
    {
        var transaction = Context.Features.Get<OpenIddictClientAspNetCoreFeature>()?.Transaction ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0112));

        transaction.Properties[typeof(AuthenticationProperties).FullName!] = properties ?? new AuthenticationProperties();

        var context = new ProcessChallengeContext(transaction)
        {
            Principal = new ClaimsPrincipal(new ClaimsIdentity()),
            Request = new OpenIddictRequest()
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
}
