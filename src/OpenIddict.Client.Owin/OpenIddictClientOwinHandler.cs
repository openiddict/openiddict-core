/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.Owin.Security.Infrastructure;
using OpenIddict.Extensions;
using static OpenIddict.Client.Owin.OpenIddictClientOwinConstants;
using Properties = OpenIddict.Client.Owin.OpenIddictClientOwinConstants.Properties;

namespace OpenIddict.Client.Owin;

/// <summary>
/// Provides the entry point necessary to register the OpenIddict client in an OWIN pipeline.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictClientOwinHandler : AuthenticationHandler<OpenIddictClientOwinOptions>
{
    private readonly IOpenIddictClientDispatcher _dispatcher;
    private readonly IOpenIddictClientFactory _factory;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientOwinHandler"/> class.
    /// </summary>
    /// <param name="dispatcher">The OpenIddict client dispatcher used by this instance.</param>
    /// <param name="factory">The OpenIddict client factory used by this instance.</param>
    public OpenIddictClientOwinHandler(
        IOpenIddictClientDispatcher dispatcher,
        IOpenIddictClientFactory factory)
    {
        _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
        _factory = factory ?? throw new ArgumentNullException(nameof(factory));
    }

    /// <inheritdoc/>
    protected override async Task InitializeCoreAsync()
    {
        // Note: the transaction may be already attached when replaying an OWIN request
        // (e.g when using a status code pages middleware re-invoking the OWIN pipeline).
        var transaction = Context.Get<OpenIddictClientTransaction>(typeof(OpenIddictClientTransaction).FullName);
        if (transaction is null)
        {
            // Create a new transaction and attach the OWIN request to make it available to the OWIN handlers.
            transaction = await _factory.CreateTransactionAsync();
            transaction.Properties[typeof(IOwinRequest).FullName!] = new WeakReference<IOwinRequest>(Request);

            // Attach the OpenIddict client transaction to the OWIN shared dictionary
            // so that it can retrieved while performing sign-in/sign-out operations.
            Context.Set(typeof(OpenIddictClientTransaction).FullName, transaction);
        }

        var context = new ProcessRequestContext(transaction);
        await _dispatcher.DispatchAsync(context);

        // Store the context in the transaction so that it can be retrieved from InvokeAsync().
        transaction.SetProperty(typeof(ProcessRequestContext).FullName!, context);
    }

    /// <inheritdoc/>
    public override async Task<bool> InvokeAsync()
    {
        // Note: due to internal differences between ASP.NET Core and Katana, the request MUST start being processed
        // in InitializeCoreAsync() to ensure the request context is available from AuthenticateCoreAsync() when
        // active authentication is used, as AuthenticateCoreAsync() is always called before InvokeAsync() in this case.

        var transaction = Context.Get<OpenIddictClientTransaction>(typeof(OpenIddictClientTransaction).FullName) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0315));

        var context = transaction.GetProperty<ProcessRequestContext>(typeof(ProcessRequestContext).FullName!) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0315));

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
    protected override async Task<AuthenticationTicket?> AuthenticateCoreAsync()
    {
        var transaction = Context.Get<OpenIddictClientTransaction>(typeof(OpenIddictClientTransaction).FullName) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0315));

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
            return null;
        }

        else if (context.IsRejected)
        {
            // Note: the missing_token error is special-cased to indicate to Katana
            // that no authentication result could be produced due to the lack of token.
            // This also helps reducing the logging noise when no token is specified.
            if (string.Equals(context.Error, Errors.MissingToken, StringComparison.Ordinal))
            {
                return null;
            }

            var properties = new AuthenticationProperties(new Dictionary<string, string?>
            {
                [Properties.Error] = context.Error,
                [Properties.ErrorDescription] = context.ErrorDescription,
                [Properties.ErrorUri] = context.ErrorUri
            });

            return new AuthenticationTicket(null, properties);
        }

        else
        {
            // A single main claims-based principal instance can be attached to an authentication ticket.
            var principal = context.EndpointType switch
            {
                // Create a composite principal containing claims resolved from the frontchannel
                // and backchannel identity tokens and the userinfo token principal, if available.
                OpenIddictClientEndpointType.Redirection => OpenIddictHelpers.CreateMergedPrincipal(
                    context.FrontchannelIdentityTokenPrincipal,
                    context.BackchannelIdentityTokenPrincipal,
                    context.UserinfoTokenPrincipal),

                OpenIddictClientEndpointType.PostLogoutRedirection => context.StateTokenPrincipal,

                _ => null
            };

            if (principal is null)
            {
                return null;
            }

            // Attach the identity of the authorization to the returned principal to allow resolving it even if no other
            // claim was added to the principal (e.g when no id_token was returned and no userinfo endpoint is available).
            principal.SetClaim(Claims.AuthorizationServer, context.StateTokenPrincipal?.GetClaim(Claims.AuthorizationServer));

            // Restore or create a new authentication properties collection and populate it.
            var properties = CreateProperties(context.StateTokenPrincipal);
            properties.ExpiresUtc = principal.GetExpirationDate();
            properties.IssuedUtc = principal.GetCreationDate();

            // Restore the return URL using the "target_link_uri" that was stored
            // in the state token when the challenge operation started, if available.
            properties.RedirectUri = context.StateTokenPrincipal?.GetClaim(Claims.TargetLinkUri);

            // Attach the tokens to allow any OWIN component (e.g a controller)
            // to retrieve them (e.g to make an API request to another application).

            if (!string.IsNullOrEmpty(context.AuthorizationCode))
            {
                properties.Dictionary[Tokens.AuthorizationCode] = context.AuthorizationCode;
            }

            if (!string.IsNullOrEmpty(context.BackchannelAccessToken))
            {
                properties.Dictionary[Tokens.BackchannelAccessToken] = context.BackchannelAccessToken;
            }

            if (!string.IsNullOrEmpty(context.BackchannelIdentityToken))
            {
                properties.Dictionary[Tokens.BackchannelIdentityToken] = context.BackchannelIdentityToken;
            }

            if (!string.IsNullOrEmpty(context.FrontchannelAccessToken))
            {
                properties.Dictionary[Tokens.FrontchannelAccessToken] = context.FrontchannelAccessToken;
            }

            if (!string.IsNullOrEmpty(context.FrontchannelIdentityToken))
            {
                properties.Dictionary[Tokens.FrontchannelIdentityToken] = context.FrontchannelIdentityToken;
            }

            if (!string.IsNullOrEmpty(context.RefreshToken))
            {
                properties.Dictionary[Tokens.RefreshToken] = context.RefreshToken;
            }

            if (!string.IsNullOrEmpty(context.StateToken))
            {
                properties.Dictionary[Tokens.StateToken] = context.StateToken;
            }

            if (!string.IsNullOrEmpty(context.UserinfoToken))
            {
                properties.Dictionary[Tokens.UserinfoToken] = context.UserinfoToken;
            }

            return new AuthenticationTicket((ClaimsIdentity) principal.Identity, properties);

            static AuthenticationProperties CreateProperties(ClaimsPrincipal? principal)
            {
                // Note: the principal may be null if no value was extracted from the corresponding token.
                if (principal is not null)
                {
                    var value = principal.GetClaim(Claims.Private.HostProperties);
                    if (!string.IsNullOrEmpty(value))
                    {
                        var dictionary = new Dictionary<string, string?>(comparer: StringComparer.Ordinal);
                        using var document = JsonDocument.Parse(value);

                        foreach (var property in document.RootElement.EnumerateObject())
                        {
                            dictionary[property.Name] = property.Value.GetString();
                        }

                        return new AuthenticationProperties(dictionary);
                    }
                }

                return new AuthenticationProperties();
            }
        }
    }

    /// <inheritdoc/>
    protected override async Task TeardownCoreAsync()
    {
        // Note: OWIN authentication handlers cannot reliabily write to the response stream
        // from ApplyResponseGrantAsync or ApplyResponseChallengeAsync because these methods
        // are susceptible to be invoked from AuthenticationHandler.OnSendingHeaderCallback,
        // where calling Write or WriteAsync on the response stream may result in a deadlock
        // on hosts using streamed responses. To work around this limitation, this handler
        // doesn't implement ApplyResponseGrantAsync but TeardownCoreAsync, which is never called
        // by AuthenticationHandler.OnSendingHeaderCallback. In theory, this would prevent
        // OpenIddictClientOwinMiddleware from both applying the response grant and allowing
        // the next middleware in the pipeline to alter the response stream but in practice,
        // OpenIddictClientOwinMiddleware is assumed to be the only middleware allowed to write
        // to the response stream when a response grant (sign-in/out or challenge) was applied.

        // Note: unlike the ASP.NET Core host, the OWIN host MUST check whether the status code
        // corresponds to a challenge response, as LookupChallenge() will always return a non-null
        // value when active authentication is used, even if no challenge was actually triggered.
        var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);
        if (challenge is not null && Response.StatusCode is 401 or 403)
        {
            var transaction = Context.Get<OpenIddictClientTransaction>(typeof(OpenIddictClientTransaction).FullName) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0315));

            transaction.Properties[typeof(AuthenticationProperties).FullName!] = challenge.Properties ?? new AuthenticationProperties();

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

        var signout = Helper.LookupSignOut(Options.AuthenticationType, Options.AuthenticationMode);
        if (signout is not null)
        {
            var transaction = Context.Get<OpenIddictClientTransaction>(typeof(OpenIddictClientTransaction).FullName) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0315));

            transaction.Properties[typeof(AuthenticationProperties).FullName!] = signout.Properties ?? new AuthenticationProperties();

            var context = new ProcessSignOutContext(transaction)
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
    }
}
