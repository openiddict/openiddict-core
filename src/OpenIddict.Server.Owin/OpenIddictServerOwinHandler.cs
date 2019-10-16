/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Server.Owin
{
    /// <summary>
    /// Provides the entry point necessary to register the OpenIddict server in an OWIN pipeline.
    /// </summary>
    public class OpenIddictServerOwinHandler : AuthenticationHandler<OpenIddictServerOwinOptions>
    {
        private readonly IOpenIddictServerProvider _provider;

        /// <summary>
        /// Creates a new instance of the <see cref="OpenIddictServerOwinHandler"/> class.
        /// </summary>
        /// <param name="provider">The OpenIddict server OWIN provider used by this instance.</param>
        public OpenIddictServerOwinHandler([NotNull] IOpenIddictServerProvider provider)
            => _provider = provider;

        public override async Task<bool> InvokeAsync()
        {
            // Note: the transaction may be already attached when replaying an OWIN request
            // (e.g when using a status code pages middleware re-invoking the OWIN pipeline).
            var transaction = Context.Get<OpenIddictServerTransaction>(typeof(OpenIddictServerTransaction).FullName);
            if (transaction == null)
            {
                // Create a new transaction and attach the OWIN request to make it available to the OWIN handlers.
                transaction = await _provider.CreateTransactionAsync();
                transaction.Properties[typeof(IOwinRequest).FullName] = new WeakReference<IOwinRequest>(Request);

                // Attach the OpenIddict server transaction to the OWIN shared dictionary
                // so that it can retrieved while performing sign-in/sign-out operations.
                Context.Set(typeof(OpenIddictServerTransaction).FullName, transaction);
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
                var notification = new ProcessErrorContext(transaction)
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

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            var transaction = Context.Get<OpenIddictServerTransaction>(typeof(OpenIddictServerTransaction).FullName);
            if (transaction == null)
            {
                throw new InvalidOperationException("An identity cannot be extracted from this request.");
            }

            // Note: in many cases, the authentication token was already validated by the time this action is called
            // (generally later in the pipeline, when using the pass-through mode). To avoid having to re-validate it,
            // the authentication context is resolved from the transaction. If it's not available, a new one is created.
            var context = transaction.GetProperty<ProcessAuthenticationContext>(typeof(ProcessAuthenticationContext).FullName);
            if (context == null)
            {
                context = new ProcessAuthenticationContext(transaction);
                await _provider.DispatchAsync(context);
            }

            if (context.IsRequestHandled || context.IsRequestSkipped)
            {
                return null;
            }

            else if (context.IsRejected)
            {
                var properties = new AuthenticationProperties(new Dictionary<string, string>
                {
                    [OpenIddictServerOwinConstants.Properties.Error] = context.Error,
                    [OpenIddictServerOwinConstants.Properties.ErrorDescription] = context.ErrorDescription,
                    [OpenIddictServerOwinConstants.Properties.ErrorUri] = context.ErrorUri
                });

                return new AuthenticationTicket(null, properties);
            }

            return null;
        }

        protected override async Task TeardownCoreAsync()
        {
            // Note: OWIN authentication handlers cannot reliabily write to the response stream
            // from ApplyResponseGrantAsync or ApplyResponseChallengeAsync because these methods
            // are susceptible to be invoked from AuthenticationHandler.OnSendingHeaderCallback,
            // where calling Write or WriteAsync on the response stream may result in a deadlock
            // on hosts using streamed responses. To work around this limitation, this handler
            // doesn't implement ApplyResponseGrantAsync but TeardownCoreAsync, which is never called
            // by AuthenticationHandler.OnSendingHeaderCallback. In theory, this would prevent
            // OpenIddictServerOwinMiddleware from both applying the response grant and allowing
            // the next middleware in the pipeline to alter the response stream but in practice,
            // OpenIddictServerOwinMiddleware is assumed to be the only middleware allowed to write
            // to the response stream when a response grant (sign-in/out or challenge) was applied.

            var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);
            if (challenge != null)
            {
                var transaction = Context.Get<OpenIddictServerTransaction>(typeof(OpenIddictServerTransaction).FullName);
                if (transaction == null)
                {
                    throw new InvalidOperationException("An OpenID Connect response cannot be returned from this endpoint.");
                }

                transaction.Properties[typeof(AuthenticationProperties).FullName] = challenge.Properties ?? new AuthenticationProperties();

                var context = new ProcessChallengeContext(transaction)
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
                    var notification = new ProcessErrorContext(transaction)
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

            var signin = Helper.LookupSignIn(Options.AuthenticationType);
            if (signin != null)
            {
                var transaction = Context.Get<OpenIddictServerTransaction>(typeof(OpenIddictServerTransaction).FullName);
                if (transaction == null)
                {
                    throw new InvalidOperationException("An OpenID Connect response cannot be returned from this endpoint.");
                }

                transaction.Properties[typeof(AuthenticationProperties).FullName] = signin.Properties ?? new AuthenticationProperties();

                var context = new ProcessSigninContext(transaction)
                {
                    Principal = signin.Principal,
                    Response = new OpenIddictResponse()
                };

                await _provider.DispatchAsync(context);

                if (context.IsRequestHandled || context.IsRequestSkipped)
                {
                    return;
                }

                else if (context.IsRejected)
                {
                    var notification = new ProcessErrorContext(transaction)
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

            var signout = Helper.LookupSignOut(Options.AuthenticationType, Options.AuthenticationMode);
            if (signout != null)
            {
                var transaction = Context.Get<OpenIddictServerTransaction>(typeof(OpenIddictServerTransaction).FullName);
                if (transaction == null)
                {
                    throw new InvalidOperationException("An OpenID Connect response cannot be returned from this endpoint.");
                }

                transaction.Properties[typeof(AuthenticationProperties).FullName] = signout.Properties ?? new AuthenticationProperties();

                var context = new ProcessSignoutContext(transaction)
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
                    var notification = new ProcessErrorContext(transaction)
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
}
