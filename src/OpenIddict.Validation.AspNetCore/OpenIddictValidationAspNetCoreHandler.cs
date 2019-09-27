/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
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
using static OpenIddict.Validation.OpenIddictValidationEvents;
using Properties = OpenIddict.Validation.AspNetCore.OpenIddictValidationAspNetCoreConstants.Properties;

namespace OpenIddict.Validation.AspNetCore
{
    /// <summary>
    /// Provides the logic necessary to extract, validate and handle OpenID Connect requests.
    /// </summary>
    public class OpenIddictValidationAspNetCoreHandler : AuthenticationHandler<OpenIddictValidationAspNetCoreOptions>,
        IAuthenticationRequestHandler
    {
        private readonly IOpenIddictValidationProvider _provider;

        /// <summary>
        /// Creates a new instance of the <see cref="OpenIddictValidationAspNetCoreHandler"/> class.
        /// </summary>
        public OpenIddictValidationAspNetCoreHandler(
            [NotNull] IOpenIddictValidationProvider provider,
            [NotNull] IOptionsMonitor<OpenIddictValidationAspNetCoreOptions> options,
            [NotNull] ILoggerFactory logger,
            [NotNull] UrlEncoder encoder,
            [NotNull] ISystemClock clock)
            : base(options, logger, encoder, clock)
            => _provider = provider;

        public async Task<bool> HandleRequestAsync()
        {
            // Note: the transaction may be already attached when replaying an ASP.NET Core request
            // (e.g when using the built-in status code pages middleware with the re-execute mode).
            var transaction = Context.Features.Get<OpenIddictValidationAspNetCoreFeature>()?.Transaction;
            if (transaction == null)
            {
                // Create a new transaction and attach the HTTP request to make it available to the ASP.NET Core handlers.
                transaction = await _provider.CreateTransactionAsync();
                transaction.Properties[typeof(HttpRequest).FullName] = new WeakReference<HttpRequest>(Request);

                // Attach the OpenIddict validation transaction to the ASP.NET Core features
                // so that it can retrieved while performing challenge/forbid operations.
                Context.Features.Set(new OpenIddictValidationAspNetCoreFeature { Transaction = transaction });
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

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var transaction = Context.Features.Get<OpenIddictValidationAspNetCoreFeature>()?.Transaction;
            if (transaction == null)
            {
                throw new InvalidOperationException("An identity cannot be extracted from this request.");
            }

            var context = new ProcessAuthenticationContext(transaction);
            await _provider.DispatchAsync(context);

            if (context.Principal == null || context.IsRequestHandled || context.IsRequestSkipped)
            {
                return AuthenticateResult.NoResult();
            }

            else if (context.IsRejected)
            {
                var builder = new StringBuilder();

                if (!string.IsNullOrEmpty(context.Error))
                {
                    builder.AppendLine("An error occurred while authenticating the current request:");
                    builder.AppendFormat("Error code: ", context.Error);

                    if (!string.IsNullOrEmpty(context.ErrorDescription))
                    {
                        builder.AppendLine();
                        builder.AppendFormat("Error description: ", context.ErrorDescription);
                    }

                    if (!string.IsNullOrEmpty(context.ErrorUri))
                    {
                        builder.AppendLine();
                        builder.AppendFormat("Error URI: ", context.ErrorUri);
                    }
                }

                else
                {
                    builder.Append("An unknown error occurred while authenticating the current request.");
                }

                return AuthenticateResult.Fail(new Exception(builder.ToString())
                {
                    // Note: the error details are stored as additional exception properties,
                    // which is similar to what other ASP.NET Core security handlers do.
                    Data =
                    {
                        [Parameters.Error] = context.Error,
                        [Parameters.ErrorDescription] = context.ErrorDescription,
                        [Parameters.ErrorUri] = context.ErrorUri
                    }
                });
            }

            return AuthenticateResult.Success(new AuthenticationTicket(
                context.Principal,
                OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme));
        }

        protected override async Task HandleChallengeAsync([CanBeNull] AuthenticationProperties properties)
        {
            var transaction = Context.Features.Get<OpenIddictValidationAspNetCoreFeature>()?.Transaction;
            if (transaction == null)
            {
                throw new InvalidOperationException("An OpenID Connect response cannot be returned from this endpoint.");
            }

            var context = new ProcessChallengeContext(transaction)
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

            static string GetProperty(AuthenticationProperties properties, string name)
                => properties != null && properties.Items.TryGetValue(name, out string value) ? value : null;
        }

        protected override Task HandleForbiddenAsync([CanBeNull] AuthenticationProperties properties)
            => HandleChallengeAsync(properties);
    }
}
