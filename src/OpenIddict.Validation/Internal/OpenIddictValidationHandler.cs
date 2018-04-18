/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using AspNet.Security.OAuth.Validation;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using Newtonsoft.Json.Linq;
using OpenIddict.Abstractions;
using OpenIddict.Core;

namespace OpenIddict.Validation
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class OpenIddictValidationHandler : OAuthValidationHandler
    {
        public OpenIddictValidationHandler(
            [NotNull] IOptionsMonitor<OpenIddictValidationOptions> options,
            [NotNull] ILoggerFactory logger,
            [NotNull] UrlEncoder encoder,
            [NotNull] ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }
    }

    [EditorBrowsable(EditorBrowsableState.Never)]
    public class OpenIddictValidationHandler<TToken> : OpenIddictValidationHandler where TToken : class
    {
        public OpenIddictValidationHandler(
            [NotNull] IOptionsMonitor<OpenIddictValidationOptions> options,
            [NotNull] ILoggerFactory logger,
            [NotNull] UrlEncoder encoder,
            [NotNull] ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var context = new RetrieveTokenContext(Context, Scheme, Options);
            await Events.RetrieveToken(context);

            if (context.Result != null)
            {
                Logger.LogInformation("The default authentication handling was skipped from user code.");

                return context.Result;
            }

            var token = context.Token;

            if (string.IsNullOrEmpty(token))
            {
                // Try to retrieve the access token from the authorization header.
                string header = Request.Headers[HeaderNames.Authorization];
                if (string.IsNullOrEmpty(header))
                {
                    Logger.LogDebug("Authentication was skipped because no bearer token was received.");

                    return AuthenticateResult.NoResult();
                }

                // Ensure that the authorization header contains the mandatory "Bearer" scheme.
                // See https://tools.ietf.org/html/rfc6750#section-2.1
                if (!header.StartsWith(OAuthValidationConstants.Schemes.Bearer + ' ', StringComparison.OrdinalIgnoreCase))
                {
                    Logger.LogDebug("Authentication was skipped because an incompatible " +
                                    "scheme was used in the 'Authorization' header.");

                    return AuthenticateResult.NoResult();
                }

                // Extract the token from the authorization header.
                token = header.Substring(OAuthValidationConstants.Schemes.Bearer.Length + 1).Trim();

                if (string.IsNullOrEmpty(token))
                {
                    Logger.LogDebug("Authentication was skipped because the bearer token " +
                                    "was missing from the 'Authorization' header.");

                    return AuthenticateResult.NoResult();
                }
            }

            // Try to unprotect the token and return an error
            // if the ticket can't be decrypted or validated.
            var result = await CreateTicketAsync(token);
            if (!result.Succeeded)
            {
                Context.Features.Set(new OAuthValidationFeature
                {
                    Error = new OAuthValidationError
                    {
                        Error = OAuthValidationConstants.Errors.InvalidToken,
                        ErrorDescription = "The access token is not valid."
                    }
                });

                return result;
            }

            // Ensure that the authentication ticket is still valid.
            var ticket = result.Ticket;
            if (ticket.Properties.ExpiresUtc.HasValue &&
                ticket.Properties.ExpiresUtc.Value < Options.SystemClock.UtcNow)
            {
                Context.Features.Set(new OAuthValidationFeature
                {
                    Error = new OAuthValidationError
                    {
                        Error = OAuthValidationConstants.Errors.InvalidToken,
                        ErrorDescription = "The access token is no longer valid."
                    }
                });

                return AuthenticateResult.Fail("Authentication failed because the access token was expired.");
            }

            // Ensure that the access token was issued
            // to be used with this resource server.
            if (!ValidateAudience(ticket))
            {
                Context.Features.Set(new OAuthValidationFeature
                {
                    Error = new OAuthValidationError
                    {
                        Error = OAuthValidationConstants.Errors.InvalidToken,
                        ErrorDescription = "The access token is not valid for this resource server."
                    }
                });

                return AuthenticateResult.Fail("Authentication failed because the access token " +
                                               "was not valid for this resource server.");
            }

            var notification = new ValidateTokenContext(Context, Scheme, Options, ticket);
            await Events.ValidateToken(notification);

            if (notification.Result != null)
            {
                Logger.LogInformation("The default authentication handling was skipped from user code.");

                return notification.Result;
            }

            // Optimization: avoid allocating a new AuthenticationTicket
            // if the principal/properties instances were not replaced.
            if (ReferenceEquals(notification.Principal, ticket.Principal) &&
                ReferenceEquals(notification.Properties, ticket.Properties))
            {
                return AuthenticateResult.Success(ticket);
            }

            return AuthenticateResult.Success(new AuthenticationTicket(
                notification.Principal, notification.Properties, Scheme.Name));
        }

        private bool ValidateAudience(AuthenticationTicket ticket)
        {
            // If no explicit audience has been configured,
            // skip the default audience validation.
            if (Options.Audiences.Count == 0)
            {
                return true;
            }

            // Extract the audiences from the authentication ticket.
            var audiences = ticket.Properties.GetProperty(OAuthValidationConstants.Properties.Audiences);
            if (string.IsNullOrEmpty(audiences))
            {
                return false;
            }

            // Ensure that the authentication ticket contains one of the registered audiences.
            foreach (var audience in JArray.Parse(audiences).Values<string>())
            {
                if (Options.Audiences.Contains(audience))
                {
                    return true;
                }
            }

            return false;
        }

        private async Task<AuthenticateResult> CreateTicketAsync(string payload)
        {
            var manager = Context.RequestServices.GetService<OpenIddictTokenManager<TToken>>();
            if (manager == null)
            {
                throw new InvalidOperationException("The token manager was not correctly registered.");
            }

            // Retrieve the token entry from the database. If it
            // cannot be found, assume the token is not valid.
            var token = await manager.FindByReferenceIdAsync(payload);
            if (token == null)
            {
                return AuthenticateResult.Fail("Authentication failed because the access token cannot be found in the database.");
            }

            // Extract the encrypted payload from the token. If it's null or empty,
            // assume the token is not a reference token and consider it as invalid.
            var ciphertext = await manager.GetPayloadAsync(token);
            if (string.IsNullOrEmpty(ciphertext))
            {
                return AuthenticateResult.Fail("Authentication failed because the access token is not a reference token.");
            }

            var ticket = Options.AccessTokenFormat.Unprotect(ciphertext);
            if (ticket == null)
            {
                return AuthenticateResult.Fail(
                    "Authentication failed because the reference token cannot be decrypted. " +
                    "This may indicate that the token entry is corrupted or tampered.");
            }

            // Dynamically set the creation and expiration dates.
            ticket.Properties.IssuedUtc = await manager.GetCreationDateAsync(token);
            ticket.Properties.ExpiresUtc = await manager.GetExpirationDateAsync(token);

            // Restore the token and authorization identifiers attached with the database entry.
            ticket.Properties.SetProperty(OpenIddictConstants.Properties.TokenId, await manager.GetIdAsync(token));
            ticket.Properties.SetProperty(OpenIddictConstants.Properties.AuthorizationId,
                await manager.GetAuthorizationIdAsync(token));

            if (Options.SaveToken)
            {
                // Store the access token in the authentication ticket.
                ticket.Properties.StoreTokens(new[]
                {
                    new AuthenticationToken { Name = OAuthValidationConstants.Properties.Token, Value = payload }
                });
            }

            // Resolve the primary identity associated with the principal.
            var identity = (ClaimsIdentity) ticket.Principal.Identity;

            // Copy the scopes extracted from the authentication ticket to the
            // ClaimsIdentity to make them easier to retrieve from application code.
            var scopes = ticket.Properties.GetProperty(OAuthValidationConstants.Properties.Scopes);
            if (!string.IsNullOrEmpty(scopes))
            {
                foreach (var scope in JArray.Parse(scopes).Values<string>())
                {
                    identity.AddClaim(new Claim(OAuthValidationConstants.Claims.Scope, scope));
                }
            }

            var notification = new CreateTicketContext(Context, Scheme, Options, ticket);
            await Events.CreateTicket(notification);

            if (notification.Result != null)
            {
                Logger.LogInformation("The default authentication handling was skipped from user code.");

                return notification.Result;
            }

            // Optimization: avoid allocating a new AuthenticationTicket
            // if the principal/properties instances were not replaced.
            if (ReferenceEquals(notification.Principal, ticket.Principal) &&
                ReferenceEquals(notification.Properties, ticket.Properties))
            {
                return AuthenticateResult.Success(ticket);
            }

            return AuthenticateResult.Success(new AuthenticationTicket(
                notification.Principal, notification.Properties, Scheme.Name));
        }

        private new OAuthValidationEvents Events => (OAuthValidationEvents) base.Events;
    }
}
