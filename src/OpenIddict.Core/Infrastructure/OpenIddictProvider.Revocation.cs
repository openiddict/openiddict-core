/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Diagnostics;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace OpenIddict.Infrastructure {
    public partial class OpenIddictProvider<TUser, TApplication, TAuthorization, TScope, TToken> : OpenIdConnectServerProvider
        where TUser : class where TApplication : class where TAuthorization : class where TScope : class where TToken : class {
        public override async Task ValidateRevocationRequest([NotNull] ValidateRevocationRequestContext context) {
            var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TUser, TApplication, TAuthorization, TScope, TToken>>();

            // When token_type_hint is specified, reject the request if it doesn't correspond to a revocable token.
            if (!string.IsNullOrEmpty(context.Request.TokenTypeHint) &&
                !string.Equals(context.Request.TokenTypeHint, OpenIdConnectConstants.TokenTypeHints.AuthorizationCode) &&
                !string.Equals(context.Request.TokenTypeHint, OpenIdConnectConstants.TokenTypeHints.RefreshToken)) {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.UnsupportedTokenType,
                    description: "Only authorization codes and refresh tokens can be revoked. When specifying a token_type_hint " +
                                 "parameter, its value must be equal to 'authorization_code' or 'refresh_token'.");

                return;
            }

            // Skip client authentication if the client identifier is missing.
            // Note: the OpenID Connect server middleware will automatically ensure that
            // the calling application cannot revoke a refresh token if it's not
            // the intended audience, even if client authentication was skipped.
            if (string.IsNullOrEmpty(context.ClientId)) {
                services.Logger.LogInformation("The revocation request validation process was skipped " +
                                               "because the client_id parameter was missing or empty.");

                context.Skip();

                return;
            }

            // Retrieve the application details corresponding to the requested client_id.
            var application = await services.Applications.FindByClientIdAsync(context.ClientId);
            if (application == null) {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Application not found in the database: ensure that your client_id is correct.");

                return;
            }

            // Reject revocation requests containing a client_secret if the client application is not confidential.
            if (await services.Applications.IsPublicAsync(application)) {
                // Reject tokens requests containing a client_secret when the client is a public application.
                if (!string.IsNullOrEmpty(context.ClientSecret)) {
                    context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidRequest,
                        description: "Public clients are not allowed to send a client_secret.");

                    return;
                }

                services.Logger.LogInformation("The revocation request validation process was not fully validated because " +
                                               "the client '{ClientId}' was a public application.", context.ClientId);

                // If client authentication cannot be enforced, call context.Skip() to inform
                // the OpenID Connect server middleware that the caller cannot be fully trusted.
                context.Skip();

                return;
            }

            // Confidential applications MUST authenticate
            // to protect them from impersonation attacks.
            if (string.IsNullOrEmpty(context.ClientSecret)) {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Missing credentials: ensure that you specified a client_secret.");

                return;
            }

            if (!await services.Applications.ValidateSecretAsync(application, context.ClientSecret)) {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Invalid credentials: ensure that you specified a correct client_secret.");

                return;
            }

            context.Validate();
        }

        public override async Task HandleRevocationRequest([NotNull] HandleRevocationRequestContext context) {
            var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TUser, TApplication, TAuthorization, TScope, TToken>>();

            Debug.Assert(context.Ticket != null, "The authentication ticket shouldn't be null.");

            // If the received token is not an authorization code or a refresh token,
            // return an error to indicate that the token cannot be revoked.
            if (!context.Ticket.IsAuthorizationCode() && !context.Ticket.IsRefreshToken()) {
                services.Logger.LogError("The revocation request was rejected because the token was not revocable.");

                context.Reject(
                    error: OpenIdConnectConstants.Errors.UnsupportedTokenType,
                    description: "Only authorization codes and refresh tokens can be revoked.");

                return;
            }

            // Extract the token identifier from the authentication ticket.
            var identifier = context.Ticket.GetTicketId();
            Debug.Assert(!string.IsNullOrEmpty(identifier), "The token should contain a ticket identifier.");

            // Retrieve the token from the database. If the token cannot be found,
            // assume it is invalid and consider the revocation as successful.
            var token = await services.Tokens.FindByIdAsync(identifier);
            if (token == null) {
                services.Logger.LogInformation("The token '{Identifier}' was already revoked.", identifier);

                context.Revoked = true;

                return;
            }

            // Revoke the token.
            await services.Tokens.RevokeAsync(token);

            services.Logger.LogInformation("The token '{Identifier}' was successfully revoked.", identifier);

            context.Revoked = true;
        }
    }
}