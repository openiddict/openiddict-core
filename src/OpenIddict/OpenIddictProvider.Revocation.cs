/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Core;

namespace OpenIddict
{
    public partial class OpenIddictProvider<TApplication, TAuthorization, TScope, TToken> : OpenIdConnectServerProvider
        where TApplication : class where TAuthorization : class where TScope : class where TToken : class
    {
        public override async Task ValidateRevocationRequest([NotNull] ValidateRevocationRequestContext context)
        {
            var applications = context.HttpContext.RequestServices.GetRequiredService<OpenIddictApplicationManager<TApplication>>();
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<OpenIddictProvider<TApplication, TAuthorization, TScope, TToken>>>();
            var options = context.HttpContext.RequestServices.GetRequiredService<IOptions<OpenIddictOptions>>();

            Debug.Assert(!options.Value.DisableTokenRevocation, "Token revocation support shouldn't be disabled at this stage.");

            // When token_type_hint is specified, reject the request if it doesn't correspond to a revocable token.
            if (!string.IsNullOrEmpty(context.Request.TokenTypeHint) &&
                !string.Equals(context.Request.TokenTypeHint, OpenIdConnectConstants.TokenTypeHints.AuthorizationCode) &&
                !string.Equals(context.Request.TokenTypeHint, OpenIdConnectConstants.TokenTypeHints.RefreshToken))
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.UnsupportedTokenType,
                    description: "Only authorization codes and refresh tokens can be revoked. When specifying a token_type_hint " +
                                 "parameter, its value must be equal to 'authorization_code' or 'refresh_token'.");

                return;
            }

            // Skip client authentication if the client identifier is missing or reject
            // the revocation request if client identification is set as required.
            // Note: the OpenID Connect server middleware will automatically ensure that
            // the calling application cannot revoke a refresh token if it's not
            // the intended audience, even if client authentication was skipped.
            if (string.IsNullOrEmpty(context.ClientId))
            {
                // Reject the request if client identification is mandatory.
                if (options.Value.RequireClientIdentification)
                {
                    logger.LogError("The revocation request was rejected becaused the " +
                                    "mandatory client_id parameter was missing or empty.");

                    context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidRequest,
                        description: "The mandatory 'client_id' parameter was missing.");

                    return;
                }

                logger.LogInformation("The revocation request validation process was skipped " +
                                      "because the client_id parameter was missing or empty.");

                context.Skip();

                return;
            }

            // Retrieve the application details corresponding to the requested client_id.
            var application = await applications.FindByClientIdAsync(context.ClientId, context.HttpContext.RequestAborted);
            if (application == null)
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Application not found in the database: ensure that your client_id is correct.");

                return;
            }

            // Reject revocation requests containing a client_secret if the client application is not confidential.
            if (await applications.IsPublicAsync(application, context.HttpContext.RequestAborted))
            {
                // Reject tokens requests containing a client_secret when the client is a public application.
                if (!string.IsNullOrEmpty(context.ClientSecret))
                {
                    context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidRequest,
                        description: "Public clients are not allowed to send a client_secret.");

                    return;
                }

                logger.LogInformation("The revocation request validation process was not fully validated because " +
                                      "the client '{ClientId}' was a public application.", context.ClientId);

                // If client authentication cannot be enforced, call context.Skip() to inform
                // the OpenID Connect server middleware that the caller cannot be fully trusted.
                context.Skip();

                return;
            }

            // Confidential applications MUST authenticate
            // to protect them from impersonation attacks.
            if (string.IsNullOrEmpty(context.ClientSecret))
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Missing credentials: ensure that you specified a client_secret.");

                return;
            }

            if (!await applications.ValidateClientSecretAsync(application, context.ClientSecret, context.HttpContext.RequestAborted))
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Invalid credentials: ensure that you specified a correct client_secret.");

                return;
            }

            context.Validate();
        }

        public override async Task HandleRevocationRequest([NotNull] HandleRevocationRequestContext context)
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<OpenIddictProvider<TApplication, TAuthorization, TScope, TToken>>>();
            var tokens = context.HttpContext.RequestServices.GetRequiredService<OpenIddictTokenManager<TToken>>();

            Debug.Assert(context.Ticket != null, "The authentication ticket shouldn't be null.");

            // If the received token is not an authorization code or a refresh token,
            // return an error to indicate that the token cannot be revoked.
            if (!context.Ticket.IsAuthorizationCode() && !context.Ticket.IsRefreshToken())
            {
                logger.LogError("The revocation request was rejected because the token was not revocable.");

                context.Reject(
                    error: OpenIdConnectConstants.Errors.UnsupportedTokenType,
                    description: "Only authorization codes and refresh tokens can be revoked.");

                return;
            }

            // Extract the token identifier from the authentication ticket.
            var identifier = context.Ticket.GetProperty(OpenIdConnectConstants.Properties.TokenId);
            Debug.Assert(!string.IsNullOrEmpty(identifier), "The token should contain a ticket identifier.");

            // Retrieve the token from the database. If the token cannot be found,
            // assume it is invalid and consider the revocation as successful.
            var token = await tokens.FindByIdAsync(identifier, context.HttpContext.RequestAborted);
            if (token == null)
            {
                logger.LogInformation("The token '{Identifier}' was already revoked.", identifier);

                context.Revoked = true;

                return;
            }

            // Revoke the token.
            await tokens.RevokeAsync(token, context.HttpContext.RequestAborted);

            logger.LogInformation("The token '{Identifier}' was successfully revoked.", identifier);

            context.Revoked = true;
        }
    }
}