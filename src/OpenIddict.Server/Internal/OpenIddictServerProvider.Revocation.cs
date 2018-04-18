/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Diagnostics;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;

namespace OpenIddict.Server
{
    public partial class OpenIddictServerProvider<TApplication, TAuthorization, TScope, TToken> : OpenIdConnectServerProvider
        where TApplication : class where TAuthorization : class where TScope : class where TToken : class
    {
        public override async Task ValidateRevocationRequest([NotNull] ValidateRevocationRequestContext context)
        {
            var options = (OpenIddictServerOptions) context.Options;

            Debug.Assert(!options.DisableTokenRevocation, "Token revocation support shouldn't be disabled at this stage.");

            // When token_type_hint is specified, reject the request if it doesn't correspond to a revocable token.
            if (!string.IsNullOrEmpty(context.Request.TokenTypeHint))
            {
                if (string.Equals(context.Request.TokenTypeHint, OpenIdConnectConstants.TokenTypeHints.IdToken))
                {
                    context.Reject(
                        error: OpenIdConnectConstants.Errors.UnsupportedTokenType,
                        description: "The specified 'token_type_hint' parameter is not supported.");

                    return;
                }

                if (!options.UseReferenceTokens &&
                    string.Equals(context.Request.TokenTypeHint, OpenIdConnectConstants.TokenTypeHints.AccessToken))
                {
                    context.Reject(
                        error: OpenIdConnectConstants.Errors.UnsupportedTokenType,
                        description: "The specified 'token_type_hint' parameter is not supported.");

                    return;
                }
            }

            // Skip client authentication if the client identifier is missing or reject
            // the revocation request if client identification is set as required.
            // Note: the OpenID Connect server middleware will automatically ensure that
            // the calling application cannot revoke a refresh token if it's not
            // the intended audience, even if client authentication was skipped.
            if (string.IsNullOrEmpty(context.ClientId))
            {
                // Reject the request if client identification is mandatory.
                if (options.RequireClientIdentification)
                {
                    Logger.LogError("The revocation request was rejected becaused the " +
                                    "mandatory client_id parameter was missing or empty.");

                    context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidRequest,
                        description: "The mandatory 'client_id' parameter is missing.");

                    return;
                }

                Logger.LogDebug("The revocation request validation process was skipped " +
                                "because the client_id parameter was missing or empty.");

                context.Skip();

                return;
            }

            // Retrieve the application details corresponding to the requested client_id.
            var application = await Applications.FindByClientIdAsync(context.ClientId);
            if (application == null)
            {
                Logger.LogError("The revocation request was rejected because the client " +
                                "application was not found: '{ClientId}'.", context.ClientId);

                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "The specified 'client_id' parameter is invalid.");

                return;
            }

            // Store the application entity as a request property to make it accessible
            // from the other provider methods without having to call the store twice.
            context.Request.SetProperty($"{OpenIddictConstants.Properties.Application}:{context.ClientId}", application);

            // Reject the request if the application is not allowed to use the revocation endpoint.
            if (!await Applications.HasPermissionAsync(application, OpenIddictConstants.Permissions.Endpoints.Revocation))
            {
                Logger.LogError("The revocation request was rejected because the application '{ClientId}' " +
                                "was not allowed to use the revocation endpoint.", context.ClientId);

                context.Reject(
                    error: OpenIdConnectConstants.Errors.UnauthorizedClient,
                    description: "This client application is not allowed to use the revocation endpoint.");

                return;
            }

            // Reject revocation requests containing a client_secret if the application is a public client.
            if (await Applications.IsPublicAsync(application))
            {
                if (!string.IsNullOrEmpty(context.ClientSecret))
                {
                    Logger.LogError("The revocation request was rejected because the public application " +
                                    "'{ClientId}' was not allowed to use this endpoint.", context.ClientId);

                    context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidRequest,
                        description: "The 'client_secret' parameter is not valid for this client application.");

                    return;
                }

                Logger.LogDebug("The revocation request validation process was not fully validated because " +
                                "the client '{ClientId}' was a public application.", context.ClientId);

                // If client authentication cannot be enforced, call context.Skip() to inform
                // the OpenID Connect server middleware that the caller cannot be fully trusted.
                context.Skip();

                return;
            }

            // Confidential and hybrid applications MUST authenticate
            // to protect them from impersonation attacks.
            if (string.IsNullOrEmpty(context.ClientSecret))
            {
                Logger.LogError("The revocation request was rejected because the confidential or hybrid application " +
                                "'{ClientId}' didn't specify a client secret.", context.ClientId);

                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "The 'client_secret' parameter required for this client application is missing.");

                return;
            }

            if (!await Applications.ValidateClientSecretAsync(application, context.ClientSecret))
            {
                Logger.LogError("The revocation request was rejected because the confidential or hybrid application " +
                                "'{ClientId}' didn't specify valid client credentials.", context.ClientId);

                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "The specified client credentials are invalid.");

                return;
            }

            context.Validate();
        }

        public override async Task HandleRevocationRequest([NotNull] HandleRevocationRequestContext context)
        {
            var options = (OpenIddictServerOptions) context.Options;

            Debug.Assert(context.Ticket != null, "The authentication ticket shouldn't be null.");

            // If the received token is not an authorization code or a refresh token,
            // return an error to indicate that the token cannot be revoked.
            if (context.Ticket.IsIdentityToken())
            {
                Logger.LogError("The revocation request was rejected because identity tokens are not revocable.");

                context.Reject(
                    error: OpenIdConnectConstants.Errors.UnsupportedTokenType,
                    description: "The specified token cannot be revoked.");

                return;
            }

            // If the received token is an access token, return an error if reference tokens are not enabled.
            if (!options.UseReferenceTokens && context.Ticket.IsAccessToken())
            {
                Logger.LogError("The revocation request was rejected because the access token was not revocable.");

                context.Reject(
                    error: OpenIdConnectConstants.Errors.UnsupportedTokenType,
                    description: "The specified token cannot be revoked.");

                return;
            }

            // Extract the token identifier from the authentication ticket.
            var identifier = context.Ticket.GetTokenId();
            Debug.Assert(!string.IsNullOrEmpty(identifier), "The authentication ticket should contain a token identifier.");

            // Retrieve the token from the request properties. If it's already marked as revoked, directly return a 200 response.
            var token = context.Request.GetProperty<TToken>($"{OpenIddictConstants.Properties.Token}:{identifier}");
            Debug.Assert(token != null, "The token shouldn't be null.");

            if (await Tokens.IsRevokedAsync(token))
            {
                Logger.LogInformation("The token '{Identifier}' was not revoked because " +
                                      "it was already marked as invalid.", identifier);

                context.Revoked = true;

                return;
            }

            // Try to revoke the token. If an exception is thrown,
            // log and swallow it to ensure that a valid response
            // will be returned to the client application.
            try
            {
                await Tokens.RevokeAsync(token);
            }

            catch (Exception exception)
            {
                Logger.LogWarning(exception, "An exception occurred while trying to revoke the authorization " +
                                             "associated with the token '{Identifier}'.", identifier);

                return;
            }

            Logger.LogInformation("The token '{Identifier}' was successfully revoked.", identifier);

            context.Revoked = true;
        }
    }
}