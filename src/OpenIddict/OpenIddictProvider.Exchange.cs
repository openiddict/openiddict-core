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
        public override async Task ValidateTokenRequest([NotNull] ValidateTokenRequestContext context)
        {
            var applications = context.HttpContext.RequestServices.GetRequiredService<OpenIddictApplicationManager<TApplication>>();
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<OpenIddictProvider<TApplication, TAuthorization, TScope, TToken>>>();
            var options = context.HttpContext.RequestServices.GetRequiredService<IOptions<OpenIddictOptions>>();

            // Reject token requests that don't specify a supported grant type.
            if (!options.Value.GrantTypes.Contains(context.Request.GrantType))
            {
                logger.LogError("The token request was rejected because the '{Grant}' " +
                                "grant is not supported.", context.Request.GrantType);

                context.Reject(
                    error: OpenIdConnectConstants.Errors.UnsupportedGrantType,
                    description: "The specified grant_type is not supported by this authorization server.");

                return;
            }

            // Reject token requests that specify scope=offline_access if the refresh token flow is not enabled.
            if (context.Request.HasScope(OpenIdConnectConstants.Scopes.OfflineAccess) &&
               !options.Value.GrantTypes.Contains(OpenIdConnectConstants.GrantTypes.RefreshToken))
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "The 'offline_access' scope is not allowed.");

                return;
            }

            // Optimization: the OpenID Connect server middleware automatically rejects grant_type=authorization_code
            // requests missing the redirect_uri parameter if one was specified in the initial authorization request.
            // Since OpenIddict doesn't allow redirect_uri-less authorization requests, an earlier check can be made here,
            // which saves the OpenID Connect server middleware from having to deserialize the authorization code ticket.
            // See http://openid.net/specs/openid-connect-core-1_0.html#TokenRequestValidation for more information.
            if (context.Request.IsAuthorizationCodeGrantType() && string.IsNullOrEmpty(context.Request.RedirectUri))
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "The mandatory 'redirect_uri' parameter was missing.");

                return;
            }

            // Note: the OpenID Connect server middleware allows returning a refresh token with grant_type=client_credentials,
            // though it's usually not recommended by the OAuth2 specification. To encourage developers to make a new
            // grant_type=client_credentials request instead of using refresh tokens, OpenIddict uses a stricter policy
            // that rejects grant_type=client_credentials requests containing the 'offline_access' scope.
            // See https://tools.ietf.org/html/rfc6749#section-4.4.3 for more information.
            if (context.Request.IsClientCredentialsGrantType() &&
                context.Request.HasScope(OpenIdConnectConstants.Scopes.OfflineAccess))
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "The 'offline_access' scope is not allowed when using grant_type=client_credentials.");

                return;
            }

            // Optimization: the OpenID Connect server middleware automatically rejects grant_type=client_credentials
            // requests when validation is skipped but an earlier check is made here to avoid making unnecessary
            // database roundtrips to retrieve the client application corresponding to the client_id.
            if (context.Request.IsClientCredentialsGrantType() && (string.IsNullOrEmpty(context.Request.ClientId) ||
                                                                   string.IsNullOrEmpty(context.Request.ClientSecret)))
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "Client applications must be authenticated to use the client credentials grant.");

                return;
            }

            // At this stage, skip client authentication if the client identifier is missing
            // or reject the token request if client identification is set as required.
            // Note: the OpenID Connect server middleware will automatically ensure that
            // the calling application cannot use an authorization code or a refresh token
            // if it's not the intended audience, even if client authentication was skipped.
            if (string.IsNullOrEmpty(context.ClientId))
            {
                // Reject the request if client identification is mandatory.
                if (options.Value.RequireClientIdentification)
                {
                    context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidRequest,
                        description: "The mandatory 'client_id' parameter was missing.");

                    return;
                }

                logger.LogDebug("The token request validation process was partially skipped " +
                                "because the 'client_id' parameter was missing or empty.");

                context.Skip();

                return;
            }

            // Retrieve the application details corresponding to the requested client_id.
            var application = await applications.FindByClientIdAsync(context.ClientId, context.HttpContext.RequestAborted);
            if (application == null)
            {
                logger.LogError("The token request was rejected because the client " +
                                "application was not found: '{ClientId}'.", context.ClientId);

                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Application not found in the database: ensure that your client_id is correct.");

                return;
            }

            if (await applications.IsPublicAsync(application, context.HttpContext.RequestAborted))
            {
                // Note: public applications are not allowed to use the client credentials grant.
                if (context.Request.IsClientCredentialsGrantType())
                {
                    logger.LogError("The token request was rejected because the public client application '{ClientId}' " +
                                    "was not allowed to use the client credentials grant.", context.Request.ClientId);

                    context.Reject(
                        error: OpenIdConnectConstants.Errors.UnauthorizedClient,
                        description: "Public clients are not allowed to use the client credentials grant.");

                    return;
                }

                // Reject tokens requests containing a client_secret when the client is a public application.
                if (!string.IsNullOrEmpty(context.ClientSecret))
                {
                    logger.LogError("The token request was rejected because the public application '{ClientId}' " +
                                    "was not allowed to send a client secret.", context.ClientId);

                    context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidRequest,
                        description: "Public clients are not allowed to send a client_secret.");

                    return;
                }

                logger.LogInformation("The token request validation process was not fully validated because " +
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
                logger.LogError("The token request was rejected because the confidential application " +
                                "'{ClientId}' didn't specify a client secret.", context.ClientId);

                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Missing credentials: ensure that you specified a client_secret.");

                return;
            }

            if (!await applications.ValidateClientSecretAsync(application, context.ClientSecret, context.HttpContext.RequestAborted))
            {
                logger.LogError("The token request was rejected because the confidential application " +
                                "'{ClientId}' didn't specify valid client credentials.", context.ClientId);

                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Invalid credentials: ensure that you specified a correct client_secret.");

                return;
            }

            context.Validate();
        }

        public override async Task HandleTokenRequest([NotNull] HandleTokenRequestContext context)
        {
            var options = context.HttpContext.RequestServices.GetRequiredService<IOptions<OpenIddictOptions>>();
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<OpenIddictProvider<TApplication, TAuthorization, TScope, TToken>>>();
            var tokens = context.HttpContext.RequestServices.GetRequiredService<OpenIddictTokenManager<TToken>>();

            if (!options.Value.DisableTokenRevocation && (context.Request.IsAuthorizationCodeGrantType() ||
                                                          context.Request.IsRefreshTokenGrantType()))
            {
                Debug.Assert(context.Ticket != null, "The authentication ticket shouldn't be null.");

                // Extract the token identifier from the authentication ticket.
                var identifier = context.Ticket.GetProperty(OpenIdConnectConstants.Properties.TokenId);
                Debug.Assert(!string.IsNullOrEmpty(identifier), "The authentication ticket should contain a ticket identifier.");

                if (context.Request.IsAuthorizationCodeGrantType())
                {
                    // Retrieve the token from the database and ensure it is still valid.
                    var token = await tokens.FindByIdAsync(identifier, context.HttpContext.RequestAborted);
                    if (token == null)
                    {
                        logger.LogError("The token request was rejected because the authorization code was revoked.");

                        context.Reject(
                            error: OpenIdConnectConstants.Errors.InvalidGrant,
                            description: "The authorization code is no longer valid.");

                        return;
                    }

                    // Revoke the authorization code to prevent token reuse.
                    await tokens.RevokeAsync(token, context.HttpContext.RequestAborted);
                }

                else if (context.Request.IsRefreshTokenGrantType())
                {
                    // Retrieve the token from the database and ensure it is still valid.
                    var token = await tokens.FindByIdAsync(identifier, context.HttpContext.RequestAborted);
                    if (token == null)
                    {
                        logger.LogError("The token request was rejected because the refresh token was revoked.");

                        context.Reject(
                            error: OpenIdConnectConstants.Errors.InvalidGrant,
                            description: "The refresh token is no longer valid.");

                        return;
                    }

                    // When sliding expiration is enabled, immediately
                    // revoke the refresh token to prevent future reuse.
                    // See https://tools.ietf.org/html/rfc6749#section-6.
                    if (context.Options.UseSlidingExpiration)
                    {
                        await tokens.RevokeAsync(token, context.HttpContext.RequestAborted);
                    }
                }
            }

            // Invoke the rest of the pipeline to allow
            // the user code to handle the token request.
            context.SkipToNextMiddleware();
        }
    }
}