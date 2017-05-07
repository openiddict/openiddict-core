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
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Core;

namespace OpenIddict
{
    public partial class OpenIddictProvider<TApplication, TAuthorization, TScope, TToken> : OpenIdConnectServerProvider
        where TApplication : class where TAuthorization : class where TScope : class where TToken : class
    {
        public override Task ExtractIntrospectionRequest([NotNull] ExtractIntrospectionRequestContext context)
        {
            // Note: the OpenID Connect server middleware supports both GET and POST
            // introspection requests but OpenIddict only accepts POST requests.
            if (!string.Equals(context.HttpContext.Request.Method, "POST", StringComparison.OrdinalIgnoreCase))
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "Introspection requests must use HTTP POST.");

                return Task.FromResult(0);
            }

            return Task.FromResult(0);
        }

        public override async Task ValidateIntrospectionRequest([NotNull] ValidateIntrospectionRequestContext context)
        {
            var applications = context.HttpContext.RequestServices.GetRequiredService<OpenIddictApplicationManager<TApplication>>();
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<OpenIddictProvider<TApplication, TAuthorization, TScope, TToken>>>();

            // Note: the OpenID Connect server middleware supports unauthenticated introspection requests
            // but OpenIddict uses a stricter policy preventing unauthenticated/public applications
            // from using the introspection endpoint, as required by the specifications.
            // See https://tools.ietf.org/html/rfc7662#section-2.1 for more information.
            if (string.IsNullOrEmpty(context.ClientId) || string.IsNullOrEmpty(context.ClientSecret))
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "Clients must be authenticated to use the introspection endpoint.");

                return;
            }

            // Retrieve the application details corresponding to the requested client_id.
            var application = await applications.FindByClientIdAsync(context.ClientId, context.HttpContext.RequestAborted);
            if (application == null)
            {
                logger.LogError("The introspection request was rejected because the client " +
                                "application was not found: '{ClientId}'.", context.ClientId);

                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Application not found in the database: ensure that your client_id is correct.");

                return;
            }

            // Reject non-confidential applications.
            if (!await applications.IsConfidentialAsync(application, context.HttpContext.RequestAborted))
            {
                logger.LogError("The introspection request was rejected because the public application " +
                                "'{ClientId}' was not allowed to use this endpoint.", context.ClientId);

                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Public applications are not allowed to use the introspection endpoint.");

                return;
            }

            // Validate the client credentials.
            if (!await applications.ValidateClientSecretAsync(application, context.ClientSecret, context.HttpContext.RequestAborted))
            {
                logger.LogError("The introspection request was rejected because the confidential application " +
                                "'{ClientId}' didn't specify valid client credentials.", context.ClientId);

                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Invalid credentials: ensure that you specified a correct client_secret.");

                return;
            }

            context.Validate();
        }

        public override async Task HandleIntrospectionRequest([NotNull] HandleIntrospectionRequestContext context)
        {
            var options = context.HttpContext.RequestServices.GetRequiredService<IOptions<OpenIddictOptions>>();
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<OpenIddictProvider<TApplication, TAuthorization, TScope, TToken>>>();
            var tokens = context.HttpContext.RequestServices.GetRequiredService<OpenIddictTokenManager<TToken>>();

            Debug.Assert(context.Ticket != null, "The authentication ticket shouldn't be null.");
            Debug.Assert(!string.IsNullOrEmpty(context.Request.ClientId), "The client_id parameter shouldn't be null.");

            var identifier = context.Ticket.GetProperty(OpenIdConnectConstants.Properties.TokenId);
            Debug.Assert(!string.IsNullOrEmpty(identifier), "The token identifier shouldn't be null or empty.");

            // Note: the OpenID Connect server middleware allows authorized presenters (e.g relying parties) to introspect access tokens
            // but OpenIddict uses a stricter policy that only allows resource servers to use the introspection endpoint, unless the ticket
            // doesn't have any audience: in this case, the caller is allowed to introspect the token even if it's not listed as a valid audience.
            if (context.Ticket.IsAccessToken() && context.Ticket.HasAudience() && !context.Ticket.HasAudience(context.Request.ClientId))
            {
                logger.LogWarning("The client application '{ClientId}' is not allowed to introspect the access " +
                                  "token '{Identifier}' because it's not listed as a valid audience.",
                                  context.Request.ClientId, identifier);

                context.Active = false;

                return;
            }

            // When the received ticket is revocable, ensure it is still valid.
            if (!options.Value.DisableTokenRevocation && (context.Ticket.IsAuthorizationCode() || context.Ticket.IsRefreshToken()))
            {
                // Retrieve the token from the database using the unique identifier stored in the authentication ticket:
                // if the corresponding entry cannot be found, return Active = false to indicate that is is no longer valid.
                var token = await tokens.FindByIdAsync(identifier, context.HttpContext.RequestAborted);
                if (token == null)
                {
                    logger.LogInformation("The token {Identifier} was declared as inactive because " +
                                          "it was revoked.", identifier);

                    context.Active = false;

                    return;
                }
            }
        }
    }
}