/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;

namespace OpenIddict.Server
{
    /// <summary>
    /// Provides the logic necessary to extract, validate and handle OpenID Connect requests.
    /// </summary>
    internal sealed partial class OpenIddictServerProvider : OpenIdConnectServerProvider
    {
        public override Task ExtractIntrospectionRequest([NotNull] ExtractIntrospectionRequestContext context)
            => _eventDispatcher.DispatchAsync(new OpenIddictServerEvents.ExtractIntrospectionRequest(context));

        public override async Task ValidateIntrospectionRequest([NotNull] ValidateIntrospectionRequestContext context)
        {
            var options = (OpenIddictServerOptions) context.Options;

            // Note: the OpenID Connect server middleware supports unauthenticated introspection requests
            // but OpenIddict uses a stricter policy preventing unauthenticated/public applications
            // from using the introspection endpoint, as required by the specifications.
            // See https://tools.ietf.org/html/rfc7662#section-2.1 for more information.
            if (string.IsNullOrEmpty(context.ClientId) || string.IsNullOrEmpty(context.ClientSecret))
            {
                context.Reject(
                    error: OpenIddictConstants.Errors.InvalidRequest,
                    description: "The mandatory 'client_id' and/or 'client_secret' parameters are missing.");

                return;
            }

            // Retrieve the application details corresponding to the requested client_id.
            var application = await _applicationManager.FindByClientIdAsync(context.ClientId);
            if (application == null)
            {
                _logger.LogError("The introspection request was rejected because the client " +
                                 "application was not found: '{ClientId}'.", context.ClientId);

                context.Reject(
                    error: OpenIddictConstants.Errors.InvalidClient,
                    description: "The specified 'client_id' parameter is invalid.");

                return;
            }

            // Reject the request if the application is not allowed to use the introspection endpoint.
            if (!options.IgnoreEndpointPermissions &&
                !await _applicationManager.HasPermissionAsync(application, OpenIddictConstants.Permissions.Endpoints.Introspection))
            {
                _logger.LogError("The introspection request was rejected because the application '{ClientId}' " +
                                 "was not allowed to use the introspection endpoint.", context.ClientId);

                context.Reject(
                    error: OpenIddictConstants.Errors.UnauthorizedClient,
                    description: "This client application is not allowed to use the introspection endpoint.");

                return;
            }

            // Reject introspection requests sent by public applications.
            if (await _applicationManager.IsPublicAsync(application))
            {
                _logger.LogError("The introspection request was rejected because the public application " +
                                 "'{ClientId}' was not allowed to use this endpoint.", context.ClientId);

                context.Reject(
                    error: OpenIddictConstants.Errors.InvalidClient,
                    description: "This client application is not allowed to use the introspection endpoint.");

                return;
            }

            // Validate the client credentials.
            if (!await _applicationManager.ValidateClientSecretAsync(application, context.ClientSecret))
            {
                _logger.LogError("The introspection request was rejected because the confidential or hybrid application " +
                                 "'{ClientId}' didn't specify valid client credentials.", context.ClientId);

                context.Reject(
                    error: OpenIddictConstants.Errors.InvalidClient,
                    description: "The specified client credentials are invalid.");

                return;
            }

            context.Validate();

            await _eventDispatcher.DispatchAsync(new OpenIddictServerEvents.ValidateIntrospectionRequest(context));
        }

        public override async Task HandleIntrospectionRequest([NotNull] HandleIntrospectionRequestContext context)
        {
            var options = (OpenIddictServerOptions) context.Options;

            Debug.Assert(context.Ticket != null, "The authentication ticket shouldn't be null.");
            Debug.Assert(!string.IsNullOrEmpty(context.Request.ClientId), "The client_id parameter shouldn't be null.");

            var identifier = context.Ticket.GetInternalTokenId();
            Debug.Assert(!string.IsNullOrEmpty(identifier), "The authentication ticket should contain a token identifier.");

            if (!context.Ticket.IsAccessToken())
            {
                _logger.LogError("The token '{Identifier}' is not an access token and thus cannot be introspected.", identifier);

                context.Active = false;

                return;
            }

            // Note: the OpenID Connect server middleware allows authorized presenters (e.g relying parties) to introspect
            // tokens but OpenIddict uses a stricter policy that only allows resource servers to use the introspection endpoint.
            // For that, an error is automatically returned if no explicit audience is attached to the authentication ticket.
            if (!context.Ticket.HasAudience())
            {
                _logger.LogError("The token '{Identifier}' doesn't have any audience attached " +
                                 "and cannot be introspected. To add an audience, use the " +
                                 "'ticket.SetResources(...)' extension when creating the ticket.", identifier);

                context.Active = false;

                return;
            }

            if (!context.Ticket.HasAudience(context.Request.ClientId))
            {
                _logger.LogError("The client application '{ClientId}' is not allowed to introspect the access " +
                                 "token '{Identifier}' because it's not listed as a valid audience.",
                                 context.Request.ClientId, identifier);

                context.Active = false;

                return;
            }

            // If an authorization was attached to the access token, ensure it is still valid.
            if (!options.DisableAuthorizationStorage && !string.IsNullOrEmpty(context.Ticket.GetInternalAuthorizationId()))
            {
                var authorization = await _authorizationManager.FindByIdAsync(context.Ticket.GetInternalAuthorizationId());
                if (authorization == null || !await _authorizationManager.IsValidAsync(authorization))
                {
                    _logger.LogError("The token '{Identifier}' was declared as inactive because " +
                                     "the associated authorization was no longer valid.", identifier);

                    context.Active = false;

                    return;
                }
            }

            // If the received token is a reference access token - i.e a token for
            // which an entry exists in the database - ensure it is still valid.
            if (options.UseReferenceTokens)
            {
                var token = await _tokenManager.FindByIdAsync(identifier);
                if (token == null || !await _tokenManager.IsValidAsync(token))
                {
                    _logger.LogInformation("The token '{Identifier}' was declared as inactive because it was " +
                                           "not found in the database or was no longer valid.", identifier);

                    context.Active = false;

                    return;
                }
            }

            await _eventDispatcher.DispatchAsync(new OpenIddictServerEvents.HandleIntrospectionRequest(context));
        }

        public override Task ApplyIntrospectionResponse([NotNull] ApplyIntrospectionResponseContext context)
            => _eventDispatcher.DispatchAsync(new OpenIddictServerEvents.ApplyIntrospectionResponse(context));
    }
}
