/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Bson;
using Newtonsoft.Json.Linq;
using OpenIddict.Abstractions;

namespace OpenIddict.Server
{
    /// <summary>
    /// Provides the logic necessary to extract, validate and handle OpenID Connect requests.
    /// </summary>
    internal sealed partial class OpenIddictServerProvider : OpenIdConnectServerProvider
    {
        public override async Task ExtractAuthorizationRequest([NotNull] ExtractAuthorizationRequestContext context)
        {
            var options = (OpenIddictServerOptions) context.Options;

            // Reject requests using the unsupported request parameter.
            if (!string.IsNullOrEmpty(context.Request.Request))
            {
                _logger.LogError("The authorization request was rejected because it contained " +
                                 "an unsupported parameter: {Parameter}.", "request");

                context.Reject(
                    error: OpenIddictConstants.Errors.RequestNotSupported,
                    description: "The 'request' parameter is not supported.");

                return;
            }

            // Reject requests using the unsupported request_uri parameter.
            if (!string.IsNullOrEmpty(context.Request.RequestUri))
            {
                _logger.LogError("The authorization request was rejected because it contained " +
                                 "an unsupported parameter: {Parameter}.", "request_uri");

                context.Reject(
                    error: OpenIddictConstants.Errors.RequestUriNotSupported,
                    description: "The 'request_uri' parameter is not supported.");

                return;
            }

            // If a request_id parameter can be found in the authorization request,
            // restore the complete authorization request from the distributed cache.
            if (!string.IsNullOrEmpty(context.Request.RequestId))
            {
                // Return an error if request caching support was not enabled.
                if (!options.EnableRequestCaching)
                {
                    _logger.LogError("The authorization request was rejected because " +
                                     "request caching support was not enabled.");

                    context.Reject(
                        error: OpenIddictConstants.Errors.InvalidRequest,
                        description: "The 'request_id' parameter is not supported.");

                    return;
                }

                // Note: the cache key is always prefixed with a specific marker
                // to avoid collisions with the other types of cached requests.
                var key = OpenIddictConstants.Environment.AuthorizationRequest + context.Request.RequestId;

                var payload = await options.Cache.GetAsync(key);
                if (payload == null)
                {
                    _logger.LogError("The authorization request was rejected because an unknown " +
                                     "or invalid request_id parameter was specified.");

                    context.Reject(
                        error: OpenIddictConstants.Errors.InvalidRequest,
                        description: "The specified 'request_id' parameter is invalid.");

                    return;
                }

                // Restore the authorization request parameters from the serialized payload.
                using (var reader = new BsonDataReader(new MemoryStream(payload)))
                {
                    foreach (var parameter in JObject.Load(reader))
                    {
                        // Avoid overriding the current request parameters.
                        if (context.Request.HasParameter(parameter.Key))
                        {
                            continue;
                        }

                        context.Request.SetParameter(parameter.Key, parameter.Value);
                    }
                }
            }

            await _eventDispatcher.DispatchAsync(new OpenIddictServerEvents.ExtractAuthorizationRequest(context));
        }

        public override async Task ValidateAuthorizationRequest([NotNull] ValidateAuthorizationRequestContext context)
        {
            var options = (OpenIddictServerOptions) context.Options;

            // Note: the OpenID Connect server middleware supports authorization code, implicit, hybrid,
            // none and custom flows but OpenIddict uses a stricter policy rejecting none and custum flows.
            if (!context.Request.IsAuthorizationCodeFlow() && !context.Request.IsHybridFlow() && !context.Request.IsImplicitFlow())
            {
                _logger.LogError("The authorization request was rejected because the '{ResponseType}' " +
                                 "response type is not supported.", context.Request.ResponseType);

                context.Reject(
                    error: OpenIddictConstants.Errors.UnsupportedResponseType,
                    description: "The specified 'response_type' parameter is not supported.");

                return;
            }

            // Reject code flow authorization requests if the authorization code flow is not enabled.
            if (context.Request.IsAuthorizationCodeFlow() &&
               !options.GrantTypes.Contains(OpenIddictConstants.GrantTypes.AuthorizationCode))
            {
                _logger.LogError("The authorization request was rejected because " +
                                 "the authorization code flow was not enabled.");

                context.Reject(
                    error: OpenIddictConstants.Errors.UnsupportedResponseType,
                    description: "The specified 'response_type' parameter is not allowed.");

                return;
            }

            // Reject implicit flow authorization requests if the implicit flow is not enabled.
            if (context.Request.IsImplicitFlow() && !options.GrantTypes.Contains(OpenIddictConstants.GrantTypes.Implicit))
            {
                _logger.LogError("The authorization request was rejected because the implicit flow was not enabled.");

                context.Reject(
                    error: OpenIddictConstants.Errors.UnsupportedResponseType,
                    description: "The specified 'response_type' parameter is not allowed.");

                return;
            }

            // Reject hybrid flow authorization requests if the authorization code or the implicit flows are not enabled.
            if (context.Request.IsHybridFlow() && (!options.GrantTypes.Contains(OpenIddictConstants.GrantTypes.AuthorizationCode) ||
                                                   !options.GrantTypes.Contains(OpenIddictConstants.GrantTypes.Implicit)))
            {
                _logger.LogError("The authorization request was rejected because the " +
                                 "authorization code flow or the implicit flow was not enabled.");

                context.Reject(
                    error: OpenIddictConstants.Errors.UnsupportedResponseType,
                    description: "The specified 'response_type' parameter is not allowed.");

                return;
            }

            // Reject authorization requests that specify scope=offline_access if the refresh token flow is not enabled.
            if (context.Request.HasScope(OpenIddictConstants.Scopes.OfflineAccess) &&
               !options.GrantTypes.Contains(OpenIddictConstants.GrantTypes.RefreshToken))
            {
                context.Reject(
                    error: OpenIddictConstants.Errors.InvalidRequest,
                    description: "The 'offline_access' scope is not allowed.");

                return;
            }

            // Validates scopes, unless scope validation was explicitly disabled.
            if (!options.DisableScopeValidation)
            {
                var scopes = new HashSet<string>(context.Request.GetScopes(), StringComparer.Ordinal);
                scopes.ExceptWith(options.Scopes);

                // If all the specified scopes are registered in the options, avoid making a database lookup.
                if (scopes.Count != 0)
                {
                    foreach (var scope in await _scopeManager.FindByNamesAsync(scopes.ToImmutableArray()))
                    {
                        scopes.Remove(await _scopeManager.GetNameAsync(scope));
                    }
                }

                // If at least one scope was not recognized, return an error.
                if (scopes.Count != 0)
                {
                    _logger.LogError("The authentication request was rejected because invalid scopes were specified: {Scopes}.", scopes);

                    context.Reject(
                        error: OpenIddictConstants.Errors.InvalidScope,
                        description: "The specified 'scope' parameter is not valid.");

                    return;
                }
            }

            // Note: the OpenID Connect server middleware supports the query, form_post and fragment response modes
            // and doesn't reject unknown/custom modes until the ApplyAuthorizationResponse event is invoked.
            // To ensure authorization requests are rejected early enough, an additional check is made by OpenIddict.
            if (!string.IsNullOrEmpty(context.Request.ResponseMode) && !context.Request.IsFormPostResponseMode() &&
                                                                       !context.Request.IsFragmentResponseMode() &&
                                                                       !context.Request.IsQueryResponseMode())
            {
                _logger.LogError("The authorization request was rejected because the '{ResponseMode}' " +
                                 "response mode is not supported.", context.Request.ResponseMode);

                context.Reject(
                    error: OpenIddictConstants.Errors.InvalidRequest,
                    description: "The specified 'response_mode' parameter is not supported.");

                return;
            }

            // Note: redirect_uri is not required for pure OAuth2 requests
            // but this provider uses a stricter policy making it mandatory,
            // as required by the OpenID Connect core specification.
            // See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest.
            if (string.IsNullOrEmpty(context.RedirectUri))
            {
                context.Reject(
                    error: OpenIddictConstants.Errors.InvalidRequest,
                    description: "The mandatory 'redirect_uri' parameter is missing.");

                return;
            }

            // If OpenIddict was configured to require PKCE, reject the request if the code challenge
            // is missing and if an authorization code was requested by the client application.
            if (options.RequireProofKeyForCodeExchange && string.IsNullOrEmpty(context.Request.CodeChallenge) &&
                context.Request.HasResponseType(OpenIddictConstants.ResponseTypes.Code))
            {
                _logger.LogError("The authorization request was rejected because the " +
                                 "required 'code_challenge' parameter was missing.");

                context.Reject(
                    error: OpenIddictConstants.Errors.InvalidRequest,
                    description: "The mandatory 'code_challenge' parameter is missing.");

                return;
            }

            // Note: the OpenID Connect server middleware always ensures a
            // code_challenge_method can't be specified without code_challenge.
            if (!string.IsNullOrEmpty(context.Request.CodeChallenge))
            {
                // Since the default challenge method (plain) is explicitly disallowed,
                // reject the authorization request if the code_challenge_method is missing.
                if (string.IsNullOrEmpty(context.Request.CodeChallengeMethod))
                {
                    _logger.LogError("The authorization request was rejected because the " +
                                     "required 'code_challenge_method' parameter was missing.");

                    context.Reject(
                        error: OpenIddictConstants.Errors.InvalidRequest,
                        description: "The 'code_challenge_method' parameter must be specified.");

                    return;
                }

                // Disallow the use of the unsecure code_challenge_method=plain method.
                // See https://tools.ietf.org/html/rfc7636#section-7.2 for more information.
                if (string.Equals(context.Request.CodeChallengeMethod, OpenIdConnectConstants.CodeChallengeMethods.Plain))
                {
                    _logger.LogError("The authorization request was rejected because the " +
                                     "'code_challenge_method' parameter was set to 'plain'.");

                    context.Reject(
                        error: OpenIddictConstants.Errors.InvalidRequest,
                        description: "The specified 'code_challenge_method' parameter is not allowed.");

                    return;
                }

                // Reject authorization requests that contain response_type=token when a code_challenge is specified.
                if (context.Request.HasResponseType(OpenIddictConstants.ResponseTypes.Token))
                {
                    _logger.LogError("The authorization request was rejected because the " +
                                     "specified response type was not compatible with PKCE.");

                    context.Reject(
                        error: OpenIddictConstants.Errors.InvalidRequest,
                        description: "The specified 'response_type' parameter is not allowed when using PKCE.");

                    return;
                }
            }

            // Retrieve the application details corresponding to the requested client_id.
            var application = await _applicationManager.FindByClientIdAsync(context.ClientId);
            if (application == null)
            {
                _logger.LogError("The authorization request was rejected because the client " +
                                 "application was not found: '{ClientId}'.", context.ClientId);

                context.Reject(
                    error: OpenIddictConstants.Errors.InvalidRequest,
                    description: "The specified 'client_id' parameter is invalid.");

                return;
            }

            // To prevent downgrade attacks, ensure that authorization requests returning an access token directly
            // from the authorization endpoint are rejected if the client_id corresponds to a confidential application.
            // Note: when using the authorization code grant, ValidateTokenRequest is responsible of rejecting
            // the token request if the client_id corresponds to an unauthenticated confidential client.
            if (await _applicationManager.IsConfidentialAsync(application) &&
                context.Request.HasResponseType(OpenIddictConstants.ResponseTypes.Token))
            {
                _logger.LogError("The authorization request was rejected because the confidential application '{ClientId}' " +
                                 "was not allowed to retrieve an access token from the authorization endpoint.", context.ClientId);

                context.Reject(
                    error: OpenIddictConstants.Errors.UnauthorizedClient,
                    description: "The specified 'response_type' parameter is not valid for this client application.");

                return;
            }

            // Reject the request if the application is not allowed to use the authorization endpoint.
            if (!options.IgnoreEndpointPermissions &&
                !await _applicationManager.HasPermissionAsync(application, OpenIddictConstants.Permissions.Endpoints.Authorization))
            {
                _logger.LogError("The authorization request was rejected because the application '{ClientId}' " +
                                 "was not allowed to use the authorization endpoint.", context.ClientId);

                context.Reject(
                    error: OpenIddictConstants.Errors.UnauthorizedClient,
                    description: "This client application is not allowed to use the authorization endpoint.");

                return;
            }

            if (!options.IgnoreGrantTypePermissions)
            {
                // Reject the request if the application is not allowed to use the authorization code flow.
                if (context.Request.IsAuthorizationCodeFlow() && !await _applicationManager.HasPermissionAsync(
                    application, OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode))
                {
                    _logger.LogError("The authorization request was rejected because the application '{ClientId}' " +
                                     "was not allowed to use the authorization code flow.", context.ClientId);

                    context.Reject(
                        error: OpenIddictConstants.Errors.UnauthorizedClient,
                        description: "The client application is not allowed to use the authorization code flow.");

                    return;
                }

                // Reject the request if the application is not allowed to use the implicit flow.
                if (context.Request.IsImplicitFlow() && !await _applicationManager.HasPermissionAsync(
                    application, OpenIddictConstants.Permissions.GrantTypes.Implicit))
                {
                    _logger.LogError("The authorization request was rejected because the application '{ClientId}' " +
                                     "was not allowed to use the implicit flow.", context.ClientId);

                    context.Reject(
                        error: OpenIddictConstants.Errors.UnauthorizedClient,
                        description: "The client application is not allowed to use the implicit flow.");

                    return;
                }

                // Reject the request if the application is not allowed to use the authorization code/implicit flows.
                if (context.Request.IsHybridFlow() &&
                   (!await _applicationManager.HasPermissionAsync(application, OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode) ||
                    !await _applicationManager.HasPermissionAsync(application, OpenIddictConstants.Permissions.GrantTypes.Implicit)))
                {
                    _logger.LogError("The authorization request was rejected because the application '{ClientId}' " +
                                     "was not allowed to use the hybrid flow.", context.ClientId);

                    context.Reject(
                        error: OpenIddictConstants.Errors.UnauthorizedClient,
                        description: "The client application is not allowed to use the hybrid flow.");

                    return;
                }

                // Reject the request if the offline_access scope was request and if
                // the application is not allowed to use the refresh token grant type.
                if (context.Request.HasScope(OpenIddictConstants.Scopes.OfflineAccess) &&
                   !await _applicationManager.HasPermissionAsync(application, OpenIddictConstants.Permissions.GrantTypes.RefreshToken))
                {
                    _logger.LogError("The authorization request was rejected because the application '{ClientId}' " +
                                     "was not allowed to request the 'offline_access' scope.", context.ClientId);

                    context.Reject(
                        error: OpenIddictConstants.Errors.InvalidRequest,
                        description: "The client application is not allowed to use the 'offline_access' scope.");

                    return;
                }
            }

            // Ensure that the specified redirect_uri is valid and is associated with the client application.
            if (!await _applicationManager.ValidateRedirectUriAsync(application, context.RedirectUri))
            {
                _logger.LogError("The authorization request was rejected because the redirect_uri " +
                                 "was invalid: '{RedirectUri}'.", context.RedirectUri);

                context.Reject(
                    error: OpenIddictConstants.Errors.InvalidRequest,
                    description: "The specified 'redirect_uri' parameter is not valid for this client application.");

                return;
            }

            // Unless permission enforcement was explicitly disabled, ensure
            // the client application is allowed to use the specified scopes.
            if (!options.IgnoreScopePermissions)
            {
                foreach (var scope in context.Request.GetScopes())
                {
                    // Avoid validating the "openid" and "offline_access" scopes as they represent protocol scopes.
                    if (string.Equals(scope, OpenIddictConstants.Scopes.OfflineAccess, StringComparison.Ordinal) ||
                        string.Equals(scope, OpenIddictConstants.Scopes.OpenId, StringComparison.Ordinal))
                    {
                        continue;
                    }

                    // Reject the request if the application is not allowed to use the iterated scope.
                    if (!await _applicationManager.HasPermissionAsync(application, OpenIddictConstants.Permissions.Prefixes.Scope + scope))
                    {
                        _logger.LogError("The authorization request was rejected because the application '{ClientId}' " +
                                         "was not allowed to use the scope {Scope}.", context.ClientId, scope);

                        context.Reject(
                            error: OpenIddictConstants.Errors.InvalidRequest,
                            description: "This client application is not allowed to use the specified scope.");

                        return;
                    }
                }
            }

            context.Validate();

            await _eventDispatcher.DispatchAsync(new OpenIddictServerEvents.ValidateAuthorizationRequest(context));
        }

        public override async Task HandleAuthorizationRequest([NotNull] HandleAuthorizationRequestContext context)
        {
            var options = (OpenIddictServerOptions) context.Options;

            // If no request_id parameter can be found in the current request, assume the OpenID Connect request
            // was not serialized yet and store the entire payload in the distributed cache to make it easier
            // to flow across requests and internal/external authentication/registration workflows.
            if (options.EnableRequestCaching && string.IsNullOrEmpty(context.Request.RequestId))
            {
                // Generate a 256-bit request identifier using a crypto-secure random number generator.
                var bytes = new byte[256 / 8];
                options.RandomNumberGenerator.GetBytes(bytes);
                context.Request.RequestId = Base64UrlEncoder.Encode(bytes);

                // Store the serialized authorization request parameters in the distributed cache.
                var stream = new MemoryStream();
                using (var writer = new BsonDataWriter(stream))
                {
                    writer.CloseOutput = false;

                    var serializer = JsonSerializer.CreateDefault();
                    serializer.Serialize(writer, context.Request);
                }

                // Note: the cache key is always prefixed with a specific marker
                // to avoid collisions with the other types of cached requests.
                var key = OpenIddictConstants.Environment.AuthorizationRequest + context.Request.RequestId;

                await options.Cache.SetAsync(key, stream.ToArray(), options.RequestCachingPolicy);

                // Create a new authorization request containing only the request_id parameter.
                var address = QueryHelpers.AddQueryString(
                    uri: context.HttpContext.Request.Scheme + "://" + context.HttpContext.Request.Host +
                         context.HttpContext.Request.PathBase + context.HttpContext.Request.Path,
                    name: OpenIddictConstants.Parameters.RequestId, value: context.Request.RequestId);

                context.HttpContext.Response.Redirect(address);

                // Mark the response as handled
                // to skip the rest of the pipeline.
                context.HandleResponse();

                return;
            }

            await _eventDispatcher.DispatchAsync(new OpenIddictServerEvents.HandleAuthorizationRequest(context));
        }

        public override async Task ApplyAuthorizationResponse([NotNull] ApplyAuthorizationResponseContext context)
        {
            var options = (OpenIddictServerOptions) context.Options;

            // Note: as this stage, the request associated with the context may be null if an error
            // occurred very early in the pipeline (e.g an invalid HTTP verb was used by the caller).

            // Remove the authorization request from the distributed cache.
            if (options.EnableRequestCaching && !string.IsNullOrEmpty(context.Request?.RequestId))
            {
                // Note: the cache key is always prefixed with a specific marker
                // to avoid collisions with the other types of cached requests.
                var key = OpenIddictConstants.Environment.AuthorizationRequest + context.Request.RequestId;

                // Note: the ApplyAuthorizationResponse event is called for both successful
                // and errored authorization responses but discrimination is not necessary here,
                // as the authorization request must be removed from the distributed cache in both cases.
                await options.Cache.RemoveAsync(key);
            }

            if (!options.ApplicationCanDisplayErrors && !string.IsNullOrEmpty(context.Error) &&
                                                         string.IsNullOrEmpty(context.RedirectUri))
            {
                // Determine if the status code pages middleware has been enabled for this request.
                // If it was not registered or enabled, let the OpenID Connect server middleware render
                // a default error page instead of delegating the rendering to the status code middleware.
                var feature = context.HttpContext.Features.Get<IStatusCodePagesFeature>();
                if (feature != null && feature.Enabled)
                {
                    // Replace the default status code to return a 400 response.
                    context.HttpContext.Response.StatusCode = 400;

                    // Mark the request as fully handled to prevent the OpenID Connect server middleware
                    // from displaying the default error page and to allow the status code pages middleware
                    // to rewrite the response using the logic defined by the developer when registering it.
                    context.HandleResponse();

                    return;
                }
            }

            await _eventDispatcher.DispatchAsync(new OpenIddictServerEvents.ApplyAuthorizationResponse(context));
        }
    }
}
