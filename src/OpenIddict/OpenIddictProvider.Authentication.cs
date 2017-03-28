/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.IO;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using Newtonsoft.Json.Bson;
using Newtonsoft.Json.Linq;
using OpenIddict.Core;

namespace OpenIddict
{
    public partial class OpenIddictProvider<TApplication, TAuthorization, TScope, TToken> : OpenIdConnectServerProvider
        where TApplication : class where TAuthorization : class where TScope : class where TToken : class
    {
        public override async Task ExtractAuthorizationRequest([NotNull] ExtractAuthorizationRequestContext context)
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<OpenIddictProvider<TApplication, TAuthorization, TScope, TToken>>>();
            var options = context.HttpContext.RequestServices.GetRequiredService<IOptions<OpenIddictOptions>>();

            // Reject requests using the unsupported request parameter.
            if (!string.IsNullOrEmpty(context.Request.Request))
            {
                logger.LogError("The authorization request was rejected because it contained " +
                                "an unsupported parameter: {Parameter}.", "request");

                context.Reject(
                    error: OpenIdConnectConstants.Errors.RequestNotSupported,
                    description: "The request parameter is not supported.");

                return;
            }

            // Reject requests using the unsupported request_uri parameter.
            if (!string.IsNullOrEmpty(context.Request.RequestUri))
            {
                logger.LogError("The authorization request was rejected because it contained " +
                                "an unsupported parameter: {Parameter}.", "request_uri");

                context.Reject(
                    error: OpenIdConnectConstants.Errors.RequestUriNotSupported,
                    description: "The request_uri parameter is not supported.");

                return;
            }

            // If a request_id parameter can be found in the authorization request,
            // restore the complete authorization request from the distributed cache.
            if (!string.IsNullOrEmpty(context.Request.RequestId))
            {
                // Return an error if request caching support was not enabled.
                if (!options.Value.EnableRequestCaching)
                {
                    logger.LogError("The authorization request was rejected because " +
                                    "request caching support was not enabled.");

                    context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidRequest,
                        description: "The request_id parameter is not supported.");

                    return;
                }

                // Note: the cache key is always prefixed with a specific marker
                // to avoid collisions with the other types of cached requests.
                var key = OpenIddictConstants.Environment.AuthorizationRequest + context.Request.RequestId;

                var payload = await options.Value.Cache.GetAsync(key);
                if (payload == null)
                {
                    logger.LogError("The authorization request was rejected because an unknown " +
                                    "or invalid request_id parameter was specified.");

                    context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidRequest,
                        description: "Invalid request: timeout expired.");

                    return;
                }

                // Restore the authorization request parameters from the serialized payload.
                using (var reader = new BsonReader(new MemoryStream(payload)))
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
        }

        public override async Task ValidateAuthorizationRequest([NotNull] ValidateAuthorizationRequestContext context)
        {
            var applications = context.HttpContext.RequestServices.GetRequiredService<OpenIddictApplicationManager<TApplication>>();
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<OpenIddictProvider<TApplication, TAuthorization, TScope, TToken>>>();
            var options = context.HttpContext.RequestServices.GetRequiredService<IOptions<OpenIddictOptions>>();

            // Note: the OpenID Connect server middleware supports authorization code, implicit, hybrid,
            // none and custom flows but OpenIddict uses a stricter policy rejecting unknown flows.
            if (!context.Request.IsAuthorizationCodeFlow() && !context.Request.IsHybridFlow() &&
                !context.Request.IsImplicitFlow() && !context.Request.IsNoneFlow())
            {
                logger.LogError("The authorization request was rejected because the '{ResponseType}' " +
                                "response type is not supported.", context.Request.ResponseType);

                context.Reject(
                    error: OpenIdConnectConstants.Errors.UnsupportedResponseType,
                    description: "The specified response_type parameter is not supported.");

                return;
            }

            // Reject code flow authorization requests if the authorization code flow is not enabled.
            if (context.Request.IsAuthorizationCodeFlow() &&
               !options.Value.GrantTypes.Contains(OpenIdConnectConstants.GrantTypes.AuthorizationCode))
            {
                logger.LogError("The authorization request was rejected because " +
                                "the authorization code flow was not enabled.");

                context.Reject(
                    error: OpenIdConnectConstants.Errors.UnsupportedResponseType,
                    description: "The specified response_type parameter is not allowed.");

                return;
            }

            // Reject implicit flow authorization requests if the implicit flow is not enabled.
            if (context.Request.IsImplicitFlow() && !options.Value.GrantTypes.Contains(OpenIdConnectConstants.GrantTypes.Implicit))
            {
                logger.LogError("The authorization request was rejected because the implicit flow was not enabled.");

                context.Reject(
                    error: OpenIdConnectConstants.Errors.UnsupportedResponseType,
                    description: "The specified response_type parameter is not allowed.");

                return;
            }

            // Reject hybrid flow authorization requests if the authorization code or the implicit flows are not enabled.
            if (context.Request.IsHybridFlow() && (!options.Value.GrantTypes.Contains(OpenIdConnectConstants.GrantTypes.AuthorizationCode) ||
                                                   !options.Value.GrantTypes.Contains(OpenIdConnectConstants.GrantTypes.Implicit)))
            {
                logger.LogError("The authorization request was rejected because the " +
                                "authorization code flow or the implicit flow was not enabled.");

                context.Reject(
                    error: OpenIdConnectConstants.Errors.UnsupportedResponseType,
                    description: "The specified response_type parameter is not allowed.");

                return;
            }

            // Reject authorization requests that specify scope=offline_access if the refresh token flow is not enabled.
            if (context.Request.HasScope(OpenIdConnectConstants.Scopes.OfflineAccess) &&
               !options.Value.GrantTypes.Contains(OpenIdConnectConstants.GrantTypes.RefreshToken))
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "The 'offline_access' scope is not allowed.");

                return;
            }

            // Note: the OpenID Connect server middleware supports the query, form_post and fragment response modes
            // and doesn't reject unknown/custom modes until the ApplyAuthorizationResponse event is invoked.
            // To ensure authorization requests are rejected early enough, an additional check is made by OpenIddict.
            if (!string.IsNullOrEmpty(context.Request.ResponseMode) && !context.Request.IsFormPostResponseMode() &&
                                                                       !context.Request.IsFragmentResponseMode() &&
                                                                       !context.Request.IsQueryResponseMode())
            {
                logger.LogError("The authorization request was rejected because the '{ResponseMode}' " +
                                "response mode is not supported.", context.Request.ResponseMode);

                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "The specified response_mode parameter is not supported.");

                return;
            }

            // Note: redirect_uri is not required for pure OAuth2 requests
            // but this provider uses a stricter policy making it mandatory,
            // as required by the OpenID Connect core specification.
            // See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest.
            if (string.IsNullOrEmpty(context.RedirectUri))
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "The required redirect_uri parameter was missing.");

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
                    logger.LogError("The authorization request was rejected because the " +
                                    "required 'code_challenge_method' parameter was missing.");

                    context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidRequest,
                        description: "The 'code_challenge_method' parameter must be specified.");

                    return;
                }

                // Disallow the use of the unsecure code_challenge_method=plain method.
                // See https://tools.ietf.org/html/rfc7636#section-7.2 for more information.
                if (string.Equals(context.Request.CodeChallengeMethod, OpenIdConnectConstants.CodeChallengeMethods.Plain))
                {
                    logger.LogError("The authorization request was rejected because the " +
                                    "'code_challenge_method' parameter was set to 'plain'.");

                    context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidRequest,
                        description: "The specified code_challenge_method parameter is not allowed.");

                    return;
                }

                // Reject authorization requests that contain response_type=token when a code_challenge is specified.
                if (context.Request.HasResponseType(OpenIdConnectConstants.ResponseTypes.Token))
                {
                    logger.LogError("The authorization request was rejected because the " +
                                    "specified response type was not compatible with PKCE.");

                    context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidRequest,
                        description: "The specified response_type parameter is not allowed when using PKCE.");

                    return;
                }
            }

            // Retrieve the application details corresponding to the requested client_id.
            var application = await applications.FindByClientIdAsync(context.ClientId, context.HttpContext.RequestAborted);
            if (application == null)
            {
                logger.LogError("The authorization request was rejected because the client " +
                                "application was not found: '{ClientId}'.", context.ClientId);

                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Application not found in the database: ensure that your client_id is correct.");

                return;
            }

            // Ensure a redirect_uri was associated with the application.
            if (!await applications.HasRedirectUriAsync(application, context.HttpContext.RequestAborted))
            {
                logger.LogError("The authorization request was rejected because no redirect_uri " +
                                "was registered with the application '{ClientId}'.", context.ClientId);

                context.Reject(
                    error: OpenIdConnectConstants.Errors.UnauthorizedClient,
                    description: "The client application is not allowed to use interactive flows.");

                return;
            }

            // Ensure the redirect_uri is valid.
            if (!await applications.ValidateRedirectUriAsync(application, context.RedirectUri, context.HttpContext.RequestAborted))
            {
                logger.LogError("The authorization request was rejected because the redirect_uri " +
                                "was invalid: '{RedirectUri}'.", context.RedirectUri);

                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Invalid redirect_uri.");

                return;
            }

            // To prevent downgrade attacks, ensure that authorization requests returning an access token directly
            // from the authorization endpoint are rejected if the client_id corresponds to a confidential application.
            // Note: when using the authorization code grant, ValidateTokenRequest is responsible of rejecting
            // the token request if the client_id corresponds to an unauthenticated confidential client.
            if (await applications.IsConfidentialAsync(application, context.HttpContext.RequestAborted) &&
                context.Request.HasResponseType(OpenIdConnectConstants.ResponseTypes.Token))
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "Confidential clients are not allowed to retrieve " +
                                 "an access token from the authorization endpoint.");

                return;
            }

            context.Validate();
        }

        public override async Task HandleAuthorizationRequest([NotNull] HandleAuthorizationRequestContext context)
        {
            var options = context.HttpContext.RequestServices.GetRequiredService<IOptions<OpenIddictOptions>>();

            // If no request_id parameter can be found in the current request, assume the OpenID Connect request
            // was not serialized yet and store the entire payload in the distributed cache to make it easier
            // to flow across requests and internal/external authentication/registration workflows.
            if (options.Value.EnableRequestCaching && string.IsNullOrEmpty(context.Request.RequestId))
            {
                // Generate a request identifier. Note: using a crypto-secure
                // random number generator is not necessary in this case.
                context.Request.RequestId = Guid.NewGuid().ToString();

                // Store the serialized authorization request parameters in the distributed cache.
                var stream = new MemoryStream();
                using (var writer = new BsonWriter(stream))
                {
                    writer.CloseOutput = false;

                    var serializer = JsonSerializer.CreateDefault();
                    serializer.Serialize(writer, context.Request);
                }

                // Note: the cache key is always prefixed with a specific marker
                // to avoid collisions with the other types of cached requests.
                var key = OpenIddictConstants.Environment.AuthorizationRequest + context.Request.RequestId;

                await options.Value.Cache.SetAsync(key, stream.ToArray(), new DistributedCacheEntryOptions
                {
                    AbsoluteExpiration = context.Options.SystemClock.UtcNow + TimeSpan.FromMinutes(30),
                    SlidingExpiration = TimeSpan.FromMinutes(10)
                });

                // Create a new authorization request containing only the request_id parameter.
                var address = QueryHelpers.AddQueryString(
                    uri: context.HttpContext.Request.Scheme + "://" + context.HttpContext.Request.Host +
                         context.HttpContext.Request.PathBase + context.HttpContext.Request.Path,
                    name: OpenIdConnectConstants.Parameters.RequestId, value: context.Request.RequestId);

                context.HttpContext.Response.Redirect(address);

                // Mark the response as handled
                // to skip the rest of the pipeline.
                context.HandleResponse();

                return;
            }

            context.SkipToNextMiddleware();
        }

        public override async Task ApplyAuthorizationResponse([NotNull] ApplyAuthorizationResponseContext context)
        {
            var options = context.HttpContext.RequestServices.GetRequiredService<IOptions<OpenIddictOptions>>();

            // Remove the authorization request from the distributed cache.
            if (options.Value.EnableRequestCaching && !string.IsNullOrEmpty(context.Request.RequestId))
            {
                // Note: the cache key is always prefixed with a specific marker
                // to avoid collisions with the other types of cached requests.
                var key = OpenIddictConstants.Environment.AuthorizationRequest + context.Request.RequestId;

                // Note: the ApplyAuthorizationResponse event is called for both successful
                // and errored authorization responses but discrimination is not necessary here,
                // as the authorization request must be removed from the distributed cache in both cases.
                await options.Value.Cache.RemoveAsync(key);
            }

            if (!options.Value.ApplicationCanDisplayErrors && !string.IsNullOrEmpty(context.Error) &&
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
                }
            }
        }
    }
}