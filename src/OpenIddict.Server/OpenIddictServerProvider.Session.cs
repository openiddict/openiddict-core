/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.IO;
using System.Threading.Tasks;
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
        public override async Task ExtractLogoutRequest([NotNull] ExtractLogoutRequestContext context)
        {
            var options = (OpenIddictServerOptions) context.Options;

            // If a request_id parameter can be found in the logout request,
            // restore the complete logout request from the distributed cache.
            if (!string.IsNullOrEmpty(context.Request.RequestId))
            {
                // Return an error if request caching support was not enabled.
                if (!options.EnableRequestCaching)
                {
                    _logger.LogError("The logout request was rejected because request caching support was not enabled.");

                    context.Reject(
                        error: OpenIddictConstants.Errors.InvalidRequest,
                        description: "The 'request_id' parameter is not supported.");

                    return;
                }

                // Note: the cache key is always prefixed with a specific marker
                // to avoid collisions with the other types of cached requests.
                var key = OpenIddictConstants.Environment.LogoutRequest + context.Request.RequestId;

                var payload = await options.Cache.GetAsync(key);
                if (payload == null)
                {
                    _logger.LogError("The logout request was rejected because an unknown " +
                                     "or invalid request_id parameter was specified.");

                    context.Reject(
                        error: OpenIddictConstants.Errors.InvalidRequest,
                        description: "The specified 'request_id' parameter is invalid.");

                    return;
                }

                // Restore the logout request parameters from the serialized payload.
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

            await _eventDispatcher.DispatchAsync(new OpenIddictServerEvents.ExtractLogoutRequest(context));
        }

        public override async Task ValidateLogoutRequest([NotNull] ValidateLogoutRequestContext context)
        {
            var options = (OpenIddictServerOptions) context.Options;

            // If an optional post_logout_redirect_uri was provided, validate it.
            if (!string.IsNullOrEmpty(context.PostLogoutRedirectUri))
            {
                if (!Uri.TryCreate(context.PostLogoutRedirectUri, UriKind.Absolute, out Uri uri) || !uri.IsWellFormedOriginalString())
                {
                    _logger.LogError("The logout request was rejected because the specified post_logout_redirect_uri was not " +
                                     "a valid absolute URL: {PostLogoutRedirectUri}.", context.PostLogoutRedirectUri);

                    context.Reject(
                        error: OpenIddictConstants.Errors.InvalidRequest,
                        description: "The 'post_logout_redirect_uri' parameter must be a valid absolute URL.");

                    return;
                }

                if (!string.IsNullOrEmpty(uri.Fragment))
                {
                    _logger.LogError("The logout request was rejected because the 'post_logout_redirect_uri' contained " +
                                     "a URL fragment: {PostLogoutRedirectUri}.", context.PostLogoutRedirectUri);

                    context.Reject(
                        error: OpenIddictConstants.Errors.InvalidRequest,
                        description: "The 'post_logout_redirect_uri' parameter must not include a fragment.");

                    return;
                }

                async Task<bool> ValidatePostLogoutRedirectUriAsync(string address)
                {
                    var applications = await _applicationManager.FindByPostLogoutRedirectUriAsync(address);
                    if (applications.IsDefaultOrEmpty)
                    {
                        return false;
                    }

                    if (options.IgnoreEndpointPermissions)
                    {
                        return true;
                    }

                    foreach (var application in applications)
                    {
                        if (await _applicationManager.HasPermissionAsync(
                            application, OpenIddictConstants.Permissions.Endpoints.Logout))
                        {
                            return true;
                        }
                    }

                    return false;
                }

                if (!await ValidatePostLogoutRedirectUriAsync(context.PostLogoutRedirectUri))
                {
                    _logger.LogError("The logout request was rejected because no application with the specified " +
                                     "post_logout_redirect_uri and with a logout endpoint permission was found: " +
                                     "{PostLogoutRedirectUri}.", context.PostLogoutRedirectUri);

                    context.Reject(
                        error: OpenIddictConstants.Errors.InvalidRequest,
                        description: "The specified 'post_logout_redirect_uri' parameter is not valid.");

                    return;
                }
            }

            context.Validate();

            await _eventDispatcher.DispatchAsync(new OpenIddictServerEvents.ValidateLogoutRequest(context));
        }

        public override async Task HandleLogoutRequest([NotNull] HandleLogoutRequestContext context)
        {
            var options = (OpenIddictServerOptions) context.Options;

            // If no request_id parameter can be found in the current request, assume the OpenID Connect
            // request was not serialized yet and store the entire payload in the distributed cache
            // to make it easier to flow across requests and internal/external logout workflows.
            if (options.EnableRequestCaching && string.IsNullOrEmpty(context.Request.RequestId))
            {
                // Generate a 256-bit request identifier using a crypto-secure random number generator.
                var bytes = new byte[256 / 8];
                options.RandomNumberGenerator.GetBytes(bytes);
                context.Request.RequestId = Base64UrlEncoder.Encode(bytes);

                // Store the serialized logout request parameters in the distributed cache.
                var stream = new MemoryStream();
                using (var writer = new BsonDataWriter(stream))
                {
                    writer.CloseOutput = false;

                    var serializer = JsonSerializer.CreateDefault();
                    serializer.Serialize(writer, context.Request);
                }

                // Note: the cache key is always prefixed with a specific marker
                // to avoid collisions with the other types of cached requests.
                var key = OpenIddictConstants.Environment.LogoutRequest + context.Request.RequestId;

                await options.Cache.SetAsync(key, stream.ToArray(), options.RequestCachingPolicy);

                // Create a new logout request containing only the request_id parameter.
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

            await _eventDispatcher.DispatchAsync(new OpenIddictServerEvents.HandleLogoutRequest(context));
        }

        public override async Task ApplyLogoutResponse([NotNull] ApplyLogoutResponseContext context)
        {
            var options = (OpenIddictServerOptions) context.Options;

            // Note: as this stage, the request associated with the context may be null if an error
            // occurred very early in the pipeline (e.g an invalid HTTP verb was used by the caller).

            // Remove the logout request from the distributed cache.
            if (options.EnableRequestCaching && !string.IsNullOrEmpty(context.Request?.RequestId))
            {
                // Note: the cache key is always prefixed with a specific marker
                // to avoid collisions with the other types of cached requests.
                var key = OpenIddictConstants.Environment.LogoutRequest + context.Request.RequestId;

                // Note: the ApplyLogoutResponse event is called for both successful
                // and errored logout responses but discrimination is not necessary here,
                // as the logout request must be removed from the distributed cache in both cases.
                await options.Cache.RemoveAsync(key);
            }

            if (!options.ApplicationCanDisplayErrors && !string.IsNullOrEmpty(context.Error) &&
                                                         string.IsNullOrEmpty(context.PostLogoutRedirectUri))
            {
                // Determine if the status code pages middleware has been enabled for this request.
                // If it was not registered or enabled, let the OpenID Connect server middleware render
                // a default error page instead of delegating the rendering to the status code middleware.
                var feature = context.HttpContext.Features.Get<IStatusCodePagesFeature>();
                if (feature != null && feature.Enabled)
                {
                    // Replace the default status code by a 400 response.
                    context.HttpContext.Response.StatusCode = 400;

                    // Mark the request as fully handled to prevent the OpenID Connect server middleware
                    // from displaying the default error page and to allow the status code pages middleware
                    // to rewrite the response using the logic defined by the developer when registering it.
                    context.HandleResponse();

                    return;
                }
            }

            await _eventDispatcher.DispatchAsync(new OpenIddictServerEvents.ApplyLogoutResponse(context));
        }
    }
}
