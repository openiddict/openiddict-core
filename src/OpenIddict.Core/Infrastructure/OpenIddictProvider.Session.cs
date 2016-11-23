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
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Bson;
using Newtonsoft.Json.Linq;

namespace OpenIddict.Infrastructure {
    public partial class OpenIddictProvider<TApplication, TAuthorization, TScope, TToken> : OpenIdConnectServerProvider
        where TApplication : class where TAuthorization : class where TScope : class where TToken : class {
        public override async Task ExtractLogoutRequest([NotNull] ExtractLogoutRequestContext context) {
            var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TApplication, TAuthorization, TScope, TToken>>();

            // If a request_id parameter can be found in the logout request,
            // restore the complete logout request from the distributed cache.
            if (!string.IsNullOrEmpty(context.Request.RequestId)) {
                // Return an error if request caching support was not enabled.
                if (!services.Options.EnableRequestCaching) {
                    services.Logger.LogError("The logout request was rejected because " +
                                             "request caching support was not enabled.");

                    context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidRequest,
                        description: "The request_id parameter is not supported.");

                    return;
                }

                // Note: the cache key is always prefixed with a specific marker
                // to avoid collisions with the other types of cached requests.
                var key = OpenIddictConstants.Environment.LogoutRequest + context.Request.RequestId;

                var payload = await services.Options.Cache.GetAsync(key);
                if (payload == null) {
                    services.Logger.LogError("The logout request was rejected because an unknown " +
                                             "or invalid request_id parameter was specified.");

                    context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidRequest,
                        description: "Invalid request: timeout expired.");

                    return;
                }

                // Restore the logout request parameters from the serialized payload.
                using (var reader = new BsonReader(new MemoryStream(payload))) {
                    foreach (var parameter in JObject.Load(reader)) {
                        // Avoid overriding the current request parameters.
                        if (context.Request.HasParameter(parameter.Key)) {
                            continue;
                        }

                        context.Request.SetParameter(parameter.Key, parameter.Value);
                    }
                }
            }
        }

        public override async Task ValidateLogoutRequest([NotNull] ValidateLogoutRequestContext context) {
            var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TApplication, TAuthorization, TScope, TToken>>();

            // Skip validation if the optional post_logout_redirect_uri
            // parameter was missing from the logout request.
            if (string.IsNullOrEmpty(context.PostLogoutRedirectUri)) {
                services.Logger.LogInformation("The logout request validation process was skipped because " +
                                               "the post_logout_redirect_uri parameter was missing.");

                context.Skip();

                return;
            }

            var application = await services.Applications.FindByLogoutRedirectUri(context.PostLogoutRedirectUri);
            if (application == null) {
                services.Logger.LogError("The logout request was rejected because the client application corresponding " +
                                         "to the specified post_logout_redirect_uri was not found in the database: " +
                                         "'{PostLogoutRedirectUri}'.", context.PostLogoutRedirectUri);

                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Invalid post_logout_redirect_uri.");

                return;
            }

            context.Validate();
        }

        public override async Task HandleLogoutRequest([NotNull] HandleLogoutRequestContext context) {
            var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TApplication, TAuthorization, TScope, TToken>>();

            // If no request_id parameter can be found in the current request, assume the OpenID Connect
            // request was not serialized yet and store the entire payload in the distributed cache
            // to make it easier to flow across requests and internal/external logout workflows.
            if (services.Options.EnableRequestCaching && string.IsNullOrEmpty(context.Request.RequestId)) {
                // Generate a request identifier. Note: using a crypto-secure
                // random number generator is not necessary in this case.
                context.Request.RequestId = Guid.NewGuid().ToString();

                // Store the serialized logout request parameters in the distributed cache.
                var stream = new MemoryStream();
                using (var writer = new BsonWriter(stream)) {
                    writer.CloseOutput = false;

                    var serializer = JsonSerializer.CreateDefault();
                    serializer.Serialize(writer, context.Request);
                }

                // Note: the cache key is always prefixed with a specific marker
                // to avoid collisions with the other types of cached requests.
                var key = OpenIddictConstants.Environment.LogoutRequest + context.Request.RequestId;

                await services.Options.Cache.SetAsync(key, stream.ToArray(), new DistributedCacheEntryOptions {
                    AbsoluteExpiration = context.Options.SystemClock.UtcNow + TimeSpan.FromMinutes(30),
                    SlidingExpiration = TimeSpan.FromMinutes(10)
                });

                // Create a new logout request containing only the request_id parameter.
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
        }

        public override async Task ApplyLogoutResponse([NotNull] ApplyLogoutResponseContext context) {
            var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TApplication, TAuthorization, TScope, TToken>>();

            // Remove the logout request from the distributed cache.
            if (services.Options.EnableRequestCaching && !string.IsNullOrEmpty(context.Request.RequestId)) {
                // Note: the cache key is always prefixed with a specific marker
                // to avoid collisions with the other types of cached requests.
                var key = OpenIddictConstants.Environment.LogoutRequest + context.Request.RequestId;

                // Note: the ApplyLogoutResponse event is called for both successful
                // and errored logout responses but discrimination is not necessary here,
                // as the logout request must be removed from the distributed cache in both cases.
                await services.Options.Cache.RemoveAsync(key);
            }

            if (!context.Options.ApplicationCanDisplayErrors && !string.IsNullOrEmpty(context.Response.Error) &&
                                                                 string.IsNullOrEmpty(context.Response.PostLogoutRedirectUri)) {
                // Determine if the status code pages middleware has been enabled for this request.
                // If it was not registered or enabled, let the OpenID Connect server middleware render
                // a default error page instead of delegating the rendering to the status code middleware.
                var feature = context.HttpContext.Features.Get<IStatusCodePagesFeature>();
                if (feature != null && feature.Enabled) {
                    // Replace the default status code by a 400 response.
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