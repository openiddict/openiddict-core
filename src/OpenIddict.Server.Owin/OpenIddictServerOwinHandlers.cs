/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.ComponentModel;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using Microsoft.Owin;
using Newtonsoft.Json;
using OpenIddict.Abstractions;
using Owin;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.Owin.OpenIddictServerOwinHandlerFilters;

namespace OpenIddict.Server.Owin
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static partial class OpenIddictServerOwinHandlers
    {
        public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Top-level request processing:
             */
            InferEndpointType.Descriptor,
            ValidateTransportSecurityRequirement.Descriptor,
            ValidateHost.Descriptor)
            .AddRange(Authentication.DefaultHandlers)
            .AddRange(Discovery.DefaultHandlers)
            .AddRange(Exchange.DefaultHandlers)
            .AddRange(Serialization.DefaultHandlers)
            .AddRange(Session.DefaultHandlers);

        /// <summary>
        /// Contains the logic responsible of inferring the endpoint type from the request address.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
        /// </summary>
        public class InferEndpointType : IOpenIddictServerHandler<ProcessRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<InferEndpointType>()
                    // Note: this handler must be invoked before any other handler,
                    // including the built-in handlers defined in OpenIddict.Server.
                    .SetOrder(int.MinValue + 50_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public Task HandleAsync([NotNull] ProcessRequestContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var request = context.Transaction.GetOwinRequest();
                if (request == null)
                {
                    throw new InvalidOperationException("The OWIN request cannot be resolved.");
                }

                context.EndpointType =
                    Matches(context.Options.AuthorizationEndpointUris) ? OpenIddictServerEndpointType.Authorization :
                    Matches(context.Options.ConfigurationEndpointUris) ? OpenIddictServerEndpointType.Configuration :
                    Matches(context.Options.CryptographyEndpointUris)  ? OpenIddictServerEndpointType.Cryptography  :
                    Matches(context.Options.IntrospectionEndpointUris) ? OpenIddictServerEndpointType.Introspection :
                    Matches(context.Options.LogoutEndpointUris)        ? OpenIddictServerEndpointType.Logout        :
                    Matches(context.Options.RevocationEndpointUris)    ? OpenIddictServerEndpointType.Revocation    :
                    Matches(context.Options.TokenEndpointUris)         ? OpenIddictServerEndpointType.Token         :
                    Matches(context.Options.UserinfoEndpointUris)      ? OpenIddictServerEndpointType.Userinfo      :
                                                                         OpenIddictServerEndpointType.Unknown;

                return Task.CompletedTask;

                bool Matches(IList<Uri> addresses)
                {
                    for (var index = 0; index < addresses.Count; index++)
                    {
                        var address = addresses[index];
                        if (address.IsAbsoluteUri)
                        {
                            if (!string.Equals(address.Scheme, request.Scheme, StringComparison.OrdinalIgnoreCase))
                            {
                                continue;
                            }

                            var host = HostString.FromUriComponent(address);
                            if (host != request.Host)
                            {
                                continue;
                            }

                            var path = PathString.FromUriComponent(address);
                            if (path == request.PathBase + request.Path ||
                                path == request.PathBase + request.Path + new PathString("/"))
                            {
                                return true;
                            }
                        }

                        else if (address.OriginalString.StartsWith("/", StringComparison.OrdinalIgnoreCase))
                        {
                            var path = new PathString(address.OriginalString);
                            if (path == request.Path || path == request.Path + new PathString("/"))
                            {
                                return true;
                            }
                        }
                    }

                    return false;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of rejecting OpenID Connect requests that don't use transport security.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
        /// </summary>
        public class ValidateTransportSecurityRequirement : IOpenIddictServerHandler<ProcessRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireOwinRequest>()
                    .AddFilter<RequireTransportSecurityRequirementEnabled>()
                    .UseSingletonHandler<ValidateTransportSecurityRequirement>()
                    .SetOrder(InferEndpointType.Descriptor.Order + 1_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public Task HandleAsync([NotNull] ProcessRequestContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var request = context.Transaction.GetOwinRequest();
                if (request == null)
                {
                    throw new InvalidOperationException("The OWIN request cannot be resolved.");
                }

                // Don't require that the host be present if the request is not handled by OpenIddict.
                if (context.EndpointType == OpenIddictServerEndpointType.Unknown)
                {
                    return Task.CompletedTask;
                }

                // Reject authorization requests sent without transport security.
                if (!request.IsSecure)
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: "This server only accepts HTTPS requests.");

                    return Task.CompletedTask;
                }

                return Task.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible of ensuring the host can be inferred from the request if none was set in the options.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
        /// </summary>
        public class ValidateHost : IOpenIddictServerHandler<ProcessRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<ValidateHost>()
                    .SetOrder(ValidateTransportSecurityRequirement.Descriptor.Order + 1_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public Task HandleAsync([NotNull] ProcessRequestContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var request = context.Transaction.GetOwinRequest();
                if (request == null)
                {
                    throw new InvalidOperationException("The OWIN request cannot be resolved.");
                }

                // Don't require that the request host be present if the request is not handled
                // by an OpenIddict endpoint or if an explicit issuer URL was set in the options.
                if (context.Options.Issuer != null || context.EndpointType == OpenIddictServerEndpointType.Unknown)
                {
                    return Task.CompletedTask;
                }

                if (string.IsNullOrEmpty(request.Host.Value))
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: "The mandatory 'Host' header is missing.");

                    return Task.CompletedTask;
                }

                return Task.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible of extracting OpenID Connect requests from GET HTTP requests.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
        /// </summary>
        public class ExtractGetRequest<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseValidatingContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<ExtractGetOrPostRequest<TContext>>()
                    .SetOrder(ValidateHost.Descriptor.Order + 1_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public Task HandleAsync([NotNull] TContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var request = context.Transaction.GetOwinRequest();
                if (request == null)
                {
                    throw new InvalidOperationException("The OWIN request cannot be resolved.");
                }

                if (string.Equals(request.Method, "GET", StringComparison.OrdinalIgnoreCase))
                {
                    context.Request = new OpenIddictRequest(request.Query);
                }

                else
                {
                    context.Logger.LogError("The request was rejected because an invalid " +
                                            "HTTP method was specified: {Method}.", request.Method);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: "The specified HTTP method is not valid.");

                    return Task.CompletedTask;
                }

                return Task.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible of extracting OpenID Connect requests from GET or POST HTTP requests.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
        /// </summary>
        public class ExtractGetOrPostRequest<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseValidatingContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<ExtractGetOrPostRequest<TContext>>()
                    .SetOrder(ExtractGetRequest<TContext>.Descriptor.Order + 1_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async Task HandleAsync([NotNull] TContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var request = context.Transaction.GetOwinRequest();
                if (request == null)
                {
                    throw new InvalidOperationException("The OWIN request cannot be resolved.");
                }

                if (string.Equals(request.Method, "GET", StringComparison.OrdinalIgnoreCase))
                {
                    context.Request = new OpenIddictRequest(request.Query);
                }

                else if (string.Equals(request.Method, "POST", StringComparison.OrdinalIgnoreCase))
                {
                    // See http://openid.net/specs/openid-connect-core-1_0.html#FormSerialization
                    if (string.IsNullOrEmpty(request.ContentType))
                    {
                        context.Logger.LogError("The request was rejected because the mandatory 'Content-Type' header was missing.");

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The mandatory 'Content-Type' header must be specified.");

                        return;
                    }

                    // May have media/type; charset=utf-8, allow partial match.
                    if (!request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
                    {
                        context.Logger.LogError("The request was rejected because an invalid 'Content-Type' " +
                                                "header was specified: {ContentType}.", request.ContentType);

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The specified 'Content-Type' header is not valid.");

                        return;
                    }

                    context.Request = new OpenIddictRequest(await request.ReadFormAsync());
                }

                else
                {
                    context.Logger.LogError("The request was rejected because an invalid " +
                                            "HTTP method was specified: {Method}.", request.Method);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: "The specified HTTP method is not valid.");

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of extracting OpenID Connect requests from POST HTTP requests.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
        /// </summary>
        public class ExtractPostRequest<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseValidatingContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<ExtractPostRequest<TContext>>()
                    .SetOrder(ExtractGetOrPostRequest<TContext>.Descriptor.Order + 1_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async Task HandleAsync([NotNull] TContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var request = context.Transaction.GetOwinRequest();
                if (request == null)
                {
                    throw new InvalidOperationException("The OWIN request cannot be resolved.");
                }

                if (string.Equals(request.Method, "POST", StringComparison.OrdinalIgnoreCase))
                {
                    // See http://openid.net/specs/openid-connect-core-1_0.html#FormSerialization
                    if (string.IsNullOrEmpty(request.ContentType))
                    {
                        context.Logger.LogError("The request was rejected because the mandatory 'Content-Type' header was missing.");

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The mandatory 'Content-Type' header must be specified.");

                        return;
                    }

                    // May have media/type; charset=utf-8, allow partial match.
                    if (!request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
                    {
                        context.Logger.LogError("The request was rejected because an invalid 'Content-Type' " +
                                                "header was specified: {ContentType}.", request.ContentType);

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The specified 'Content-Type' header is not valid.");

                        return;
                    }

                    context.Request = new OpenIddictRequest(await request.ReadFormAsync());
                }

                else
                {
                    context.Logger.LogError("The request was rejected because an invalid " +
                                            "HTTP method was specified: {Method}.", request.Method);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: "The specified HTTP method is not valid.");

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of rejecting token requests that specify an invalid grant type.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
        /// </summary>
        public class ExtractBasicAuthenticationCredentials<TContext> : IOpenIddictServerHandler<TContext>
            where TContext : BaseValidatingContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<ExtractBasicAuthenticationCredentials<TContext>>()
                    .SetOrder(ExtractPostRequest<TContext>.Descriptor.Order + 1_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public Task HandleAsync([NotNull] TContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var request = context.Transaction.GetOwinRequest();
                if (request == null)
                {
                    throw new InvalidOperationException("The OWIN request cannot be resolved.");
                }

                var header = request.Headers["Authorization"];
                if (string.IsNullOrEmpty(header) || !header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
                {
                    return Task.CompletedTask;
                }

                // At this point, reject requests that use multiple client authentication methods.
                // See https://tools.ietf.org/html/rfc6749#section-2.3 for more information.
                if (!string.IsNullOrEmpty(context.Request.ClientAssertion) || !string.IsNullOrEmpty(context.Request.ClientSecret))
                {
                    context.Logger.LogError("The request was rejected because multiple client credentials were specified.");

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: "Multiple client credentials cannot be specified.");

                    return Task.CompletedTask;
                }

                try
                {
                    var value = header.Substring("Basic ".Length).Trim();
                    var data = Encoding.ASCII.GetString(Convert.FromBase64String(value));

                    var index = data.IndexOf(':');
                    if (index < 0)
                    {
                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: "The specified client credentials are invalid.");

                        return Task.CompletedTask;
                    }

                    // Attach the basic authentication credentials to the request message.
                    context.Request.ClientId = UnescapeDataString(data.Substring(0, index));
                    context.Request.ClientSecret = UnescapeDataString(data.Substring(index + 1));

                    return Task.CompletedTask;
                }

                catch
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: "The specified client credentials are invalid.");

                    return Task.CompletedTask;
                }

                static string UnescapeDataString(string data)
                {
                    if (string.IsNullOrEmpty(data))
                    {
                        return null;
                    }

                    return Uri.UnescapeDataString(data.Replace("+", "%20"));
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of processing OpenID Connect responses that must be returned as JSON.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
        /// </summary>
        public class ProcessJsonResponse<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<ProcessJsonResponse<TContext>>()
                    .SetOrder(int.MinValue + 100_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async Task HandleAsync([NotNull] TContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (context.Response == null)
                {
                    throw new InvalidOperationException("This handler cannot be invoked without a response attached.");
                }

                // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var response = context.Transaction.GetOwinRequest()?.Context.Response;
                if (response == null)
                {
                    throw new InvalidOperationException("The OWIN request cannot be resolved.");
                }

                using (var buffer = new MemoryStream())
                using (var writer = new JsonTextWriter(new StreamWriter(buffer)))
                {
                    var serializer = JsonSerializer.CreateDefault();
                    serializer.Serialize(writer, context.Response);

                    writer.Flush();

                    if (!string.IsNullOrEmpty(context.Response.Error))
                    {
                        // Note: when using basic authentication, returning an invalid_client error MUST result in
                        // an unauthorized response but returning a 401 status code would invoke the previously
                        // registered authentication middleware and potentially replace it by a 302 response.
                        // To work around this OWIN/Katana limitation, a 400 response code is always returned.
                        response.StatusCode = 400;
                    }

                    response.ContentLength = buffer.Length;
                    response.ContentType = "application/json;charset=UTF-8";

                    buffer.Seek(offset: 0, loc: SeekOrigin.Begin);
                    await buffer.CopyToAsync(response.Body, 4096, response.Context.Request.CallCancelled);
                }

                context.HandleRequest();
            }
        }
    }
}
