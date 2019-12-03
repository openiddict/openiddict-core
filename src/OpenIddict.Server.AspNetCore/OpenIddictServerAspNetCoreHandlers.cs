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
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.AspNetCore.OpenIddictServerAspNetCoreHandlerFilters;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers;
using Properties = OpenIddict.Server.AspNetCore.OpenIddictServerAspNetCoreConstants.Properties;

namespace OpenIddict.Server.AspNetCore
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static partial class OpenIddictServerAspNetCoreHandlers
    {
        public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Top-level request processing:
             */
            InferEndpointType.Descriptor,
            InferIssuerFromHost.Descriptor,
            ValidateTransportSecurityRequirement.Descriptor,

            /*
             * Challenge processing:
             */
            AttachHostChallengeError.Descriptor)
            .AddRange(Authentication.DefaultHandlers)
            .AddRange(Device.DefaultHandlers)
            .AddRange(Discovery.DefaultHandlers)
            .AddRange(Exchange.DefaultHandlers)
            .AddRange(Introspection.DefaultHandlers)
            .AddRange(Revocation.DefaultHandlers)
            .AddRange(Session.DefaultHandlers)
            .AddRange(Userinfo.DefaultHandlers);

        /// <summary>
        /// Contains the logic responsible of inferring the endpoint type from the request address.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public class InferEndpointType : IOpenIddictServerHandler<ProcessRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<InferEndpointType>()
                    .SetOrder(int.MinValue + 50_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessRequestContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var request = context.Transaction.GetHttpRequest();
                if (request == null)
                {
                    throw new InvalidOperationException("The ASP.NET Core HTTP request cannot be resolved.");
                }

                context.EndpointType =
                    Matches(context.Options.AuthorizationEndpointUris) ? OpenIddictServerEndpointType.Authorization :
                    Matches(context.Options.ConfigurationEndpointUris) ? OpenIddictServerEndpointType.Configuration :
                    Matches(context.Options.CryptographyEndpointUris)  ? OpenIddictServerEndpointType.Cryptography  :
                    Matches(context.Options.DeviceEndpointUris)        ? OpenIddictServerEndpointType.Device        :
                    Matches(context.Options.IntrospectionEndpointUris) ? OpenIddictServerEndpointType.Introspection :
                    Matches(context.Options.LogoutEndpointUris)        ? OpenIddictServerEndpointType.Logout        :
                    Matches(context.Options.RevocationEndpointUris)    ? OpenIddictServerEndpointType.Revocation    :
                    Matches(context.Options.TokenEndpointUris)         ? OpenIddictServerEndpointType.Token         :
                    Matches(context.Options.UserinfoEndpointUris)      ? OpenIddictServerEndpointType.Userinfo      :
                    Matches(context.Options.VerificationEndpointUris)  ? OpenIddictServerEndpointType.Verification  :
                                                                         OpenIddictServerEndpointType.Unknown;

                return default;

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
        /// Contains the logic responsible of infering the issuer URL from the HTTP request host and validating it.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public class InferIssuerFromHost : IOpenIddictServerHandler<ProcessRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<InferIssuerFromHost>()
                    .SetOrder(InferEndpointType.Descriptor.Order + 1_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessRequestContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var request = context.Transaction.GetHttpRequest();
                if (request == null)
                {
                    throw new InvalidOperationException("The ASP.NET Core HTTP request cannot be resolved.");
                }

                // Don't require that the request host be present if the request is not handled
                // by an OpenIddict endpoint or if an explicit issuer URL was already set.
                if (context.Issuer != null || context.EndpointType == OpenIddictServerEndpointType.Unknown)
                {
                    return default;
                }

                if (!request.Host.HasValue)
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: "The mandatory 'Host' header is missing.");

                    return default;
                }

                if (!Uri.TryCreate(request.Scheme + "://" + request.Host + request.PathBase, UriKind.Absolute, out Uri issuer) ||
                    !issuer.IsWellFormedOriginalString())
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: "The specified 'Host' header is invalid.");

                    return default;
                }

                context.Issuer = issuer;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of rejecting OpenID Connect requests that don't use transport security.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public class ValidateTransportSecurityRequirement : IOpenIddictServerHandler<ProcessRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireHttpRequest>()
                    .AddFilter<RequireTransportSecurityRequirementEnabled>()
                    .UseSingletonHandler<ValidateTransportSecurityRequirement>()
                    .SetOrder(InferEndpointType.Descriptor.Order + 1_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessRequestContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var request = context.Transaction.GetHttpRequest();
                if (request == null)
                {
                    throw new InvalidOperationException("The ASP.NET Core HTTP request cannot be resolved.");
                }

                // Don't require that the host be present if the request is not handled by OpenIddict.
                if (context.EndpointType == OpenIddictServerEndpointType.Unknown)
                {
                    return default;
                }

                // Reject authorization requests sent without transport security.
                if (!request.IsHttps)
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: "This server only accepts HTTPS requests.");

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of attaching the error details using the ASP.NET Core authentication properties.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public class AttachHostChallengeError : IOpenIddictServerHandler<ProcessChallengeContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<AttachHostChallengeError>()
                    .SetOrder(AttachDefaultChallengeError.Descriptor.Order - 1_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessChallengeContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (context.Transaction.Properties.TryGetValue(typeof(AuthenticationProperties).FullName, out var property) &&
                    property is AuthenticationProperties properties)
                {
                    context.Response.Error = properties.GetString(Properties.Error);
                    context.Response.ErrorDescription = properties.GetString(Properties.ErrorDescription);
                    context.Response.ErrorUri = properties.GetString(Properties.ErrorUri);
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of extracting OpenID Connect requests from GET HTTP requests.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public class ExtractGetRequest<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseValidatingContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<ExtractGetRequest<TContext>>()
                    .SetOrder(ValidateTransportSecurityRequirement.Descriptor.Order + 1_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] TContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var request = context.Transaction.GetHttpRequest();
                if (request == null)
                {
                    throw new InvalidOperationException("The ASP.NET Core HTTP request cannot be resolved.");
                }

                if (HttpMethods.IsGet(request.Method))
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

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of extracting OpenID Connect requests from GET or POST HTTP requests.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public class ExtractGetOrPostRequest<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseValidatingContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<ExtractGetOrPostRequest<TContext>>()
                    .SetOrder(ExtractGetRequest<TContext>.Descriptor.Order + 1_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async ValueTask HandleAsync([NotNull] TContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var request = context.Transaction.GetHttpRequest();
                if (request == null)
                {
                    throw new InvalidOperationException("The ASP.NET Core HTTP request cannot be resolved.");
                }

                if (HttpMethods.IsGet(request.Method))
                {
                    context.Request = new OpenIddictRequest(request.Query);
                }

                else if (HttpMethods.IsPost(request.Method))
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

                    context.Request = new OpenIddictRequest(await request.ReadFormAsync(request.HttpContext.RequestAborted));
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
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public class ExtractPostRequest<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseValidatingContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<ExtractPostRequest<TContext>>()
                    .SetOrder(ExtractGetOrPostRequest<TContext>.Descriptor.Order + 1_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async ValueTask HandleAsync([NotNull] TContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var request = context.Transaction.GetHttpRequest();
                if (request == null)
                {
                    throw new InvalidOperationException("The ASP.NET Core HTTP request cannot be resolved.");
                }

                if (HttpMethods.IsPost(request.Method))
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

                    context.Request = new OpenIddictRequest(await request.ReadFormAsync(request.HttpContext.RequestAborted));
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
        /// Contains the logic responsible of extracting client credentials from the standard HTTP Authorization header.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public class ExtractBasicAuthenticationCredentials<TContext> : IOpenIddictServerHandler<TContext>
            where TContext : BaseValidatingContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<ExtractBasicAuthenticationCredentials<TContext>>()
                    .SetOrder(ExtractPostRequest<TContext>.Descriptor.Order + 1_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] TContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var request = context.Transaction.GetHttpRequest();
                if (request == null)
                {
                    throw new InvalidOperationException("The ASP.NET Core HTTP request cannot be resolved.");
                }

                string header = request.Headers[HeaderNames.Authorization];
                if (string.IsNullOrEmpty(header) || !header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
                {
                    return default;
                }

                // At this point, reject requests that use multiple client authentication methods.
                // See https://tools.ietf.org/html/rfc6749#section-2.3 for more information.
                if (!string.IsNullOrEmpty(context.Request.ClientAssertion) || !string.IsNullOrEmpty(context.Request.ClientSecret))
                {
                    context.Logger.LogError("The request was rejected because multiple client credentials were specified.");

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: "Multiple client credentials cannot be specified.");

                    return default;
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

                        return default;
                    }

                    // Attach the basic authentication credentials to the request message.
                    context.Request.ClientId = UnescapeDataString(data.Substring(0, index));
                    context.Request.ClientSecret = UnescapeDataString(data.Substring(index + 1));

                    return default;
                }

                catch
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: "The specified client credentials are invalid.");

                    return default;
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
        /// Contains the logic responsible of extracting an access token from the standard HTTP Authorization header.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public class ExtractAccessToken<TContext> : IOpenIddictServerHandler<TContext>
            where TContext : BaseValidatingContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<ExtractAccessToken<TContext>>()
                    .SetOrder(ExtractBasicAuthenticationCredentials<TContext>.Descriptor.Order + 1_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] TContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var request = context.Transaction.GetHttpRequest();
                if (request == null)
                {
                    throw new InvalidOperationException("The ASP.NET Core HTTP request cannot be resolved.");
                }

                string header = request.Headers[HeaderNames.Authorization];
                if (string.IsNullOrEmpty(header) || !header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                {
                    return default;
                }

                // Attach the access token to the request message.
                context.Request.AccessToken = header.Substring("Bearer ".Length);

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of enabling the pass-through mode for the received request.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public class EnablePassthroughMode<TContext, TFilter> : IOpenIddictServerHandler<TContext>
            where TContext : BaseRequestContext
            where TFilter : IOpenIddictServerHandlerFilter<TContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireHttpRequest>()
                    .AddFilter<TFilter>()
                    .UseSingletonHandler<EnablePassthroughMode<TContext, TFilter>>()
                    .SetOrder(int.MaxValue - 100_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] TContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                context.SkipRequest();

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of processing empty OpenID Connect responses that should trigger a host redirection.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public class ProcessHostRedirectionResponse<TContext> : IOpenIddictServerHandler<TContext>
            where TContext : BaseRequestContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<ProcessHostRedirectionResponse<TContext>>()
                    .SetOrder(ProcessJsonResponse<TContext>.Descriptor.Order - 1_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] TContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var response = context.Transaction.GetHttpRequest()?.HttpContext.Response;
                if (response == null)
                {
                    throw new InvalidOperationException("The ASP.NET Core HTTP request cannot be resolved.");
                }

                if (context.Transaction.Properties.TryGetValue(typeof(AuthenticationProperties).FullName, out var property) &&
                    property is AuthenticationProperties properties && !string.IsNullOrEmpty(properties.RedirectUri))
                {
                    response.Redirect(properties.RedirectUri);

                    context.Logger.LogInformation("The response was successfully returned as a 302 response.");
                    context.HandleRequest();
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of processing OpenID Connect responses that must be returned as JSON.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public class ProcessJsonResponse<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<ProcessJsonResponse<TContext>>()
                    .SetOrder(ProcessPassthroughErrorResponse<TContext, IOpenIddictServerHandlerFilter<TContext>>.Descriptor.Order - 1_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async ValueTask HandleAsync([NotNull] TContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (context.Response == null)
                {
                    throw new InvalidOperationException("This handler cannot be invoked without a response attached.");
                }

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var request = context.Transaction.GetHttpRequest();
                if (request == null)
                {
                    throw new InvalidOperationException("The ASP.NET Core HTTP request cannot be resolved.");
                }

                context.Logger.LogInformation("The response was successfully returned as a JSON document: {Response}.", context.Response);

                using var stream = new MemoryStream();
                await JsonSerializer.SerializeAsync(stream, context.Response, new JsonSerializerOptions
                {
                    Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                    WriteIndented = false
                });

                if (!string.IsNullOrEmpty(context.Response.Error))
                {
                    // When client authentication is made using basic authentication, the authorization server MUST return
                    // a 401 response with a valid WWW-Authenticate header containing the Basic scheme and a non-empty realm.
                    // A similar error MAY be returned even when basic authentication is not used and MUST also be returned
                    // when an invalid token is received by the userinfo endpoint using the Bearer authentication scheme.
                    // To simplify the logic, a 401 response with the Bearer scheme is returned for invalid_token errors
                    // and a 401 response with the Basic scheme is returned for invalid_client, even if the credentials
                    // were specified in the request form instead of the HTTP headers, as allowed by the specification.
                    var scheme = context.Response.Error switch
                    {
                        Errors.InvalidClient => Schemes.Basic,
                        Errors.InvalidToken  => Schemes.Bearer,
                        _ => null
                    };

                    if (!string.IsNullOrEmpty(scheme))
                    {
                        if (context.Issuer == null)
                        {
                            throw new InvalidOperationException("The issuer address cannot be inferred from the current request.");
                        }

                        request.HttpContext.Response.StatusCode = 401;

                        request.HttpContext.Response.Headers[HeaderNames.WWWAuthenticate] = new StringBuilder()
                            .Append(scheme)
                            .Append(' ')
                            .Append(Parameters.Realm)
                            .Append("=\"")
                            .Append(context.Issuer.AbsoluteUri)
                            .Append('"')
                            .ToString();
                    }

                    else
                    {
                        request.HttpContext.Response.StatusCode = 400;
                    }
                }

                request.HttpContext.Response.ContentLength = stream.Length;
                request.HttpContext.Response.ContentType = "application/json;charset=UTF-8";

                stream.Seek(offset: 0, loc: SeekOrigin.Begin);
                await stream.CopyToAsync(request.HttpContext.Response.Body, 4096, request.HttpContext.RequestAborted);

                context.HandleRequest();
            }
        }

        /// <summary>
        /// Contains the logic responsible of processing OpenID Connect responses that must be handled by another
        /// middleware in the pipeline at a later stage (e.g an ASP.NET Core MVC action or a NancyFX module).
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public class ProcessPassthroughErrorResponse<TContext, TFilter> : IOpenIddictServerHandler<TContext>
            where TContext : BaseRequestContext
            where TFilter : IOpenIddictServerHandlerFilter<TContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireHttpRequest>()
                    .AddFilter<RequireErrorPassthroughEnabled>()
                    .AddFilter<TFilter>()
                    .UseSingletonHandler<ProcessPassthroughErrorResponse<TContext, TFilter>>()
                    .SetOrder(ProcessStatusCodePagesErrorResponse<TContext>.Descriptor.Order - 1_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] TContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var response = context.Transaction.GetHttpRequest()?.HttpContext.Response;
                if (response == null)
                {
                    throw new InvalidOperationException("The ASP.NET Core HTTP request cannot be resolved.");
                }

                if (string.IsNullOrEmpty(context.Response.Error))
                {
                    return default;
                }

                // Apply a 400 status code by default.
                response.StatusCode = 400;

                context.SkipRequest();

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of processing OpenID Connect responses handled by the status code pages middleware.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public class ProcessStatusCodePagesErrorResponse<TContext> : IOpenIddictServerHandler<TContext>
            where TContext : BaseRequestContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireHttpRequest>()
                    .AddFilter<RequireStatusCodePagesIntegrationEnabled>()
                    .UseSingletonHandler<ProcessStatusCodePagesErrorResponse<TContext>>()
                    .SetOrder(ProcessLocalErrorResponse<TContext>.Descriptor.Order - 1_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] TContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (context.Response == null)
                {
                    throw new InvalidOperationException("This handler cannot be invoked without a response attached.");
                }

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var response = context.Transaction.GetHttpRequest()?.HttpContext.Response;
                if (response == null)
                {
                    throw new InvalidOperationException("The ASP.NET Core HTTP request cannot be resolved.");
                }

                if (string.IsNullOrEmpty(context.Response.Error))
                {
                    return default;
                }

                // Determine if the status code pages middleware has been enabled for this request.
                // If it was not registered or enabled, let the default OpenIddict server handlers render
                // a default error page instead of delegating the rendering to the status code middleware.
                var feature = response.HttpContext.Features.Get<IStatusCodePagesFeature>();
                if (feature == null || !feature.Enabled)
                {
                    return default;
                }

                // Replace the default status code to return a 400 response.
                response.StatusCode = 400;

                // Mark the request as fully handled to prevent the other OpenIddict server handlers
                // from displaying the default error page and to allow the status code pages middleware
                // to rewrite the response using the logic defined by the developer when registering it.
                context.HandleRequest();

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of processing context responses that must be returned as plain-text.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public class ProcessLocalErrorResponse<TContext> : IOpenIddictServerHandler<TContext>
            where TContext : BaseRequestContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<ProcessLocalErrorResponse<TContext>>()
                    .SetOrder(ProcessEmptyResponse<TContext>.Descriptor.Order - 1_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async ValueTask HandleAsync([NotNull] TContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var response = context.Transaction.GetHttpRequest()?.HttpContext.Response;
                if (response == null)
                {
                    throw new InvalidOperationException("The ASP.NET Core HTTP request cannot be resolved.");
                }

                if (string.IsNullOrEmpty(context.Response.Error))
                {
                    return;
                }

                // Don't return the state originally sent by the client application.
                context.Response.State = null;

                // Apply a 400 status code by default.
                response.StatusCode = 400;

                context.Logger.LogInformation("The authorization response was successfully returned " +
                                              "as a plain-text document: {Response}.", context.Response);

                using (var buffer = new MemoryStream())
                using (var writer = new StreamWriter(buffer))
                {
                    foreach (var parameter in context.Response.GetParameters())
                    {
                        // Ignore null or empty parameters, including JSON
                        // objects that can't be represented as strings.
                        var value = (string) parameter.Value;
                        if (string.IsNullOrEmpty(value))
                        {
                            continue;
                        }

                        writer.WriteLine("{0}:{1}", parameter.Key, value);
                    }

                    writer.Flush();

                    response.ContentLength = buffer.Length;
                    response.ContentType = "text/plain;charset=UTF-8";

                    response.Headers[HeaderNames.CacheControl] = "no-cache";
                    response.Headers[HeaderNames.Pragma] = "no-cache";
                    response.Headers[HeaderNames.Expires] = "Thu, 01 Jan 1970 00:00:00 GMT";

                    buffer.Seek(offset: 0, loc: SeekOrigin.Begin);
                    await buffer.CopyToAsync(response.Body, 4096, response.HttpContext.RequestAborted);
                }

                context.HandleRequest();
            }
        }

        /// <summary>
        /// Contains the logic responsible of processing OpenID Connect responses that don't specify any parameter.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public class ProcessEmptyResponse<TContext> : IOpenIddictServerHandler<TContext>
            where TContext : BaseRequestContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<ProcessEmptyResponse<TContext>>()
                    .SetOrder(int.MaxValue - 100_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] TContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var response = context.Transaction.GetHttpRequest()?.HttpContext.Response;
                if (response == null)
                {
                    throw new InvalidOperationException("The ASP.NET Core HTTP request cannot be resolved.");
                }

                context.Logger.LogInformation("The response was successfully returned as an empty 200 response.");
                context.HandleRequest();

                return default;
            }
        }
    }
}
