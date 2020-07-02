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
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using OpenIddict.Abstractions;
using Owin;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers;
using static OpenIddict.Server.Owin.OpenIddictServerOwinHandlerFilters;
using Properties = OpenIddict.Server.Owin.OpenIddictServerOwinConstants.Properties;

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
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
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

                // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var request = context.Transaction.GetOwinRequest();
                if (request == null)
                {
                    throw new InvalidOperationException("The OWIN request cannot be resolved.");
                }

                context.EndpointType =
                    Matches(request, context.Options.AuthorizationEndpointUris) ? OpenIddictServerEndpointType.Authorization :
                    Matches(request, context.Options.ConfigurationEndpointUris) ? OpenIddictServerEndpointType.Configuration :
                    Matches(request, context.Options.CryptographyEndpointUris)  ? OpenIddictServerEndpointType.Cryptography  :
                    Matches(request, context.Options.DeviceEndpointUris)        ? OpenIddictServerEndpointType.Device        :
                    Matches(request, context.Options.IntrospectionEndpointUris) ? OpenIddictServerEndpointType.Introspection :
                    Matches(request, context.Options.LogoutEndpointUris)        ? OpenIddictServerEndpointType.Logout        :
                    Matches(request, context.Options.RevocationEndpointUris)    ? OpenIddictServerEndpointType.Revocation    :
                    Matches(request, context.Options.TokenEndpointUris)         ? OpenIddictServerEndpointType.Token         :
                    Matches(request, context.Options.UserinfoEndpointUris)      ? OpenIddictServerEndpointType.Userinfo      :
                    Matches(request, context.Options.VerificationEndpointUris)  ? OpenIddictServerEndpointType.Verification  :
                                                                                  OpenIddictServerEndpointType.Unknown;

                return default;

                static bool Matches(IOwinRequest request, IReadOnlyList<Uri> addresses)
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
                            if (AreEquivalent(path, request.PathBase + request.Path))
                            {
                                return true;
                            }
                        }

                        else if (address.OriginalString.StartsWith("/", StringComparison.OrdinalIgnoreCase))
                        {
                            var path = new PathString(address.OriginalString);
                            if (AreEquivalent(path, request.Path))
                            {
                                return true;
                            }
                        }
                    }

                    return false;

                    // ASP.NET MVC's routing system ignores trailing slashes when determining
                    // whether the request path matches a registered route, which is not the case
                    // with PathString, that treats /connect/token and /connect/token/ as different
                    // addresses. To mitigate this inconsistency, a manual check is used here.
                    static bool AreEquivalent(PathString left, PathString right)
                        => left.Equals(right, StringComparison.OrdinalIgnoreCase) ||
                           left.Equals(right + new PathString("/"), StringComparison.OrdinalIgnoreCase) ||
                           right.Equals(left + new PathString("/"), StringComparison.OrdinalIgnoreCase);
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of infering the issuer URL from the HTTP request host and validating it.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
        /// </summary>
        public class InferIssuerFromHost : IOpenIddictServerHandler<ProcessRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<InferIssuerFromHost>()
                    .SetOrder(InferEndpointType.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
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

                // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var request = context.Transaction.GetOwinRequest();
                if (request == null)
                {
                    throw new InvalidOperationException("The OWIN request cannot be resolved.");
                }

                // Don't require that the request host be present if the request is not handled
                // by an OpenIddict endpoint or if an explicit issuer URL was already set.
                if (context.Issuer != null || context.EndpointType == OpenIddictServerEndpointType.Unknown)
                {
                    return default;
                }

                if (string.IsNullOrEmpty(request.Host.Value))
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
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
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
                    return default;
                }

                // Reject authorization requests sent without transport security.
                if (!request.IsSecure)
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
        /// Contains the logic responsible of attaching the error details using the OWIN authentication properties.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
        /// </summary>
        public class AttachHostChallengeError : IOpenIddictServerHandler<ProcessChallengeContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<AttachHostChallengeError>()
                    .SetOrder(AttachDefaultChallengeError.Descriptor.Order - 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
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

                var properties = context.Transaction.GetProperty<AuthenticationProperties>(typeof(AuthenticationProperties).FullName);
                if (properties != null)
                {
                    context.Response.Error = GetProperty(properties, Properties.Error);
                    context.Response.ErrorDescription = GetProperty(properties, Properties.ErrorDescription);
                    context.Response.ErrorUri = GetProperty(properties, Properties.ErrorUri);
                    context.Response.Scope = GetProperty(properties, Properties.Scope);
                }

                return default;

                static string GetProperty(AuthenticationProperties properties, string name)
                    => properties.Dictionary.TryGetValue(name, out string value) ? value : null;
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
                    .UseSingletonHandler<ExtractGetRequest<TContext>>()
                    .SetOrder(ValidateTransportSecurityRequirement.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
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

                    return default;
                }

                return default;
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
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
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
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
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
        /// Contains the logic responsible of extracting client credentials from the standard HTTP Authorization header.
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
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
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
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
        /// </summary>
        public class ExtractAccessToken<TContext> : IOpenIddictServerHandler<TContext>
            where TContext : BaseValidatingContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<ExtractAccessToken<TContext>>()
                    .SetOrder(ExtractBasicAuthenticationCredentials<TContext>.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
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

                // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var request = context.Transaction.GetOwinRequest();
                if (request == null)
                {
                    throw new InvalidOperationException("The OWIN request cannot be resolved.");
                }

                var header = request.Headers["Authorization"];
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
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
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
                    .AddFilter<RequireOwinRequest>()
                    .AddFilter<TFilter>()
                    .UseSingletonHandler<EnablePassthroughMode<TContext, TFilter>>()
                    .SetOrder(int.MaxValue - 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
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
        /// Contains the logic responsible of attaching an appropriate HTTP status code.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
        /// </summary>
        public class AttachHttpResponseCode<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<AttachHttpResponseCode<TContext>>()
                    .SetOrder(AttachCacheControlHeader<TContext>.Descriptor.Order - 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
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

                // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var response = context.Transaction.GetOwinRequest()?.Context.Response;
                if (response == null)
                {
                    throw new InvalidOperationException("The OWIN request cannot be resolved.");
                }

                // When client authentication is made using basic authentication, the authorization server MUST return
                // a 401 response with a valid WWW-Authenticate header containing the Basic scheme and a non-empty realm.
                // A similar error MAY be returned even when basic authentication is not used and MUST also be returned
                // when an invalid token is received by the userinfo endpoint using the Bearer authentication scheme.
                // To simplify the logic, a 401 response with the Bearer scheme is returned for invalid_token errors
                // and a 401 response with the Basic scheme is returned for invalid_client, even if the credentials
                // were specified in the request form instead of the HTTP headers, as allowed by the specification.
                response.StatusCode = context.Response.Error switch
                {
                    null => 200, // Note: the default code may be replaced by another handler (e.g when doing redirects).

                    Errors.InvalidClient => 401,
                    Errors.InvalidToken  => 401,
                    Errors.MissingToken  => 401,

                    Errors.InsufficientAccess => 403,
                    Errors.InsufficientScope  => 403,

                    _ => 400
                };

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of attaching the appropriate HTTP response cache headers.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
        /// </summary>
        public class AttachCacheControlHeader<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<AttachCacheControlHeader<TContext>>()
                    .SetOrder(AttachWwwAuthenticateHeader<TContext>.Descriptor.Order - 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
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

                // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var response = context.Transaction.GetOwinRequest()?.Context.Response;
                if (response == null)
                {
                    throw new InvalidOperationException("The OWIN request cannot be resolved.");
                }

                // Prevent the response from being cached.
                response.Headers["Cache-Control"] = "no-store";
                response.Headers["Pragma"] = "no-cache";
                response.Headers["Expires"] = "Thu, 01 Jan 1970 00:00:00 GMT";

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of attaching errors details to the WWW-Authenticate header.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
        /// </summary>
        public class AttachWwwAuthenticateHeader<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
        {
            private readonly IOptionsMonitor<OpenIddictServerOwinOptions> _options;

            public AttachWwwAuthenticateHeader([NotNull] IOptionsMonitor<OpenIddictServerOwinOptions> options)
                => _options = options;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<AttachWwwAuthenticateHeader<TContext>>()
                    .SetOrder(ProcessChallengeErrorResponse<TContext>.Descriptor.Order - 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
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

                // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var response = context.Transaction.GetOwinRequest()?.Context.Response;
                if (response == null)
                {
                    throw new InvalidOperationException("The OWIN request cannot be resolved.");
                }

                // When client authentication is made using basic authentication, the authorization server MUST return
                // a 401 response with a valid WWW-Authenticate header containing the HTTP Basic authentication scheme.
                // A similar error MAY be returned even when basic authentication is not used and MUST also be returned
                // when an invalid token is received by the userinfo endpoint using the Bearer authentication scheme.
                // To simplify the logic, a 401 response with the Bearer scheme is returned for invalid_token errors
                // and a 401 response with the Basic scheme is returned for invalid_client, even if the credentials
                // were specified in the request form instead of the HTTP headers, as allowed by the specification.
                var scheme = context.Response.Error switch
                {
                    Errors.InvalidClient      => Schemes.Basic,

                    Errors.InvalidToken       => Schemes.Bearer,
                    Errors.MissingToken       => Schemes.Bearer,
                    Errors.InsufficientAccess => Schemes.Bearer,
                    Errors.InsufficientScope  => Schemes.Bearer,

                    _ => null
                };

                if (string.IsNullOrEmpty(scheme))
                {
                    return default;
                }

                var parameters = new Dictionary<string, string>(StringComparer.Ordinal);

                // If a realm was configured in the options, attach it to the parameters.
                if (!string.IsNullOrEmpty(_options.CurrentValue.Realm))
                {
                    parameters[Parameters.Realm] = _options.CurrentValue.Realm;
                }

                foreach (var parameter in context.Response.GetParameters())
                {
                    // Note: the error details are only included if the error was not caused by a missing token, as recommended
                    // by the OAuth 2.0 bearer specification: https://tools.ietf.org/html/rfc6750#section-3.1.
                    if (string.Equals(context.Response.Error, Errors.MissingToken, StringComparison.Ordinal) &&
                       (string.Equals(parameter.Key, Parameters.Error, StringComparison.Ordinal) ||
                        string.Equals(parameter.Key, Parameters.ErrorDescription, StringComparison.Ordinal) ||
                        string.Equals(parameter.Key, Parameters.ErrorUri, StringComparison.Ordinal)))
                    {
                        continue;
                    }

                    // Ignore values that can't be represented as unique strings.
                    var value = (string) parameter.Value;
                    if (string.IsNullOrEmpty(value))
                    {
                        continue;
                    }

                    parameters[parameter.Key] = value;
                }

                var builder = new StringBuilder(scheme);

                foreach (var parameter in parameters)
                {
                    builder.Append(' ');
                    builder.Append(parameter.Key);
                    builder.Append('=');
                    builder.Append('"');
                    builder.Append(parameter.Value.Replace("\"", "\\\""));
                    builder.Append('"');
                    builder.Append(',');
                }

                // If the WWW-Authenticate header ends with a comma, remove it.
                if (builder[builder.Length - 1] == ',')
                {
                    builder.Remove(builder.Length - 1, 1);
                }

                response.Headers.Append("WWW-Authenticate", builder.ToString());

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of processing challenge responses that contain a WWW-Authenticate header.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
        /// </summary>
        public class ProcessChallengeErrorResponse<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<ProcessChallengeErrorResponse<TContext>>()
                    .SetOrder(ProcessJsonResponse<TContext>.Descriptor.Order - 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
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

                // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var response = context.Transaction.GetOwinRequest()?.Context.Response;
                if (response == null)
                {
                    throw new InvalidOperationException("The OWIN request cannot be resolved.");
                }

                // If the response doesn't contain a WWW-Authenticate header, don't return an empty response.
                if (!response.Headers.ContainsKey("WWW-Authenticate"))
                {
                    return default;
                }

                context.Logger.LogInformation("The response was successfully returned as a challenge response: {Response}.", context.Response);
                context.HandleRequest();

                return default;
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
                    .SetOrder(ProcessPassthroughErrorResponse<TContext, IOpenIddictServerHandlerFilter<TContext>>.Descriptor.Order - 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
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

                // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var response = context.Transaction.GetOwinRequest()?.Context.Response;
                if (response == null)
                {
                    throw new InvalidOperationException("The OWIN request cannot be resolved.");
                }

                context.Logger.LogInformation("The response was successfully returned as a JSON document: {Response}.", context.Response);

                using var stream = new MemoryStream();
                await JsonSerializer.SerializeAsync(stream, context.Response, new JsonSerializerOptions
                {
                    Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                    WriteIndented = false
                });

                response.ContentLength = stream.Length;
                response.ContentType = "application/json;charset=UTF-8";

                stream.Seek(offset: 0, loc: SeekOrigin.Begin);
                await stream.CopyToAsync(response.Body, 4096, response.Context.Request.CallCancelled);

                context.HandleRequest();
            }
        }

        /// <summary>
        /// Contains the logic responsible of processing OpenID Connect responses that must be handled by another
        /// middleware in the pipeline at a later stage (e.g an ASP.NET MVC action or a NancyFX module).
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
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
                    .AddFilter<RequireOwinRequest>()
                    .AddFilter<RequireErrorPassthroughEnabled>()
                    .AddFilter<TFilter>()
                    .UseSingletonHandler<ProcessPassthroughErrorResponse<TContext, TFilter>>()
                    .SetOrder(ProcessLocalErrorResponse<TContext>.Descriptor.Order - 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
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

                // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var response = context.Transaction.GetOwinRequest()?.Context.Response;
                if (response == null)
                {
                    throw new InvalidOperationException("The OWIN request cannot be resolved.");
                }

                if (string.IsNullOrEmpty(context.Response.Error))
                {
                    return default;
                }

                // Don't return the state originally sent by the client application.
                context.Response.State = null;

                context.SkipRequest();

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of processing OpenID Connect responses that must be returned as plain-text.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
        /// </summary>
        public class ProcessLocalErrorResponse<TContext> : IOpenIddictServerHandler<TContext>
            where TContext : BaseRequestContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<ProcessLocalErrorResponse<TContext>>()
                    .SetOrder(ProcessEmptyResponse<TContext>.Descriptor.Order - 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
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

                // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var response = context.Transaction.GetOwinRequest()?.Context.Response;
                if (response == null)
                {
                    throw new InvalidOperationException("The OWIN request cannot be resolved.");
                }

                if (string.IsNullOrEmpty(context.Response.Error))
                {
                    return;
                }

                // Don't return the state originally sent by the client application.
                context.Response.State = null;

                context.Logger.LogInformation("The authorization response was successfully returned " +
                                              "as a plain-text document: {Response}.", context.Response);

                using var stream = new MemoryStream();
                using var writer = new StreamWriter(stream);

                foreach (var parameter in context.Response.GetParameters())
                {
                    // Ignore null or empty parameters, including JSON
                    // objects that can't be represented as strings.
                    var value = (string) parameter.Value;
                    if (string.IsNullOrEmpty(value))
                    {
                        continue;
                    }

                    writer.Write(parameter.Key);
                    writer.Write(':');
                    writer.Write(value);
                    writer.WriteLine();
                }

                writer.Flush();

                response.ContentLength = stream.Length;
                response.ContentType = "text/plain;charset=UTF-8";

                stream.Seek(offset: 0, loc: SeekOrigin.Begin);
                await stream.CopyToAsync(response.Body, 4096, response.Context.Request.CallCancelled);

                context.HandleRequest();
            }
        }

        /// <summary>
        /// Contains the logic responsible of processing empty OpenID Connect responses that should trigger a host redirection.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
        /// </summary>
        public class ProcessHostRedirectionResponse<TContext> : IOpenIddictServerHandler<TContext>
            where TContext : BaseRequestContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<ProcessHostRedirectionResponse<TContext>>()
                    .SetOrder(ProcessEmptyResponse<TContext>.Descriptor.Order - 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
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

                // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var response = context.Transaction.GetOwinRequest()?.Context.Response;
                if (response == null)
                {
                    throw new InvalidOperationException("The OWIN request cannot be resolved.");
                }

                var properties = context.Transaction.GetProperty<AuthenticationProperties>(typeof(AuthenticationProperties).FullName);
                if (properties != null && !string.IsNullOrEmpty(properties.RedirectUri))
                {
                    response.Redirect(properties.RedirectUri);

                    context.Logger.LogInformation("The response was successfully returned as a 302 response.");
                    context.HandleRequest();
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of processing OpenID Connect responses that don't specify any parameter.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
        /// </summary>
        public class ProcessEmptyResponse<TContext> : IOpenIddictServerHandler<TContext>
            where TContext : BaseRequestContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<ProcessEmptyResponse<TContext>>()
                    .SetOrder(int.MaxValue - 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
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

                context.Logger.LogInformation("The response was successfully returned as an empty 200 response.");
                context.HandleRequest();

                return default;
            }
        }
    }
}
