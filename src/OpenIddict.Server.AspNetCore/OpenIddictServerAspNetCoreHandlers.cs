/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.AspNetCore.OpenIddictServerAspNetCoreHandlerFilters;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers;
using Properties = OpenIddict.Server.AspNetCore.OpenIddictServerAspNetCoreConstants.Properties;
using SR = OpenIddict.Abstractions.OpenIddictResources;

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
            ResolveHostChallengeParameters.Descriptor,

            /*
             * Sign-in processing:
             */
            ResolveHostSignInParameters.Descriptor,

            /*
             * Sign-out processing:
             */
            ResolveHostSignOutParameters.Descriptor)
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
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var request = context.Transaction.GetHttpRequest();
                if (request is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));
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

                if (context.EndpointType != OpenIddictServerEndpointType.Unknown)
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6053), context.EndpointType);
                }

                return default;

                static bool Matches(HttpRequest request, IReadOnlyList<Uri> addresses)
                {
                    for (var index = 0; index < addresses.Count; index++)
                    {
                        var address = addresses[index];
                        if (address.IsAbsoluteUri)
                        {
                            // If the request host is not available (e.g because HTTP/1.0 was used), ignore absolute URLs.
                            if (!request.Host.HasValue)
                            {
                                continue;
                            }

                            // Create a Uri instance using the request scheme and raw host and compare the two base addresses.
                            if (!Uri.TryCreate(request.Scheme + Uri.SchemeDelimiter + request.Host, UriKind.Absolute, out Uri? uri) ||
                                !uri.IsWellFormedOriginalString() || uri.Port != address.Port ||
                                !string.Equals(uri.Scheme, address.Scheme, StringComparison.OrdinalIgnoreCase) ||
                                !string.Equals(uri.Host, address.Host, StringComparison.OrdinalIgnoreCase))
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

                    // ASP.NET Core's routing system ignores trailing slashes when determining
                    // whether the request path matches a registered route, which is not the case
                    // with PathString, that treats /connect/token and /connect/token/ as different
                    // addresses. To mitigate this inconsistency, a manual check is used here.
                    static bool AreEquivalent(PathString left, PathString right)
                        => left.Equals(right, StringComparison.OrdinalIgnoreCase) ||
                           left.Equals(right + "/", StringComparison.OrdinalIgnoreCase) ||
                           right.Equals(left + "/", StringComparison.OrdinalIgnoreCase);
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
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var request = context.Transaction.GetHttpRequest();
                if (request is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));
                }

                // Don't require that the request host be present if the request is not handled
                // by an OpenIddict endpoint or if an explicit issuer URL was already set.
                if (context.Issuer is not null || context.EndpointType == OpenIddictServerEndpointType.Unknown)
                {
                    return default;
                }

                if (!request.Host.HasValue)
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2081(HeaderNames.Host),
                        uri: SR.FormatID8000(SR.ID2081));

                    return default;
                }

                if (!Uri.TryCreate(request.Scheme + Uri.SchemeDelimiter + request.Host + request.PathBase, UriKind.Absolute, out Uri? issuer) ||
                    !issuer.IsWellFormedOriginalString())
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2082(HeaderNames.Host),
                        uri: SR.FormatID8000(SR.ID2082));

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
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var request = context.Transaction.GetHttpRequest();
                if (request is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));
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
                        description: SR.GetResourceString(SR.ID2083),
                        uri: SR.FormatID8000(SR.ID2083));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of resolving the additional sign-in parameters stored in the ASP.NET
        /// Core authentication properties specified by the application that triggered the sign-in operation.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public class ResolveHostChallengeParameters : IOpenIddictServerHandler<ProcessChallengeContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<ResolveHostChallengeParameters>()
                    .SetOrder(AttachDefaultChallengeError.Descriptor.Order - 500)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessChallengeContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var properties = context.Transaction.GetProperty<AuthenticationProperties>(typeof(AuthenticationProperties).FullName!);
                if (properties is null)
                {
                    return default;
                }

                if (properties.Items.TryGetValue(Properties.Error, out string? error) &&
                    !string.IsNullOrEmpty(error))
                {
                    context.Parameters[Parameters.Error] = error;
                }

                if (properties.Items.TryGetValue(Properties.ErrorDescription, out string? description) &&
                    !string.IsNullOrEmpty(description))
                {
                    context.Parameters[Parameters.ErrorDescription] = description;
                }

                if (properties.Items.TryGetValue(Properties.ErrorUri, out string? uri) &&
                    !string.IsNullOrEmpty(uri))
                {
                    context.Parameters[Parameters.ErrorUri] = uri;
                }

                if (properties.Items.TryGetValue(Properties.Scope, out string? scope) &&
                    !string.IsNullOrEmpty(scope))
                {
                    context.Parameters[Parameters.Scope] = scope;
                }

                foreach (var parameter in properties.Parameters)
                {
                    context.Parameters[parameter.Key] = parameter.Value switch
                    {
                        OpenIddictParameter value => value,
                        JsonElement         value => new OpenIddictParameter(value),
                        bool                value => new OpenIddictParameter(value),
                        int                 value => new OpenIddictParameter(value),
                        long                value => new OpenIddictParameter(value),
                        string              value => new OpenIddictParameter(value),
                        string[]            value => new OpenIddictParameter(value),

                        _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0115))
                    };
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of resolving the additional sign-in parameters stored in the ASP.NET
        /// Core authentication properties specified by the application that triggered the sign-in operation.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public class ResolveHostSignInParameters : IOpenIddictServerHandler<ProcessSignInContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<ResolveHostSignInParameters>()
                    .SetOrder(AttachSignInParameters.Descriptor.Order - 500)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessSignInContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var properties = context.Transaction.GetProperty<AuthenticationProperties>(typeof(AuthenticationProperties).FullName!);
                if (properties is null)
                {
                    return default;
                }

                foreach (var parameter in properties.Parameters)
                {
                    context.Parameters[parameter.Key] = parameter.Value switch
                    {
                        OpenIddictParameter value => value,
                        JsonElement         value => new OpenIddictParameter(value),
                        bool                value => new OpenIddictParameter(value),
                        int                 value => new OpenIddictParameter(value),
                        long                value => new OpenIddictParameter(value),
                        string              value => new OpenIddictParameter(value),
                        string[]            value => new OpenIddictParameter(value),

                        _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0115))
                    };
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of resolving the additional sign-out parameters stored in the ASP.NET
        /// Core authentication properties specified by the application that triggered the sign-out operation.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public class ResolveHostSignOutParameters : IOpenIddictServerHandler<ProcessSignOutContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignOutContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<ResolveHostSignOutParameters>()
                    .SetOrder(AttachSignOutParameters.Descriptor.Order - 500)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessSignOutContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var properties = context.Transaction.GetProperty<AuthenticationProperties>(typeof(AuthenticationProperties).FullName!);
                if (properties is null)
                {
                    return default;
                }

                foreach (var parameter in properties.Parameters)
                {
                    context.Parameters[parameter.Key] = parameter.Value switch
                    {
                        OpenIddictParameter value => value,
                        JsonElement         value => new OpenIddictParameter(value),
                        bool                value => new OpenIddictParameter(value),
                        int                 value => new OpenIddictParameter(value),
                        long                value => new OpenIddictParameter(value),
                        string              value => new OpenIddictParameter(value),
                        string[]            value => new OpenIddictParameter(value),

                        _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0115))
                    };
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
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(TContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var request = context.Transaction.GetHttpRequest();
                if (request is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));
                }

                if (HttpMethods.IsGet(request.Method))
                {
                    context.Transaction.Request = new OpenIddictRequest(request.Query);
                }

                else
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6137), request.Method);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.GetResourceString(SR.ID2084),
                        uri: SR.FormatID8000(SR.ID2084));

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
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(TContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var request = context.Transaction.GetHttpRequest();
                if (request is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));
                }

                if (HttpMethods.IsGet(request.Method))
                {
                    context.Transaction.Request = new OpenIddictRequest(request.Query);
                }

                else if (HttpMethods.IsPost(request.Method))
                {
                    // See http://openid.net/specs/openid-connect-core-1_0.html#FormSerialization
                    if (string.IsNullOrEmpty(request.ContentType))
                    {
                        context.Logger.LogInformation(SR.GetResourceString(SR.ID6138), HeaderNames.ContentType);

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: SR.FormatID2081(HeaderNames.ContentType),
                            uri: SR.FormatID8000(SR.ID2081));

                        return;
                    }

                    // May have media/type; charset=utf-8, allow partial match.
                    if (!request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
                    {
                        context.Logger.LogInformation(SR.GetResourceString(SR.ID6139), HeaderNames.ContentType, request.ContentType);

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: SR.FormatID2082(HeaderNames.ContentType),
                            uri: SR.FormatID8000(SR.ID2082));

                        return;
                    }

                    context.Transaction.Request = new OpenIddictRequest(await request.ReadFormAsync(request.HttpContext.RequestAborted));
                }

                else
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6137), request.Method);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.GetResourceString(SR.ID2084),
                        uri: SR.FormatID8000(SR.ID2084));

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
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(TContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var request = context.Transaction.GetHttpRequest();
                if (request is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));
                }

                if (HttpMethods.IsPost(request.Method))
                {
                    // See http://openid.net/specs/openid-connect-core-1_0.html#FormSerialization
                    if (string.IsNullOrEmpty(request.ContentType))
                    {
                        context.Logger.LogInformation(SR.GetResourceString(SR.ID6138), HeaderNames.ContentType);

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: SR.FormatID2081(HeaderNames.ContentType),
                            uri: SR.FormatID8000(SR.ID2081));

                        return;
                    }

                    // May have media/type; charset=utf-8, allow partial match.
                    if (!request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
                    {
                        context.Logger.LogInformation(SR.GetResourceString(SR.ID6139), HeaderNames.ContentType, request.ContentType);

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: SR.FormatID2082(HeaderNames.ContentType),
                            uri: SR.FormatID8000(SR.ID2082));

                        return;
                    }

                    context.Transaction.Request = new OpenIddictRequest(await request.ReadFormAsync(request.HttpContext.RequestAborted));
                }

                else
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6137), request.Method);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.GetResourceString(SR.ID2084),
                        uri: SR.FormatID8000(SR.ID2084));

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
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(TContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(context.Transaction.Request is not null, SR.GetResourceString(SR.ID4008));

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var request = context.Transaction.GetHttpRequest();
                if (request is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));
                }

                string header = request.Headers[HeaderNames.Authorization];
                if (string.IsNullOrEmpty(header) || !header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
                {
                    return default;
                }

                // At this point, reject requests that use multiple client authentication methods.
                // See https://tools.ietf.org/html/rfc6749#section-2.3 for more information.
                if (!string.IsNullOrEmpty(context.Transaction.Request.ClientAssertion) ||
                    !string.IsNullOrEmpty(context.Transaction.Request.ClientSecret))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6140));

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.GetResourceString(SR.ID2087),
                        uri: SR.FormatID8000(SR.ID2087));

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
                            description: SR.GetResourceString(SR.ID2055),
                            uri: SR.FormatID8000(SR.ID2055));

                        return default;
                    }

                    // Attach the basic authentication credentials to the request message.
                    context.Transaction.Request.ClientId = UnescapeDataString(data.Substring(0, index));
                    context.Transaction.Request.ClientSecret = UnescapeDataString(data.Substring(index + 1));

                    return default;
                }

                catch
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.GetResourceString(SR.ID2055),
                        uri: SR.FormatID8000(SR.ID2055));

                    return default;
                }

                static string? UnescapeDataString(string data)
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
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(TContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var request = context.Transaction.GetHttpRequest();
                if (request is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));
                }

                Debug.Assert(context.Transaction.Request is not null, SR.GetResourceString(SR.ID4008));

                string header = request.Headers[HeaderNames.Authorization];
                if (string.IsNullOrEmpty(header) || !header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                {
                    return default;
                }

                // Attach the access token to the request message.
                context.Transaction.Request.AccessToken = header.Substring("Bearer ".Length);

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
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(TContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                context.SkipRequest();

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of attaching an appropriate HTTP status code.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public class AttachHttpResponseCode<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<AttachHttpResponseCode<TContext>>()
                    .SetOrder(100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(TContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var response = context.Transaction.GetHttpRequest()?.HttpContext.Response;
                if (response is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));
                }

                Debug.Assert(context.Transaction.Response is not null, SR.GetResourceString(SR.ID4007));

                // When client authentication is made using basic authentication, the authorization server MUST return
                // a 401 response with a valid WWW-Authenticate header containing the Basic scheme and a non-empty realm.
                // A similar error MAY be returned even when basic authentication is not used and MUST also be returned
                // when an invalid token is received by the userinfo endpoint using the Bearer authentication scheme.
                // To simplify the logic, a 401 response with the Bearer scheme is returned for invalid_token errors
                // and a 401 response with the Basic scheme is returned for invalid_client, even if the credentials
                // were specified in the request form instead of the HTTP headers, as allowed by the specification.
                response.StatusCode = context.Transaction.Response.Error switch
                {
                    null => 200, // Note: the default code may be replaced by another handler (e.g when doing redirects).

                    Errors.InvalidClient or Errors.InvalidToken or Errors.MissingToken => 401,

                    Errors.InsufficientAccess or Errors.InsufficientScope => 403,

                    _  => 400
                };

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of attaching the appropriate HTTP response cache headers.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public class AttachCacheControlHeader<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<AttachCacheControlHeader<TContext>>()
                    .SetOrder(AttachHttpResponseCode<TContext>.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(TContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var response = context.Transaction.GetHttpRequest()?.HttpContext.Response;
                if (response is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));
                }

                // Prevent the response from being cached.
                response.Headers[HeaderNames.CacheControl] = "no-store";
                response.Headers[HeaderNames.Pragma] = "no-cache";
                response.Headers[HeaderNames.Expires] = "Thu, 01 Jan 1970 00:00:00 GMT";

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of attaching errors details to the WWW-Authenticate header.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public class AttachWwwAuthenticateHeader<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
        {
            private readonly IOptionsMonitor<OpenIddictServerAspNetCoreOptions> _options;

            public AttachWwwAuthenticateHeader(IOptionsMonitor<OpenIddictServerAspNetCoreOptions> options)
                => _options = options;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<AttachWwwAuthenticateHeader<TContext>>()
                    .SetOrder(AttachCacheControlHeader<TContext>.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(TContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var response = context.Transaction.GetHttpRequest()?.HttpContext.Response;
                if (response is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));
                }

                Debug.Assert(context.Transaction.Response is not null, SR.GetResourceString(SR.ID4007));

                // When client authentication is made using basic authentication, the authorization server MUST return
                // a 401 response with a valid WWW-Authenticate header containing the HTTP Basic authentication scheme.
                // A similar error MAY be returned even when basic authentication is not used and MUST also be returned
                // when an invalid token is received by the userinfo endpoint using the Bearer authentication scheme.
                // To simplify the logic, a 401 response with the Bearer scheme is returned for invalid_token errors
                // and a 401 response with the Basic scheme is returned for invalid_client, even if the credentials
                // were specified in the request form instead of the HTTP headers, as allowed by the specification.
                var scheme = context.Transaction.Response.Error switch
                {
                    Errors.InvalidClient => Schemes.Basic,

                    Errors.InvalidToken or
                    Errors.MissingToken or
                    Errors.InsufficientAccess or
                    Errors.InsufficientScope => Schemes.Bearer,

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

                foreach (var parameter in context.Transaction.Response.GetParameters())
                {
                    // Note: the error details are only included if the error was not caused by a missing token, as recommended
                    // by the OAuth 2.0 bearer specification: https://tools.ietf.org/html/rfc6750#section-3.1.
                    if (string.Equals(context.Transaction.Response.Error, Errors.MissingToken, StringComparison.Ordinal) &&
                       (string.Equals(parameter.Key, Parameters.Error, StringComparison.Ordinal) ||
                        string.Equals(parameter.Key, Parameters.ErrorDescription, StringComparison.Ordinal) ||
                        string.Equals(parameter.Key, Parameters.ErrorUri, StringComparison.Ordinal)))
                    {
                        continue;
                    }

                    // Ignore values that can't be represented as unique strings.
                    var value = (string?) parameter.Value;
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

                response.Headers.Append(HeaderNames.WWWAuthenticate, builder.ToString());

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of processing challenge responses that contain a WWW-Authenticate header.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public class ProcessChallengeErrorResponse<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<ProcessChallengeErrorResponse<TContext>>()
                    .SetOrder(AttachWwwAuthenticateHeader<TContext>.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(TContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var response = context.Transaction.GetHttpRequest()?.HttpContext.Response;
                if (response is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));
                }

                // If the response doesn't contain a WWW-Authenticate header, don't return an empty response.
                if (!response.Headers.ContainsKey(HeaderNames.WWWAuthenticate))
                {
                    return default;
                }

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6141), context.Transaction.Response);
                context.HandleRequest();

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
                    .SetOrder(ProcessChallengeErrorResponse<TContext>.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(TContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(context.Transaction.Response is not null, SR.GetResourceString(SR.ID4007));

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var response = context.Transaction.GetHttpRequest()?.HttpContext.Response;
                if (response is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));
                }

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6142), context.Transaction.Response);

                using var stream = new MemoryStream();
                using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
                {
                    Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                    Indented = true
                });

                context.Transaction.Response.WriteTo(writer);
                writer.Flush();

                response.ContentLength = stream.Length;
                response.ContentType = "application/json;charset=UTF-8";

                stream.Seek(offset: 0, loc: SeekOrigin.Begin);
                await stream.CopyToAsync(response.Body, 4096, response.HttpContext.RequestAborted);

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
                    .SetOrder(ProcessJsonResponse<TContext>.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(TContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var response = context.Transaction.GetHttpRequest()?.HttpContext.Response;
                if (response is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));
                }

                Debug.Assert(context.Transaction.Response is not null, SR.GetResourceString(SR.ID4007));

                if (string.IsNullOrEmpty(context.Transaction.Response.Error))
                {
                    return default;
                }

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
                    .SetOrder(ProcessPassthroughErrorResponse<TContext, IOpenIddictServerHandlerFilter<TContext>>.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(TContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var response = context.Transaction.GetHttpRequest()?.HttpContext.Response;
                if (response is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));
                }

                Debug.Assert(context.Transaction.Response is not null, SR.GetResourceString(SR.ID4007));

                if (string.IsNullOrEmpty(context.Transaction.Response.Error))
                {
                    return default;
                }

                // Determine if the status code pages middleware has been enabled for this request.
                // If it was not registered or enabled, let the default OpenIddict server handlers render
                // a default error page instead of delegating the rendering to the status code middleware.
                var feature = response.HttpContext.Features.Get<IStatusCodePagesFeature>();
                if (feature is null || !feature.Enabled)
                {
                    return default;
                }

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
                    .SetOrder(ProcessStatusCodePagesErrorResponse<TContext>.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(TContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var response = context.Transaction.GetHttpRequest()?.HttpContext.Response;
                if (response is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));
                }

                Debug.Assert(context.Transaction.Response is not null, SR.GetResourceString(SR.ID4007));

                if (string.IsNullOrEmpty(context.Transaction.Response.Error))
                {
                    return;
                }

                // Don't return the state originally sent by the client application.
                context.Transaction.Response.State = null;

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6143), context.Transaction.Response);

                using var stream = new MemoryStream();
                using var writer = new StreamWriter(stream);

                foreach (var parameter in context.Transaction.Response.GetParameters())
                {
                    // Ignore null or empty parameters, including JSON
                    // objects that can't be represented as strings.
                    var value = (string?) parameter.Value;
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
                await stream.CopyToAsync(response.Body, 4096, response.HttpContext.RequestAborted);

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
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(TContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6145));
                context.HandleRequest();

                return default;
            }
        }
    }
}
