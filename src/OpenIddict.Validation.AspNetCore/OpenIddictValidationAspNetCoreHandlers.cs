/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
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
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Validation.AspNetCore.OpenIddictValidationAspNetCoreHandlerFilters;
using static OpenIddict.Validation.OpenIddictValidationEvents;
using Properties = OpenIddict.Validation.AspNetCore.OpenIddictValidationAspNetCoreConstants.Properties;

namespace OpenIddict.Validation.AspNetCore
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static partial class OpenIddictValidationAspNetCoreHandlers
    {
        public static ImmutableArray<OpenIddictValidationHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Request top-level processing:
             */
            InferIssuerFromHost.Descriptor,
            ExtractGetOrPostRequest.Descriptor,
            ExtractAccessToken.Descriptor,

            /*
             * Challenge processing:
             */
            AttachHostChallengeError.Descriptor,

            /*
             * Response processing:
             */
            AttachHttpResponseCode<ProcessChallengeContext>.Descriptor,
            AttachCacheControlHeader<ProcessChallengeContext>.Descriptor,
            AttachWwwAuthenticateHeader<ProcessChallengeContext>.Descriptor,
            ProcessJsonResponse<ProcessChallengeContext>.Descriptor,

            AttachHttpResponseCode<ProcessErrorContext>.Descriptor,
            AttachCacheControlHeader<ProcessErrorContext>.Descriptor,
            AttachWwwAuthenticateHeader<ProcessErrorContext>.Descriptor,
            ProcessJsonResponse<ProcessErrorContext>.Descriptor);

        /// <summary>
        /// Contains the logic responsible of infering the default issuer from the HTTP request host and validating it.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public class InferIssuerFromHost : IOpenIddictValidationHandler<ProcessRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<InferIssuerFromHost>()
                    .SetOrder(int.MinValue + 100_000)
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

                // Only use the current host as the issuer if the
                // issuer was not explicitly set in the options.
                if (context.Issuer != null)
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
        /// Contains the logic responsible of extracting OpenID Connect requests from GET or POST HTTP requests.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public class ExtractGetOrPostRequest : IOpenIddictValidationHandler<ProcessRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<ExtractGetOrPostRequest>()
                    .SetOrder(InferIssuerFromHost.Descriptor.Order + 1_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async ValueTask HandleAsync([NotNull] ProcessRequestContext context)
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

                else if (HttpMethods.IsPost(request.Method) && !string.IsNullOrEmpty(request.ContentType) &&
                    request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
                {
                    context.Request = new OpenIddictRequest(await request.ReadFormAsync(request.HttpContext.RequestAborted));
                }

                else
                {
                    context.Request = new OpenIddictRequest();
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of extracting an access token from the standard HTTP Authorization header.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public class ExtractAccessToken : IOpenIddictValidationHandler<ProcessRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<ExtractAccessToken>()
                    .SetOrder(ExtractGetOrPostRequest.Descriptor.Order + 1_000)
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
        /// Contains the logic responsible of attaching the error details using the ASP.NET Core authentication properties.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public class AttachHostChallengeError : IOpenIddictValidationHandler<ProcessChallengeContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<AttachHostChallengeError>()
                    .SetOrder(int.MinValue + 50_000)
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
                    context.Response.Error = properties.GetString(Properties.Error);
                    context.Response.ErrorDescription = properties.GetString(Properties.ErrorDescription);
                    context.Response.ErrorUri = properties.GetString(Properties.ErrorUri);
                    context.Response.Realm = properties.GetString(Properties.Realm);
                    context.Response.Scope = properties.GetString(Properties.Scope);
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of attaching an appropriate HTTP status code.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public class AttachHttpResponseCode<TContext> : IOpenIddictValidationHandler<TContext> where TContext : BaseRequestContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<AttachHttpResponseCode<TContext>>()
                    .SetOrder(AttachCacheControlHeader<TContext>.Descriptor.Order - 1_000)
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

                response.StatusCode = context.Response.Error switch
                {
                    null => 200,

                    Errors.InvalidToken => 401,
                    Errors.MissingToken => 401,

                    Errors.InsufficientAccess => 403,
                    Errors.InsufficientScope  => 403,

                    _ => 400
                };

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of attaching the appropriate HTTP response cache headers.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public class AttachCacheControlHeader<TContext> : IOpenIddictValidationHandler<TContext> where TContext : BaseRequestContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<AttachCacheControlHeader<TContext>>()
                    .SetOrder(AttachWwwAuthenticateHeader<TContext>.Descriptor.Order - 1_000)
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
        public class AttachWwwAuthenticateHeader<TContext> : IOpenIddictValidationHandler<TContext> where TContext : BaseRequestContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<AttachWwwAuthenticateHeader<TContext>>()
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

                var scheme = context.Response.Error switch
                {
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

                // Optimization: avoid allocating a StringBuilder if the
                // WWW-Authenticate header doesn't contain any parameter.
                if (string.IsNullOrEmpty(context.Response.Realm) &&
                    string.IsNullOrEmpty(context.Response.Error) &&
                    string.IsNullOrEmpty(context.Response.ErrorDescription) &&
                    string.IsNullOrEmpty(context.Response.ErrorUri) &&
                    string.IsNullOrEmpty(context.Response.Scope))
                {
                    response.Headers.Append(HeaderNames.WWWAuthenticate, scheme);

                    return default;
                }

                var builder = new StringBuilder(scheme);

                // Append the realm if one was specified.
                if (!string.IsNullOrEmpty(context.Response.Realm))
                {
                    builder.Append(' ');
                    builder.Append(Parameters.Realm);
                    builder.Append("=\"");
                    builder.Append(context.Response.Realm.Replace("\"", "\\\""));
                    builder.Append('"');
                }

                // Append the error if one was specified.
                if (!string.IsNullOrEmpty(context.Response.Error))
                {
                    if (!string.IsNullOrEmpty(context.Response.Realm))
                    {
                        builder.Append(',');
                    }

                    builder.Append(' ');
                    builder.Append(Parameters.Error);
                    builder.Append("=\"");
                    builder.Append(context.Response.Error.Replace("\"", "\\\""));
                    builder.Append('"');
                }

                // Append the error_description if one was specified.
                if (!string.IsNullOrEmpty(context.Response.ErrorDescription))
                {
                    if (!string.IsNullOrEmpty(context.Response.Realm) ||
                        !string.IsNullOrEmpty(context.Response.Error))
                    {
                        builder.Append(',');
                    }

                    builder.Append(' ');
                    builder.Append(Parameters.ErrorDescription);
                    builder.Append("=\"");
                    builder.Append(context.Response.ErrorDescription.Replace("\"", "\\\""));
                    builder.Append('"');
                }

                // Append the error_uri if one was specified.
                if (!string.IsNullOrEmpty(context.Response.ErrorUri))
                {
                    if (!string.IsNullOrEmpty(context.Response.Realm) ||
                        !string.IsNullOrEmpty(context.Response.Error) ||
                        !string.IsNullOrEmpty(context.Response.ErrorDescription))
                    {
                        builder.Append(',');
                    }

                    builder.Append(' ');
                    builder.Append(Parameters.ErrorUri);
                    builder.Append("=\"");
                    builder.Append(context.Response.ErrorUri.Replace("\"", "\\\""));
                    builder.Append('"');
                }

                // Append the scope if one was specified.
                if (!string.IsNullOrEmpty(context.Response.Scope))
                {
                    if (!string.IsNullOrEmpty(context.Response.Realm) ||
                        !string.IsNullOrEmpty(context.Response.Error) ||
                        !string.IsNullOrEmpty(context.Response.ErrorDescription) ||
                        !string.IsNullOrEmpty(context.Response.ErrorUri))
                    {
                        builder.Append(',');
                    }

                    builder.Append(' ');
                    builder.Append(Parameters.Scope);
                    builder.Append("=\"");
                    builder.Append(context.Response.Scope.Replace("\"", "\\\""));
                    builder.Append('"');
                }

                response.Headers.Append(HeaderNames.WWWAuthenticate, builder.ToString());

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of processing OpenID Connect responses that must be returned as JSON.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public class ProcessJsonResponse<TContext> : IOpenIddictValidationHandler<TContext> where TContext : BaseRequestContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<ProcessJsonResponse<TContext>>()
                    .SetOrder(int.MaxValue - 100_000)
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
                var response = context.Transaction.GetHttpRequest()?.HttpContext.Response;
                if (response == null)
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

                response.ContentLength = stream.Length;
                response.ContentType = "application/json;charset=UTF-8";

                stream.Seek(offset: 0, loc: SeekOrigin.Begin);
                await stream.CopyToAsync(response.Body, 4096, response.HttpContext.RequestAborted);

                context.HandleRequest();
            }
        }
    }
}
