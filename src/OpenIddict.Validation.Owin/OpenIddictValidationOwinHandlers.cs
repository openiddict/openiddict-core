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
using Microsoft.Owin.Security;
using Owin;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Validation.OpenIddictValidationEvents;
using static OpenIddict.Validation.Owin.OpenIddictValidationOwinHandlerFilters;
using Properties = OpenIddict.Validation.Owin.OpenIddictValidationOwinConstants.Properties;

namespace OpenIddict.Validation.Owin
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static partial class OpenIddictValidationOwinHandlers
    {
        public static ImmutableArray<OpenIddictValidationHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Request top-level processing:
             */
            InferIssuerFromHost.Descriptor,

            /*
             * Authentication processing:
             */
            ExtractAccessTokenFromAuthorizationHeader.Descriptor,
            ExtractAccessTokenFromBodyForm.Descriptor,
            ExtractAccessTokenFromQueryString.Descriptor,

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
            ProcessChallengeErrorResponse<ProcessChallengeContext>.Descriptor,
            ProcessJsonResponse<ProcessChallengeContext>.Descriptor,

            AttachHttpResponseCode<ProcessErrorContext>.Descriptor,
            AttachCacheControlHeader<ProcessErrorContext>.Descriptor,
            AttachWwwAuthenticateHeader<ProcessErrorContext>.Descriptor,
            ProcessChallengeErrorResponse<ProcessErrorContext>.Descriptor,
            ProcessJsonResponse<ProcessErrorContext>.Descriptor);

        /// <summary>
        /// Contains the logic responsible of infering the default issuer from the HTTP request host and validating it.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
        /// </summary>
        public class InferIssuerFromHost : IOpenIddictValidationHandler<ProcessRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<InferIssuerFromHost>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
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

                // Only use the current host as the issuer if the
                // issuer was not explicitly set in the options.
                if (context.Issuer != null)
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
        /// Contains the logic responsible of extracting the access token from the standard HTTP Authorization header.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
        /// </summary>
        public class ExtractAccessTokenFromAuthorizationHeader : IOpenIddictValidationHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<ExtractAccessTokenFromAuthorizationHeader>()
                    .SetOrder(int.MinValue + 50_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessAuthenticationContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If a token was already resolved, don't overwrite it.
                if (!string.IsNullOrEmpty(context.Token))
                {
                    return default;
                }

                // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var request = context.Transaction.GetOwinRequest();
                if (request == null)
                {
                    throw new InvalidOperationException("The OWIN request cannot be resolved.");
                }

                // Resolve the access token from the standard Authorization header.
                // See https://tools.ietf.org/html/rfc6750#section-2.1 for more information.
                string header = request.Headers["Authorization"];
                if (!string.IsNullOrEmpty(header) && header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                {
                    context.Token = header.Substring("Bearer ".Length);
                    context.TokenType = TokenTypeHints.AccessToken;

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of extracting the access token from the standard access_token form parameter.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
        /// </summary>
        public class ExtractAccessTokenFromBodyForm : IOpenIddictValidationHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<ExtractAccessTokenFromBodyForm>()
                    .SetOrder(ExtractAccessTokenFromAuthorizationHeader.Descriptor.Order + 1_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async ValueTask HandleAsync([NotNull] ProcessAuthenticationContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If a token was already resolved, don't overwrite it.
                if (!string.IsNullOrEmpty(context.Token))
                {
                    return;
                }

                // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var request = context.Transaction.GetOwinRequest();
                if (request == null)
                {
                    throw new InvalidOperationException("The OWIN request cannot be resolved.");
                }

                if (string.IsNullOrEmpty(request.ContentType) ||
                    !request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }

                // Resolve the access token from the standard access_token form parameter.
                // See https://tools.ietf.org/html/rfc6750#section-2.2 for more information.
                var form = await request.ReadFormAsync();
                string token = form[Parameters.AccessToken];
                if (!string.IsNullOrEmpty(token))
                {
                    context.Token = token;
                    context.TokenType = TokenTypeHints.AccessToken;

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of extracting the access token from the standard access_token query parameter.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
        /// </summary>
        public class ExtractAccessTokenFromQueryString : IOpenIddictValidationHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<ExtractAccessTokenFromQueryString>()
                    .SetOrder(ExtractAccessTokenFromBodyForm.Descriptor.Order + 1_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessAuthenticationContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If a token was already resolved, don't overwrite it.
                if (!string.IsNullOrEmpty(context.Token))
                {
                    return default;
                }

                // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var request = context.Transaction.GetOwinRequest();
                if (request == null)
                {
                    throw new InvalidOperationException("The OWIN request cannot be resolved.");
                }

                // Resolve the access token from the standard access_token query parameter.
                // See https://tools.ietf.org/html/rfc6750#section-2.3 for more information.
                string token = request.Query[Parameters.AccessToken];
                if (!string.IsNullOrEmpty(token))
                {
                    context.Token = token;
                    context.TokenType = TokenTypeHints.AccessToken;

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of attaching the error details using the OWIN authentication properties.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
        /// </summary>
        public class AttachHostChallengeError : IOpenIddictValidationHandler<ProcessChallengeContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<AttachHostChallengeError>()
                    .SetOrder(int.MinValue + 50_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
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
        /// Contains the logic responsible of attaching an appropriate HTTP status code.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
        /// </summary>
        public class AttachHttpResponseCode<TContext> : IOpenIddictValidationHandler<TContext> where TContext : BaseRequestContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<AttachHttpResponseCode<TContext>>()
                    .SetOrder(AttachCacheControlHeader<TContext>.Descriptor.Order - 1_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
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
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
        /// </summary>
        public class AttachCacheControlHeader<TContext> : IOpenIddictValidationHandler<TContext> where TContext : BaseRequestContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<AttachCacheControlHeader<TContext>>()
                    .SetOrder(AttachWwwAuthenticateHeader<TContext>.Descriptor.Order - 1_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
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
        public class AttachWwwAuthenticateHeader<TContext> : IOpenIddictValidationHandler<TContext> where TContext : BaseRequestContext
        {
            private readonly IOptionsMonitor<OpenIddictValidationOwinOptions> _options;

            public AttachWwwAuthenticateHeader([NotNull] IOptionsMonitor<OpenIddictValidationOwinOptions> options)
                => _options = options;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<AttachWwwAuthenticateHeader<TContext>>()
                    .SetOrder(ProcessChallengeErrorResponse<TContext>.Descriptor.Order - 1_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
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
        public class ProcessChallengeErrorResponse<TContext> : IOpenIddictValidationHandler<TContext> where TContext : BaseRequestContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<ProcessChallengeErrorResponse<TContext>>()
                    .SetOrder(ProcessJsonResponse<TContext>.Descriptor.Order - 1_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
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
        public class ProcessJsonResponse<TContext> : IOpenIddictValidationHandler<TContext> where TContext : BaseRequestContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<ProcessJsonResponse<TContext>>()
                    .SetOrder(int.MaxValue - 100_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
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
    }
}
