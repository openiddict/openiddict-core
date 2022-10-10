/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Owin;
using static OpenIddict.Validation.Owin.OpenIddictValidationOwinConstants;
using Properties = OpenIddict.Validation.Owin.OpenIddictValidationOwinConstants.Properties;

namespace OpenIddict.Validation.Owin;

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
        ResolveHostChallengeProperties.Descriptor,
        AttachHostChallengeError.Descriptor,

        /*
         * Response processing:
         */
        AttachHttpResponseCode<ProcessChallengeContext>.Descriptor,
        AttachOwinResponseChallenge<ProcessChallengeContext>.Descriptor,
        SuppressFormsAuthenticationRedirect<ProcessChallengeContext>.Descriptor,
        AttachCacheControlHeader<ProcessChallengeContext>.Descriptor,
        AttachWwwAuthenticateHeader<ProcessChallengeContext>.Descriptor,
        ProcessChallengeErrorResponse<ProcessChallengeContext>.Descriptor,

        AttachHttpResponseCode<ProcessErrorContext>.Descriptor,
        AttachOwinResponseChallenge<ProcessErrorContext>.Descriptor,
        SuppressFormsAuthenticationRedirect<ProcessErrorContext>.Descriptor,
        AttachCacheControlHeader<ProcessErrorContext>.Descriptor,
        AttachWwwAuthenticateHeader<ProcessErrorContext>.Descriptor,
        ProcessChallengeErrorResponse<ProcessErrorContext>.Descriptor);

    /// <summary>
    /// Contains the logic responsible for infering the default issuer from the HTTP request host and validating it.
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

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessRequestContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetOwinRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            // Only use the current host as the issuer if the
            // issuer was not explicitly set in the options.
            if (context.Issuer is not null)
            {
                return default;
            }

            if (string.IsNullOrEmpty(request.Host.Value))
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.FormatID2081(Headers.Host),
                    uri: SR.FormatID8000(SR.ID2081));

                return default;
            }

            if (!Uri.TryCreate(request.Scheme + Uri.SchemeDelimiter + request.Host + request.PathBase, UriKind.Absolute, out Uri? issuer) ||
                !issuer.IsWellFormedOriginalString())
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.FormatID2082(Headers.Host),
                    uri: SR.FormatID8000(SR.ID2082));

                return default;
            }

            context.Issuer = issuer;

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for extracting the access token from the standard HTTP Authorization header.
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
                .AddFilter<RequireAccessTokenExtracted>()
                .UseSingletonHandler<ExtractAccessTokenFromAuthorizationHeader>()
                .SetOrder(EvaluateValidatedTokens.Descriptor.Order + 500)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // If a token was already resolved, don't overwrite it.
            if (!string.IsNullOrEmpty(context.AccessToken))
            {
                return default;
            }

            // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetOwinRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            // Resolve the access token from the standard Authorization header.
            // See https://tools.ietf.org/html/rfc6750#section-2.1 for more information.
            string header = request.Headers[Headers.Authorization];
            if (!string.IsNullOrEmpty(header) && header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                context.AccessToken = header.Substring("Bearer ".Length);

                return default;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for extracting the access token from the standard access_token form parameter.
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
                .AddFilter<RequireAccessTokenExtracted>()
                .UseSingletonHandler<ExtractAccessTokenFromBodyForm>()
                .SetOrder(ExtractAccessTokenFromAuthorizationHeader.Descriptor.Order + 1_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // If a token was already resolved, don't overwrite it.
            if (!string.IsNullOrEmpty(context.AccessToken))
            {
                return;
            }

            // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetOwinRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

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
                context.AccessToken = token;

                return;
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for extracting the access token from the standard access_token query parameter.
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
                .AddFilter<RequireAccessTokenExtracted>()
                .UseSingletonHandler<ExtractAccessTokenFromQueryString>()
                .SetOrder(ExtractAccessTokenFromBodyForm.Descriptor.Order + 1_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // If a token was already resolved, don't overwrite it.
            if (!string.IsNullOrEmpty(context.AccessToken))
            {
                return default;
            }

            // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetOwinRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            // Resolve the access token from the standard access_token query parameter.
            // See https://tools.ietf.org/html/rfc6750#section-2.3 for more information.
            string token = request.Query[Parameters.AccessToken];
            if (!string.IsNullOrEmpty(token))
            {
                context.AccessToken = token;

                return default;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for resolving the context-specific properties and parameters stored in the
    /// OWIN authentication properties specified by the application that triggered the challenge operation.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public class ResolveHostChallengeProperties : IOpenIddictValidationHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
            = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<ResolveHostChallengeProperties>()
                .SetOrder(AttachHostChallengeError.Descriptor.Order - 500)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var properties = context.Transaction.GetProperty<AuthenticationProperties>(typeof(AuthenticationProperties).FullName!);
            if (properties is not { Dictionary.Count: > 0 })
            {
                return default;
            }

            // Note: unlike ASP.NET Core, OWIN's AuthenticationProperties doesn't offer a strongly-typed
            // dictionary that allows flowing parameters while preserving their original types. To allow
            // returning custom parameters, the OWIN host allows using AuthenticationProperties.Dictionary
            // but requires suffixing the properties that are meant to be used as parameters using a special
            // suffix that indicates that the property is public and determines its actual representation.
            foreach (var property in properties.Dictionary)
            {
                var (name, value) = property.Key switch
                {
                    // If the property ends with #string, represent it as a string parameter.
                    string key when key.EndsWith(PropertyTypes.String, StringComparison.OrdinalIgnoreCase) => (
                        Name: key.Substring(0, key.Length - PropertyTypes.String.Length),
                        Value: new OpenIddictParameter(property.Value)),

                    // If the property ends with #boolean, return it as a boolean parameter.
                    string key when key.EndsWith(PropertyTypes.Boolean, StringComparison.OrdinalIgnoreCase) => (
                        Name: key.Substring(0, key.Length - PropertyTypes.Boolean.Length),
                        Value: new OpenIddictParameter(bool.Parse(property.Value))),

                    // If the property ends with #integer, return it as an integer parameter.
                    string key when key.EndsWith(PropertyTypes.Integer, StringComparison.OrdinalIgnoreCase) => (
                        Name: key.Substring(0, key.Length - PropertyTypes.Integer.Length),
                        Value: new OpenIddictParameter(long.Parse(property.Value, CultureInfo.InvariantCulture))),

                    // If the property ends with #json, return it as a JSON parameter.
                    string key when key.EndsWith(PropertyTypes.Json, StringComparison.OrdinalIgnoreCase) => (
                        Name: key.Substring(0, key.Length - PropertyTypes.Json.Length),
                        Value: new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(property.Value))),

                    _ => default
                };

                if (!string.IsNullOrEmpty(name))
                {
                    context.Parameters[name] = value;
                }

                else
                {
                    context.Properties[property.Key] = property.Value;
                }
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the error details using the OWIN authentication properties.
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
                .SetOrder(AttachDefaultChallengeError.Descriptor.Order - 500)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var properties = context.Transaction.GetProperty<AuthenticationProperties>(typeof(AuthenticationProperties).FullName!);
            if (properties is not null)
            {
                context.Response.Error = GetProperty(properties, Properties.Error);
                context.Response.ErrorDescription = GetProperty(properties, Properties.ErrorDescription);
                context.Response.ErrorUri = GetProperty(properties, Properties.ErrorUri);
                context.Response.Scope = GetProperty(properties, Properties.Scope);
            }

            return default;

            static string? GetProperty(AuthenticationProperties properties, string name)
                => properties.Dictionary.TryGetValue(name, out string? value) ? value : null;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching an appropriate HTTP status code.
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
                .SetOrder(100_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Transaction.Response is not null, SR.GetResourceString(SR.ID4007));

            // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetOwinRequest()?.Context.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            response.StatusCode = context.Transaction.Response.Error switch
            {
                // Note: the default code may be replaced by another handler (e.g when doing redirects).
                null or { Length: 0 } => 200,

                Errors.InvalidToken or Errors.MissingToken => 401,

                Errors.InsufficientAccess or Errors.InsufficientScope => 403,

                Errors.ServerError => 500,

                _ => 400
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching an OWIN response chalenge to the context, if necessary.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public class AttachOwinResponseChallenge<TContext> : IOpenIddictValidationHandler<TContext> where TContext : BaseRequestContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
            = OpenIddictValidationHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<AttachOwinResponseChallenge<TContext>>()
                .SetOrder(AttachHttpResponseCode<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetOwinRequest()?.Context.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            // OWIN authentication middleware configured to use active authentication (which is the default mode)
            // are known to aggressively intercept 401 responses even if the request is already considered fully
            // handled. In practice, this behavior is often seen with the cookies authentication middleware,
            // that will rewrite the 401 responses returned by OpenIddict and try to redirect the user agent
            // to the login page configured in the options. To prevent this undesirable behavior, a fake
            // response challenge pointing to a non-existent middleware is manually added to the OWIN context
            // to prevent the active authentication middleware from rewriting OpenIddict's 401 HTTP responses.
            //
            // Note: while 403 responses are generally not intercepted by the built-in OWIN authentication
            // middleware, they are treated the same way as 401 responses to account for custom middleware
            // that may potentially use the same interception logic for both 401 and 403 HTTP responses.
            if (response.StatusCode is 401 or 403 &&
                response.Context.Authentication.AuthenticationResponseChallenge is null)
            {
                response.Context.Authentication.AuthenticationResponseChallenge =
                    new AuthenticationResponseChallenge(new[] { Guid.NewGuid().ToString() }, null);
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for suppressing the redirection applied by FormsAuthenticationModule, if necessary.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public class SuppressFormsAuthenticationRedirect<TContext> : IOpenIddictValidationHandler<TContext> where TContext : BaseRequestContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
            = OpenIddictValidationHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<SuppressFormsAuthenticationRedirect<TContext>>()
                .SetOrder(AttachOwinResponseChallenge<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetOwinRequest()?.Context.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            // Similarly to the automatic authentication mode used by OWIN authentication middleware,
            // the ASP.NET FormsAuthentication module aggressively intercepts 401 responses even if
            // the request has already been fully handled by another component (like OpenIddict).
            // To prevent that, this handler is responsible for suppressing the redirection enforced
            // by FormsAuthenticationModule when the status code was set to 401 (the only status code
            // used by the FormsAuthenticationModule) and the OWIN application is hosted on SystemWeb.
            if (response.StatusCode is 401)
            {
                TrySuppressFormsAuthenticationRedirect(response.Environment);
            }

            return default;

            static void TrySuppressFormsAuthenticationRedirect(IDictionary<string, object> environment)
            {
                // Note: the OWIN host cannot depend on the OWIN SystemWeb package but a direct access
                // to the underlying ASP.NET 4.x context is required to be able to disable the redirection
                // enforced by the FormsAuthentication module. To work around that, the HttpContextBase
                // instance is resolved from the OWIN environment and SuppressFormsAuthenticationRedirect
                // is set to true using a dynamic runtime resolution (that uses reflection under the hood).
                if (environment.TryGetValue("System.Web.HttpContextBase", out dynamic context))
                {
                    try
                    {
                        // Note: the SuppressFormsAuthenticationRedirect property was introduced in ASP.NET 4.5
                        // and thus should always be present, as OpenIddict requires targeting ASP.NET >= 4.6.1.
                        context.Response.SuppressFormsAuthenticationRedirect = true;
                    }

                    catch
                    {
                    }
                }
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the appropriate HTTP response cache headers.
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
                .SetOrder(SuppressFormsAuthenticationRedirect<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetOwinRequest()?.Context.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            // Prevent the response from being cached.
            response.Headers[Headers.CacheControl] = "no-store";
            response.Headers[Headers.Pragma] = "no-cache";
            response.Headers[Headers.Expires] = "Thu, 01 Jan 1970 00:00:00 GMT";

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching errors details to the WWW-Authenticate header.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
    /// </summary>
    public class AttachWwwAuthenticateHeader<TContext> : IOpenIddictValidationHandler<TContext> where TContext : BaseRequestContext
    {
        private readonly IOptionsMonitor<OpenIddictValidationOwinOptions> _options;

        public AttachWwwAuthenticateHeader(IOptionsMonitor<OpenIddictValidationOwinOptions> options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
            = OpenIddictValidationHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireOwinRequest>()
                .UseSingletonHandler<AttachWwwAuthenticateHeader<TContext>>()
                .SetOrder(AttachCacheControlHeader<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Transaction.Response is not null, SR.GetResourceString(SR.ID4007));

            // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetOwinRequest()?.Context.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            if (string.IsNullOrEmpty(context.Transaction.Response.Error))
            {
                return default;
            }

            // Note: unlike the server stack, the validation stack doesn't expose any endpoint
            // and thus never returns responses containing a formatted body (e.g a JSON response).
            //
            // As such, all errors - even errors indicating an invalid request - are returned
            // as part of the standard WWW-Authenticate header, as defined by the specification.
            // See https://datatracker.ietf.org/doc/html/rfc6750#section-3 for more information.

            var parameters = new Dictionary<string, string>(StringComparer.Ordinal);

            // If a realm was configured in the options, attach it to the parameters.
            if (_options.CurrentValue.Realm is string { Length: > 0 } realm)
            {
                parameters[Parameters.Realm] = realm;
            }

            foreach (var parameter in context.Transaction.Response.GetParameters())
            {
                // Note: the error details are only included if the error was not caused by a missing token, as recommended
                // by the OAuth 2.0 bearer specification: https://tools.ietf.org/html/rfc6750#section-3.1.
                if (context.Transaction.Response.Error is Errors.MissingToken &&
                    parameter.Key is Parameters.Error            or
                                     Parameters.ErrorDescription or
                                     Parameters.ErrorUri)
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

            var builder = new StringBuilder(Schemes.Bearer);

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

            response.Headers.Append(Headers.WwwAuthenticate, builder.ToString());

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for processing challenge responses that contain a WWW-Authenticate header.
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
                .SetOrder(AttachWwwAuthenticateHeader<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictValidationHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetOwinRequest()?.Context.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

            // If the response doesn't contain a WWW-Authenticate header, don't return an empty response.
            if (!response.Headers.ContainsKey(Headers.WwwAuthenticate))
            {
                return default;
            }

            context.Logger.LogInformation(SR.GetResourceString(SR.ID6141), context.Transaction.Response);
            context.HandleRequest();

            return default;
        }
    }
}
