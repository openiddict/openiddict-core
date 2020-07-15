/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.Globalization;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.IdentityModel.JsonWebTokens;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Validation.OpenIddictValidationEvents;

namespace OpenIddict.Validation
{
    public static partial class OpenIddictValidationHandlers
    {
        public static class Introspection
        {
            public static ImmutableArray<OpenIddictValidationHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
                /*
                 * Introspection response handling:
                 */
                AttachCredentials.Descriptor,
                AttachToken.Descriptor,

                /*
                 * Introspection response handling:
                 */
                HandleErrorResponse<HandleIntrospectionResponseContext>.Descriptor,
                HandleInactiveResponse.Descriptor,
                ValidateWellKnownClaims.Descriptor,
                ValidateIssuer.Descriptor,
                ValidateTokenType.Descriptor,
                PopulateClaims.Descriptor);

            /// <summary>
            /// Contains the logic responsible of attaching the client credentials to the introspection request.
            /// </summary>
            public class AttachCredentials : IOpenIddictValidationHandler<PrepareIntrospectionRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                    = OpenIddictValidationHandlerDescriptor.CreateBuilder<PrepareIntrospectionRequestContext>()
                        .UseSingletonHandler<AttachCredentials>()
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
                public ValueTask HandleAsync([NotNull] PrepareIntrospectionRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    context.Request.ClientId = context.Options.ClientId;
                    context.Request.ClientSecret = context.Options.ClientSecret;

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of attaching the token to the introspection request.
            /// </summary>
            public class AttachToken : IOpenIddictValidationHandler<PrepareIntrospectionRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                    = OpenIddictValidationHandlerDescriptor.CreateBuilder<PrepareIntrospectionRequestContext>()
                        .UseSingletonHandler<AttachToken>()
                        .SetOrder(AttachCredentials.Descriptor.Order + 100_000)
                        .SetType(OpenIddictValidationHandlerType.BuiltIn)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] PrepareIntrospectionRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    context.Request.Token = context.Token;
                    context.Request.TokenTypeHint = context.TokenType;

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of extracting the active: false marker from the response.
            /// </summary>
            public class HandleInactiveResponse : IOpenIddictValidationHandler<HandleIntrospectionResponseContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                    = OpenIddictValidationHandlerDescriptor.CreateBuilder<HandleIntrospectionResponseContext>()
                        .UseSingletonHandler<HandleInactiveResponse>()
                        .SetOrder(HandleErrorResponse<HandleIntrospectionResponseContext>.Descriptor.Order + 1_000)
                        .SetType(OpenIddictValidationHandlerType.BuiltIn)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] HandleIntrospectionResponseContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // Note: the introspection specification requires that server return "active: false" instead of a proper
                    // OAuth 2.0 error when the token is invalid, expired, revoked or invalid for any other reason.
                    // While OpenIddict's server can be tweaked to return a proper error (by removing NormalizeErrorResponse)
                    // from the enabled handlers, supporting "active: false" is required to ensure total compatibility.

                    if (!context.Response.TryGetParameter(Parameters.Active, out var parameter))
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: "The mandatory 'active' parameter couldn't be found in the introspection response.");

                        return default;
                    }

                    // Note: if the parameter cannot be converted to a boolean instance, the default value
                    // (false) is returned by the static operator, which is appropriate for this check.
                    if (!(bool) parameter)
                    {
                        context.Reject(
                            error: Errors.InvalidToken,
                            description: "The token was rejected by the remote authorization server.");

                        return default;
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of validating the well-known claims contained in the introspection response.
            /// </summary>
            public class ValidateWellKnownClaims : IOpenIddictValidationHandler<HandleIntrospectionResponseContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                    = OpenIddictValidationHandlerDescriptor.CreateBuilder<HandleIntrospectionResponseContext>()
                        .UseSingletonHandler<ValidateWellKnownClaims>()
                        .SetOrder(HandleInactiveResponse.Descriptor.Order + 1_000)
                        .SetType(OpenIddictValidationHandlerType.BuiltIn)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] HandleIntrospectionResponseContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    foreach (var parameter in context.Response.GetParameters())
                    {
                        if (ValidateClaimType(parameter.Key, parameter.Value))
                        {
                            continue;
                        }

                        context.Reject(
                            error: Errors.ServerError,
                            description: $"The {parameter.Key} claim is malformed or isn't of the expected type.");

                        return default;
                    }

                    return default;

                    static bool ValidateClaimType(string name, OpenIddictParameter value)
                    {
                        switch ((name, value.Value))
                        {
                            // The 'aud' claim CAN be represented either as a unique string or as an array of multiple strings.
                            case (Claims.Audience, string _):
                            case (Claims.Audience, string[] _):
                            case (Claims.Audience, JsonElement element) when element.ValueKind == JsonValueKind.String ||
                                (element.ValueKind == JsonValueKind.Array && ValidateArrayChildren(element, JsonValueKind.String)):
                                return true;

                            // The 'exp', 'iat' and 'nbf' claims MUST be formatted as numeric date values.
                            case (Claims.ExpiresAt, long _):
                            case (Claims.ExpiresAt, JsonElement element) when element.ValueKind == JsonValueKind.Number:
                                return true;

                            case (Claims.IssuedAt, long _):
                            case (Claims.IssuedAt, JsonElement element) when element.ValueKind == JsonValueKind.Number:
                                return true;

                            case (Claims.NotBefore, long _):
                            case (Claims.NotBefore, JsonElement element) when element.ValueKind == JsonValueKind.Number:
                                return true;

                            // The 'jti' claim MUST be formatted as a unique string.
                            case (Claims.JwtId, string _):
                            case (Claims.JwtId, JsonElement element) when element.ValueKind == JsonValueKind.String:
                                return true;

                            // The 'iss' claim MUST be formatted as a unique string.
                            case (Claims.Issuer, string _):
                            case (Claims.Issuer, JsonElement element) when element.ValueKind == JsonValueKind.String:
                                return true;

                            // The 'scope' claim MUST be formatted as a unique string.
                            case (Claims.Scope, string _):
                            case (Claims.Scope, JsonElement element) when element.ValueKind == JsonValueKind.String:
                                return true;

                            // The 'token_usage' claim MUST be formatted as a unique string.
                            case (Claims.TokenUsage, string _):
                            case (Claims.TokenUsage, JsonElement element) when element.ValueKind == JsonValueKind.String:
                                return true;

                            // If the previously listed claims are represented differently,
                            // return false to indicate the claims validation logic failed.
                            case (Claims.Audience, _):
                            case (Claims.ExpiresAt, _):
                            case (Claims.IssuedAt, _):
                            case (Claims.Issuer, _):
                            case (Claims.NotBefore, _):
                            case (Claims.JwtId, _):
                            case (Claims.Scope, _):
                            case (Claims.TokenUsage, _):
                                return false;

                            // Claims that are not in the well-known list can be of any type.
                            default: return true;
                        }
                    }

                    static bool ValidateArrayChildren(JsonElement element, JsonValueKind kind)
                    {
                        foreach (var child in element.EnumerateArray())
                        {
                            if (child.ValueKind != kind)
                            {
                                return false;
                            }
                        }

                        return true;
                    }
                }
            }

            /// <summary>
            /// Contains the logic responsible of extracting the issuer from the introspection response.
            /// </summary>
            public class ValidateIssuer : IOpenIddictValidationHandler<HandleIntrospectionResponseContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                    = OpenIddictValidationHandlerDescriptor.CreateBuilder<HandleIntrospectionResponseContext>()
                        .UseSingletonHandler<ValidateIssuer>()
                        .SetOrder(ValidateWellKnownClaims.Descriptor.Order + 1_000)
                        .SetType(OpenIddictValidationHandlerType.BuiltIn)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] HandleIntrospectionResponseContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // The issuer claim is optional. If it's not null or empty, validate it to
                    // ensure it matches the issuer registered in the server configuration.
                    var issuer = (string) context.Response[Claims.Issuer];
                    if (!string.IsNullOrEmpty(issuer))
                    {
                        if (!Uri.TryCreate(issuer, UriKind.Absolute, out Uri uri))
                        {
                            context.Reject(
                                error: Errors.ServerError,
                                description: "An introspection response containing an invalid issuer was returned.");

                            return default;
                        }

                        if (context.Issuer != null && context.Issuer != uri)
                        {
                            context.Reject(
                                error: Errors.ServerError,
                                description: "The issuer returned in the introspection response is not valid.");

                            return default;
                        }
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of extracting and validating the token type from the introspection response.
            /// </summary>
            public class ValidateTokenType : IOpenIddictValidationHandler<HandleIntrospectionResponseContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                    = OpenIddictValidationHandlerDescriptor.CreateBuilder<HandleIntrospectionResponseContext>()
                        .UseSingletonHandler<ValidateTokenType>()
                        .SetOrder(ValidateIssuer.Descriptor.Order + 1_000)
                        .SetType(OpenIddictValidationHandlerType.BuiltIn)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] HandleIntrospectionResponseContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // OpenIddict-based authorization servers always return the actual token type using
                    // the special "token_usage" claim, that helps resource servers determine whether the
                    // introspected token is of the expected type and prevent token substitution attacks.
                    if (!string.IsNullOrEmpty(context.TokenType))
                    {
                        var usage = (string) context.Response[Claims.TokenUsage];
                        if (!string.IsNullOrEmpty(usage) &&
                            !string.Equals(usage, context.TokenType, StringComparison.OrdinalIgnoreCase))
                        {
                            context.Reject(
                                error: Errors.InvalidToken,
                                description: "The type of the introspection token doesn't match the expected type.");

                            return default;
                        }
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of extracting the claims from the introspection response.
            /// </summary>
            public class PopulateClaims : IOpenIddictValidationHandler<HandleIntrospectionResponseContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                    = OpenIddictValidationHandlerDescriptor.CreateBuilder<HandleIntrospectionResponseContext>()
                        .UseSingletonHandler<PopulateClaims>()
                        .SetOrder(ValidateTokenType.Descriptor.Order + 1_000)
                        .SetType(OpenIddictValidationHandlerType.BuiltIn)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] HandleIntrospectionResponseContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // Create a new claims-based identity using the same authentication type
                    // and the name/role claims as the one used by IdentityModel for JWT tokens.
                    var identity = new ClaimsIdentity(
                        context.Options.TokenValidationParameters.AuthenticationType,
                        context.Options.TokenValidationParameters.NameClaimType,
                        context.Options.TokenValidationParameters.RoleClaimType);

                    // Resolve the issuer that will be attached to the claims created by this handler.
                    // Note: at this stage, the optional issuer extracted from the response is assumed
                    // to be valid, as it is guarded against unknown values by the ValidateIssuer handler.
                    var issuer = (string) context.Response[Claims.Issuer] ?? context.Issuer?.AbsoluteUri ?? ClaimsIdentity.DefaultIssuer;

                    foreach (var parameter in context.Response.GetParameters())
                    {
                        // Always exclude null keys and values, as they can't be represented as valid claims.
                        if (string.IsNullOrEmpty(parameter.Key) || OpenIddictParameter.IsNullOrEmpty(parameter.Value))
                        {
                            continue;
                        }

                        // Exclude OpenIddict-specific private claims, that MUST NOT be set based on data returned
                        // by the remote authorization server (that may or may not be an OpenIddict server).
                        if (parameter.Key.StartsWith(Claims.Prefixes.Private, StringComparison.OrdinalIgnoreCase))
                        {
                            continue;
                        }

                        switch ((name: parameter.Key, value: parameter.Value.Value))
                        {
                            // Ignore all protocol claims that are not mapped to CLR claims.
                            case (Claims.Active, _):
                            case (Claims.Issuer, _):
                            case (Claims.NotBefore, _):
                            case (Claims.TokenType, _):
                            case (Claims.TokenUsage, _):
                                continue;

                            // Claims represented as arrays are split and mapped to multiple CLR claims.
                            case (var name, JsonElement value) when value.ValueKind == JsonValueKind.Array:
                                foreach (var element in value.EnumerateArray())
                                {
                                    identity.AddClaim(new Claim(name, element.ToString(),
                                        GetClaimValueType(value.ValueKind), issuer, issuer, identity));
                                }
                                break;

                            case (var name, JsonElement value):
                                identity.AddClaim(new Claim(name, value.ToString(),
                                    GetClaimValueType(value.ValueKind), issuer, issuer, identity));
                                break;

                            // Note: in the typical case, the introspection parameters should be deserialized from
                            // a JSON response and thus represented as System.Text.Json.JsonElement instances.
                            // However, to support responses resolved from custom locations and parameters manually added
                            // by the application using the events model, the CLR primitive types are also supported.

                            case (var name, bool value):
                                identity.AddClaim(new Claim(name, value.ToString(), ClaimValueTypes.Boolean, issuer, issuer, identity));
                                break;

                            case (var name, long value):
                                identity.AddClaim(new Claim(name, value.ToString(CultureInfo.InvariantCulture),
                                    ClaimValueTypes.Integer64, issuer, issuer, identity));
                                break;

                            case (var name, string value):
                                identity.AddClaim(new Claim(name, value, ClaimValueTypes.String, issuer, issuer, identity));
                                break;

                            // Claims represented as arrays are split and mapped to multiple CLR claims.
                            case (var name, string[] value):
                                for (var index = 0; index < value.Length; index++)
                                {
                                    identity.AddClaim(new Claim(name, value[index], ClaimValueTypes.String, issuer, issuer, identity));
                                }
                                break;
                        }
                    }

                    context.Principal = new ClaimsPrincipal(identity);

                    return default;

                    static string GetClaimValueType(JsonValueKind kind) => kind switch
                    {
                        JsonValueKind.True   => ClaimValueTypes.Boolean,
                        JsonValueKind.False  => ClaimValueTypes.Boolean,
                        JsonValueKind.String => ClaimValueTypes.String,
                        JsonValueKind.Number => ClaimValueTypes.Integer64,

                        JsonValueKind.Array  => JsonClaimValueTypes.JsonArray,
                        JsonValueKind.Object => JsonClaimValueTypes.Json,

                        _ => JsonClaimValueTypes.Json
                    };
                }
            }
        }
    }
}
