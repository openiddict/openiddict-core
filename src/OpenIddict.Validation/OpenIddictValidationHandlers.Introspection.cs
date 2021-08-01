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
using Microsoft.IdentityModel.JsonWebTokens;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Validation.OpenIddictValidationEvents;
using SR = OpenIddict.Abstractions.OpenIddictResources;

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
                ValidateTokenUsage.Descriptor,
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

                /// <inheritdoc/>
                public ValueTask HandleAsync(PrepareIntrospectionRequestContext context)
                {
                    if (context is null)
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

                /// <inheritdoc/>
                public ValueTask HandleAsync(PrepareIntrospectionRequestContext context)
                {
                    if (context is null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    context.Request.Token = context.Token;
                    context.Request.TokenTypeHint = context.TokenTypeHint;

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

                /// <inheritdoc/>
                public ValueTask HandleAsync(HandleIntrospectionResponseContext context)
                {
                    if (context is null)
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
                            description: SR.FormatID2105(Parameters.Active),
                            uri: SR.FormatID8000(SR.ID2105));

                        return default;
                    }

                    // Note: if the parameter cannot be converted to a boolean instance, the default value
                    // (false) is returned by the static operator, which is appropriate for this check.
                    if (!(bool) parameter)
                    {
                        context.Reject(
                            error: Errors.InvalidToken,
                            description: SR.GetResourceString(SR.ID2106),
                            uri: SR.FormatID8000(SR.ID2106));

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

                /// <inheritdoc/>
                public ValueTask HandleAsync(HandleIntrospectionResponseContext context)
                {
                    if (context is null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    foreach (var parameter in context.Response.GetParameters())
                    {
                        if (ValidateClaimType(parameter.Key, parameter.Value.Value))
                        {
                            continue;
                        }

                        context.Reject(
                            error: Errors.ServerError,
                            description: SR.FormatID2107(parameter.Key),
                            uri: SR.FormatID8000(SR.ID2107));

                        return default;
                    }

                    return default;

                    static bool ValidateClaimType(string name, object? value) => name switch
                    {
                        // The 'aud' claim MUST be represented either as a unique string or as an array of multiple strings.
                        Claims.Audience when value is string or string[] => true,
                        Claims.Audience when value is JsonElement { ValueKind: JsonValueKind.String } => true,
                        Claims.Audience when value is JsonElement { ValueKind: JsonValueKind.Array } element &&
                            ValidateArrayChildren(element, JsonValueKind.String) => true,
                        Claims.Audience => false,

                        // The 'exp', 'iat' and 'nbf' claims MUST be formatted as numeric date values.
                        Claims.ExpiresAt or Claims.IssuedAt or Claims.NotBefore
                            => value is long or JsonElement { ValueKind: JsonValueKind.Number },

                        // The 'jti', 'iss', 'scope' and 'token_usage' claims MUST be formatted as a unique string.
                        Claims.JwtId or Claims.Issuer or Claims.Scope or Claims.TokenUsage
                            => value is string or JsonElement { ValueKind: JsonValueKind.String },

                        // Claims that are not in the well-known list can be of any type.
                        _ => true
                    };

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

                /// <inheritdoc/>
                public ValueTask HandleAsync(HandleIntrospectionResponseContext context)
                {
                    if (context is null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // The issuer claim is optional. If it's not null or empty, validate it to
                    // ensure it matches the issuer registered in the server configuration.
                    var issuer = (string?) context.Response[Claims.Issuer];
                    if (!string.IsNullOrEmpty(issuer))
                    {
                        if (!Uri.TryCreate(issuer, UriKind.Absolute, out Uri? uri))
                        {
                            context.Reject(
                                error: Errors.ServerError,
                                description: SR.GetResourceString(SR.ID2108),
                                uri: SR.FormatID8000(SR.ID2108));

                            return default;
                        }

                        if (context.Issuer is not null && context.Issuer != uri)
                        {
                            context.Reject(
                                error: Errors.ServerError,
                                description: SR.GetResourceString(SR.ID2109),
                                uri: SR.FormatID8000(SR.ID2109));

                            return default;
                        }
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of extracting and validating the token usage from the introspection response.
            /// </summary>
            public class ValidateTokenUsage : IOpenIddictValidationHandler<HandleIntrospectionResponseContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                    = OpenIddictValidationHandlerDescriptor.CreateBuilder<HandleIntrospectionResponseContext>()
                        .UseSingletonHandler<ValidateTokenUsage>()
                        .SetOrder(ValidateIssuer.Descriptor.Order + 1_000)
                        .SetType(OpenIddictValidationHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public ValueTask HandleAsync(HandleIntrospectionResponseContext context)
                {
                    if (context is null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // OpenIddict-based authorization servers always return the actual token type using
                    // the special "token_usage" claim, that helps resource servers determine whether the
                    // introspected token is of the expected type and prevent token substitution attacks.
                    // In this handler, the "token_usage" is verified to ensure it corresponds to a supported
                    // value so that the component that triggered the introspection request can determine
                    // whether the returned token has an acceptable type depending on the context.
                    var usage = (string?) context.Response[Claims.TokenUsage];
                    if (string.IsNullOrEmpty(usage))
                    {
                        return default;
                    }

                    if (!(usage switch
                    {
                        // Note: by default, OpenIddict only allows access/refresh tokens to be
                        // introspected but additional types can be added using the events model.
                        TokenTypeHints.AccessToken or TokenTypeHints.AuthorizationCode or
                        TokenTypeHints.IdToken or TokenTypeHints.RefreshToken or
                        TokenTypeHints.UserCode
                            => true,

                        _ => false // Other token usages are not supported.
                    }))
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: SR.GetResourceString(SR.ID2118),
                            uri: SR.FormatID8000(SR.ID2118));

                        return default;
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
                        .SetOrder(ValidateTokenUsage.Descriptor.Order + 1_000)
                        .SetType(OpenIddictValidationHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public ValueTask HandleAsync(HandleIntrospectionResponseContext context)
                {
                    if (context is null)
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
                    var issuer = (string?) context.Response[Claims.Issuer] ?? context.Issuer?.AbsoluteUri ?? ClaimsIdentity.DefaultIssuer;

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

                        // Ignore all protocol claims that shouldn't be mapped to CLR claims.
                        if (parameter.Key is Claims.Active or Claims.Issuer or Claims.NotBefore or Claims.TokenType)
                        {
                            continue;
                        }

                        switch (parameter.Value.Value)
                        {
                            // Claims represented as arrays are split and mapped to multiple CLR claims.
                            case JsonElement { ValueKind: JsonValueKind.Array } value:
                                foreach (var element in value.EnumerateArray())
                                {
                                    var item = element.GetString();
                                    if (string.IsNullOrEmpty(item))
                                    {
                                        continue;
                                    }

                                    identity.AddClaim(new Claim(parameter.Key, item,
                                        GetClaimValueType(value.ValueKind), issuer, issuer, identity));
                                }
                                break;

                            case JsonElement value:
                                identity.AddClaim(new Claim(parameter.Key, value.ToString()!,
                                    GetClaimValueType(value.ValueKind), issuer, issuer, identity));
                                break;

                            // Note: in the typical case, the introspection parameters should be deserialized from
                            // a JSON response and thus represented as System.Text.Json.JsonElement instances.
                            // However, to support responses resolved from custom locations and parameters manually added
                            // by the application using the events model, the CLR primitive types are also supported.

                            case bool value:
                                identity.AddClaim(new Claim(parameter.Key, value.ToString(),
                                    ClaimValueTypes.Boolean, issuer, issuer, identity));
                                break;

                            case long value:
                                identity.AddClaim(new Claim(parameter.Key, value.ToString(CultureInfo.InvariantCulture),
                                    ClaimValueTypes.Integer64, issuer, issuer, identity));
                                break;

                            case string value:
                                identity.AddClaim(new Claim(parameter.Key, value, ClaimValueTypes.String, issuer, issuer, identity));
                                break;

                            // Claims represented as arrays are split and mapped to multiple CLR claims.
                            case string[] value:
                                for (var index = 0; index < value.Length; index++)
                                {
                                    identity.AddClaim(new Claim(parameter.Key, value[index], ClaimValueTypes.String, issuer, issuer, identity));
                                }
                                break;
                        }
                    }

                    context.Principal = new ClaimsPrincipal(identity);

                    return default;

                    static string GetClaimValueType(JsonValueKind kind) => kind switch
                    {
                        JsonValueKind.True or JsonValueKind.False => ClaimValueTypes.Boolean,

                        JsonValueKind.String => ClaimValueTypes.String,
                        JsonValueKind.Number => ClaimValueTypes.Integer64,

                        JsonValueKind.Array       => JsonClaimValueTypes.JsonArray,
                        JsonValueKind.Object or _ => JsonClaimValueTypes.Json
                    };
                }
            }
        }
    }
}
