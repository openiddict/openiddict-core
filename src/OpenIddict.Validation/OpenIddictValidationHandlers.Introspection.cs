/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;

namespace OpenIddict.Validation;

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
            ValidateWellKnownParameters.Descriptor,
            HandleInactiveResponse.Descriptor,
            ValidateIssuer.Descriptor,
            ValidateTokenUsage.Descriptor,
            PopulateClaims.Descriptor);

        /// <summary>
        /// Contains the logic responsible for attaching the client credentials to the introspection request.
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
        /// Contains the logic responsible for attaching the token to the introspection request.
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
        /// Contains the logic responsible for validating the well-known parameters contained in the introspection response.
        /// </summary>
        public class ValidateWellKnownParameters : IOpenIddictValidationHandler<HandleIntrospectionResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<HandleIntrospectionResponseContext>()
                    .UseSingletonHandler<ValidateWellKnownParameters>()
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

                foreach (var parameter in context.Response.GetParameters())
                {
                    if (!ValidateParameterType(parameter.Key, parameter.Value))
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: SR.FormatID2107(parameter.Key),
                            uri: SR.FormatID8000(SR.ID2107));

                        return default;
                    }
                }

                return default;

                // Note: in the typical case, the response parameters should be deserialized from a
                // JSON response and thus natively stored as System.Text.Json.JsonElement instances.
                //
                // In the rare cases where the underlying value wouldn't be a JsonElement instance
                // (e.g when custom parameters are manually added to the response), the static
                // conversion operator would take care of converting the underlying value to a
                // JsonElement instance using the same value type as the original parameter value.
                static bool ValidateParameterType(string name, OpenIddictParameter value) => name switch
                {
                    // The following parameters MUST be formatted as booleans:
                    Claims.Active => ((JsonElement) value).ValueKind is JsonValueKind.True or JsonValueKind.False,

                    // The following parameters MUST be formatted as unique strings:
                    Claims.JwtId or Claims.Issuer or Claims.Scope or Claims.TokenUsage
                        => ((JsonElement) value).ValueKind is JsonValueKind.String,

                    // The following parameters MUST be formatted as strings or arrays of strings:
                    //
                    // Note: empty arrays and arrays that contain a single value are also considered valid.
                    Claims.Audience => ((JsonElement) value) is JsonElement element &&
                        element.ValueKind is JsonValueKind.String ||
                       (element.ValueKind is JsonValueKind.Array && ValidateStringArray(element)),

                    // The following parameters MUST be formatted as numeric dates:
                    Claims.ExpiresAt or Claims.IssuedAt or Claims.NotBefore
                        => ((JsonElement) value).ValueKind is JsonValueKind.Number,

                    // Parameters that are not in the well-known list can be of any type.
                    _ => true
                };

                static bool ValidateStringArray(JsonElement element)
                {
                    foreach (var item in element.EnumerateArray())
                    {
                        if (item.ValueKind is not JsonValueKind.String)
                        {
                            return false;
                        }
                    }

                    return true;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the active: false marker from the response.
        /// </summary>
        public class HandleInactiveResponse : IOpenIddictValidationHandler<HandleIntrospectionResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<HandleIntrospectionResponseContext>()
                    .UseSingletonHandler<HandleInactiveResponse>()
                    .SetOrder(ValidateWellKnownParameters.Descriptor.Order + 1_000)
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

                var active = (bool?) context.Response[Parameters.Active];
                if (active is null)
                {
                    context.Reject(
                        error: Errors.ServerError,
                        description: SR.FormatID2105(Parameters.Active),
                        uri: SR.FormatID8000(SR.ID2105));

                    return default;
                }

                if (active is not true)
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
        /// Contains the logic responsible for extracting the issuer from the introspection response.
        /// </summary>
        public class ValidateIssuer : IOpenIddictValidationHandler<HandleIntrospectionResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<HandleIntrospectionResponseContext>()
                    .UseSingletonHandler<ValidateIssuer>()
                    .SetOrder(ValidateWellKnownParameters.Descriptor.Order + 1_000)
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
        /// Contains the logic responsible for extracting and validating the token usage from the introspection response.
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
                    TokenTypeHints.IdToken     or TokenTypeHints.RefreshToken      or
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
        /// Contains the logic responsible for extracting the claims from the introspection response.
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
            public async ValueTask HandleAsync(HandleIntrospectionResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var configuration = await context.Options.ConfigurationManager.GetConfigurationAsync(default) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0140));

                // Ensure the issuer resolved from the configuration matches the expected value.
                if (configuration is not null && configuration.Issuer != context.Issuer)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0307));
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
                var issuer = (string?) context.Response[Claims.Issuer] ??
                    configuration?.Issuer?.AbsoluteUri ??
                    context.Issuer?.AbsoluteUri ?? ClaimsIdentity.DefaultIssuer;

                foreach (var parameter in context.Response.GetParameters())
                {
                    // Always exclude null keys as they can't be represented as valid claims.
                    if (string.IsNullOrEmpty(parameter.Key))
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

                    // Note: in the typical case, the response parameters should be deserialized from a
                    // JSON response and thus natively stored as System.Text.Json.JsonElement instances.
                    //
                    // In the rare cases where the underlying value wouldn't be a JsonElement instance
                    // (e.g when custom parameters are manually added to the response), the static
                    // conversion operator would take care of converting the underlying value to a
                    // JsonElement instance using the same value type as the original parameter value.
                    switch ((JsonElement) parameter.Value)
                    {
                        // Top-level claims represented as arrays are split and mapped to multiple CLR claims
                        // to match the logic implemented by IdentityModel for JWT token deserialization.
                        case { ValueKind: JsonValueKind.Array } value:
                            foreach (var item in value.EnumerateArray())
                            {
                                identity.AddClaim(new Claim(
                                    type          : parameter.Key,
                                    value         : item.ToString()!,
                                    valueType     : GetClaimValueType(item),
                                    issuer        : issuer,
                                    originalIssuer: issuer,
                                    subject       : identity));
                            }
                            break;

                        // Note: JsonElement.ToString() returns string.Empty for JsonValueKind.Null and
                        // JsonValueKind.Undefined, which, unlike null strings, is a valid claim value.
                        case { ValueKind: _ } value:
                            identity.AddClaim(new Claim(
                                type          : parameter.Key,
                                value         : value.ToString()!,
                                valueType     : GetClaimValueType(value),
                                issuer        : issuer,
                                originalIssuer: issuer,
                                subject       : identity));
                            break;
                    }
                }

                context.Principal = new ClaimsPrincipal(identity);

                static string GetClaimValueType(JsonElement element) => element.ValueKind switch
                {
                    JsonValueKind.String                      => ClaimValueTypes.String,
                    JsonValueKind.True or JsonValueKind.False => ClaimValueTypes.Boolean,

                    JsonValueKind.Number when element.TryGetInt32(out _)  => ClaimValueTypes.Integer32,
                    JsonValueKind.Number when element.TryGetInt64(out _)  => ClaimValueTypes.Integer64,
                    JsonValueKind.Number when element.TryGetUInt32(out _) => ClaimValueTypes.UInteger32,
                    JsonValueKind.Number when element.TryGetUInt64(out _) => ClaimValueTypes.UInteger64,
                    JsonValueKind.Number when element.TryGetDouble(out _) => ClaimValueTypes.Double,

                    JsonValueKind.Null or JsonValueKind.Undefined => JsonClaimValueTypes.JsonNull,
                    JsonValueKind.Array                           => JsonClaimValueTypes.JsonArray,
                    JsonValueKind.Object or _                     => JsonClaimValueTypes.Json
                };
            }
        }
    }
}
