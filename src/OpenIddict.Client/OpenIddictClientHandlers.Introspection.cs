/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics;
using System.Globalization;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using OpenIddict.Extensions;

namespace OpenIddict.Client;

public static partial class OpenIddictClientHandlers
{
    public static class Introspection
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create([
            /*
             * Introspection response handling:
             */
            ValidateWellKnownParameters.Descriptor,
            HandleErrorResponse.Descriptor,
            HandleInactiveResponse.Descriptor,
            ValidateIssuer.Descriptor,
            ValidateExpirationDate.Descriptor,
            ValidateTokenUsage.Descriptor,
            PopulateClaims.Descriptor,
            MapInternalClaims.Descriptor
        ]);

        /// <summary>
        /// Contains the logic responsible for validating the well-known parameters contained in the introspection response.
        /// </summary>
        public sealed class ValidateWellKnownParameters : IOpenIddictClientHandler<HandleIntrospectionResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleIntrospectionResponseContext>()
                    .UseSingletonHandler<ValidateWellKnownParameters>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
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
                    // Error parameters MUST be formatted as unique strings:
                    Parameters.Error or Parameters.ErrorDescription or Parameters.ErrorUri
                        => ((JsonElement) value).ValueKind is JsonValueKind.String,

                    // The following claims MUST be formatted as booleans:
                    Claims.Active => ((JsonElement) value).ValueKind is JsonValueKind.True or JsonValueKind.False,

                    // The following claims MUST be formatted as unique strings:
                    Claims.JwtId or Claims.Issuer or Claims.Scope or Claims.TokenUsage
                        => ((JsonElement) value).ValueKind is JsonValueKind.String,

                    // The following claims MUST be formatted as strings or arrays of strings:
                    //
                    // Note: empty arrays and arrays that contain a single value are also considered valid.
                    Claims.Audience => ((JsonElement) value) is JsonElement element &&
                        element.ValueKind is JsonValueKind.String ||
                       (element.ValueKind is JsonValueKind.Array &&
                        OpenIddictHelpers.ValidateArrayElements(element, JsonValueKind.String)),

                    // The following claims MUST be formatted as numeric dates:
                    Claims.ExpiresAt or Claims.IssuedAt or Claims.NotBefore
                        => (JsonElement) value is { ValueKind: JsonValueKind.Number } element &&
                        element.TryGetDecimal(out decimal result) && result is >= 0,

                    // Claims that are not in the well-known list can be of any type.
                    _ => true
                };
            }
        }

        /// <summary>
        /// Contains the logic responsible for surfacing potential errors from the introspection response.
        /// </summary>
        public sealed class HandleErrorResponse : IOpenIddictClientHandler<HandleIntrospectionResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleIntrospectionResponseContext>()
                    .UseSingletonHandler<HandleErrorResponse>()
                    .SetOrder(ValidateWellKnownParameters.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleIntrospectionResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Note: the specification requires returning most errors (e.g invalid token errors)
                // as "active: false" responses instead of as proper OAuth 2.0 error responses.
                // For more information, see https://datatracker.ietf.org/doc/html/rfc7662#section-2.3.
                if (!string.IsNullOrEmpty(context.Response.Error))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6205), context.Response);

                    context.Reject(
                        error: context.Response.Error switch
                        {
                            Errors.UnauthorizedClient => Errors.UnauthorizedClient,
                            _                         => Errors.ServerError
                        },
                        description: SR.GetResourceString(SR.ID2146),
                        uri: SR.FormatID8000(SR.ID2146));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the active: false marker from the response.
        /// </summary>
        public sealed class HandleInactiveResponse : IOpenIddictClientHandler<HandleIntrospectionResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleIntrospectionResponseContext>()
                    .UseSingletonHandler<HandleInactiveResponse>()
                    .SetOrder(HandleErrorResponse.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
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
        /// Contains the logic responsible for extracting and validating the issuer from the introspection response.
        /// </summary>
        public sealed class ValidateIssuer : IOpenIddictClientHandler<HandleIntrospectionResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleIntrospectionResponseContext>()
                    .UseSingletonHandler<ValidateIssuer>()
                    .SetOrder(ValidateWellKnownParameters.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
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

                    // Ensure the issuer matches the expected value.
                    if (uri != context.Configuration.Issuer)
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
        /// Contains the logic responsible for extracting and validating the expiration date from the introspection response.
        /// </summary>
        public sealed class ValidateExpirationDate : IOpenIddictClientHandler<HandleIntrospectionResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleIntrospectionResponseContext>()
                    .UseSingletonHandler<ValidateExpirationDate>()
                    .SetOrder(ValidateIssuer.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleIntrospectionResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Note: in most cases, an expired token should lead to an errored or "active=false" response
                // being returned by the authorization server. Unfortunately, some implementations are known not
                // to check the expiration date of the introspected token before returning a positive response.
                //
                // To ensure expired tokens are rejected, a manual check is performed here if the
                // expiration date was returned as a dedicated claim by the remote authorization server.

                if (long.TryParse((string?) context.Response[Claims.ExpiresAt],
                    NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) &&
                    DateTimeOffset.FromUnixTimeSeconds(value) is DateTimeOffset date &&
                    date.Add(context.Registration.TokenValidationParameters.ClockSkew) < (
#if SUPPORTS_TIME_PROVIDER
                        context.Options.TimeProvider?.GetUtcNow() ??
#endif
                        DateTimeOffset.UtcNow))
                {
                    context.Reject(
                        error: Errors.ServerError,
                        description: SR.GetResourceString(SR.ID2176),
                        uri: SR.FormatID8000(SR.ID2176));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting and validating the token usage from the introspection response.
        /// </summary>
        public sealed class ValidateTokenUsage : IOpenIddictClientHandler<HandleIntrospectionResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleIntrospectionResponseContext>()
                    .UseSingletonHandler<ValidateTokenUsage>()
                    .SetOrder(ValidateExpirationDate.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
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

                // Note: by default, OpenIddict only allows access/refresh tokens to be
                // introspected but additional types can be added using the events model.
                if (usage is not (TokenTypeHints.AccessToken  or TokenTypeHints.AuthorizationCode or
                                  TokenTypeHints.DeviceCode   or TokenTypeHints.IdToken           or
                                  TokenTypeHints.RefreshToken or TokenTypeHints.UserCode))
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
        public sealed class PopulateClaims : IOpenIddictClientHandler<HandleIntrospectionResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleIntrospectionResponseContext>()
                    .UseSingletonHandler<PopulateClaims>()
                    .SetOrder(ValidateTokenUsage.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleIntrospectionResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(context.Registration.Issuer is { IsAbsoluteUri: true }, SR.GetResourceString(SR.ID4013));

                // Create a new claims-based identity using the same authentication type
                // and the name/role claims as the one used by IdentityModel for JWT tokens.
                //
                // Note: if WS-Federation claim mapping was not disabled, the resulting identity
                // will use the default WS-Federation claims as the name/role claim types.
                var identity = context.Options.DisableWebServicesFederationClaimMapping ?
                    new ClaimsIdentity(
                        context.Registration.TokenValidationParameters.AuthenticationType,
                        context.Registration.TokenValidationParameters.NameClaimType,
                        context.Registration.TokenValidationParameters.RoleClaimType) :
                    new ClaimsIdentity(
                        context.Registration.TokenValidationParameters.AuthenticationType,
                        nameType: ClaimTypes.Name,
                        roleType: ClaimTypes.Role);

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
                            identity.AddClaims(parameter.Key, value, context.Registration.Issuer.AbsoluteUri);
                            break;

                        case { ValueKind: _ } value:
                            identity.AddClaim(parameter.Key, value, context.Registration.Issuer.AbsoluteUri);
                            break;
                    }
                }

                context.Principal = new ClaimsPrincipal(identity);

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for mapping the standard claims to their internal/OpenIddict-specific equivalent.
        /// </summary>
        public sealed class MapInternalClaims : IOpenIddictClientHandler<HandleIntrospectionResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleIntrospectionResponseContext>()
                    .UseSingletonHandler<MapInternalClaims>()
                    .SetOrder(PopulateClaims.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleIntrospectionResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

                // Map the internal "oi_crt_dt" claim from the standard "iat" claim, if available.
                context.Principal.SetCreationDate(context.Principal.GetClaim(Claims.IssuedAt) switch
                {
                    string date when long.TryParse(date, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value)
                        => DateTimeOffset.FromUnixTimeSeconds(value),

                    _ => null
                });

                // Map the internal "oi_exp_dt" claim from the standard "exp" claim, if available.
                context.Principal.SetExpirationDate(context.Principal.GetClaim(Claims.ExpiresAt) switch
                {
                    string date when long.TryParse(date, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value)
                        => DateTimeOffset.FromUnixTimeSeconds(value),

                    _ => null
                });

                // Map the internal "oi_aud" claims from the standard "aud" claims, if available.
                context.Principal.SetAudiences(context.Principal.GetClaims(Claims.Audience));

                // Map the internal "oi_prst" claims from the standard "client_id" claim, if available.
                context.Principal.SetPresenters(context.Principal.GetClaim(Claims.ClientId) switch
                {
                    string identifier when !string.IsNullOrEmpty(identifier)
                        => ImmutableArray.Create(identifier),

                    _ => ImmutableArray<string>.Empty
                });

                // Map the internal "oi_scp" claims from the standard, space-separated "scope" claim, if available.
                context.Principal.SetScopes(context.Principal.GetClaim(Claims.Scope) switch
                {
                    string scope => scope.Split(Separators.Space, StringSplitOptions.RemoveEmptyEntries).ToImmutableArray(),

                    _ => ImmutableArray<string>.Empty
                });

                return default;
            }
        }
    }
}
