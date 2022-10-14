/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace OpenIddict.Client;

public static partial class OpenIddictClientHandlers
{
    public static class Userinfo
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Userinfo response handling:
             */
            ValidateWellKnownParameters.Descriptor,
            HandleErrorResponse.Descriptor,
            PopulateClaims.Descriptor);

        /// <summary>
        /// Contains the logic responsible for validating the well-known parameters contained in the userinfo response.
        /// </summary>
        public class ValidateWellKnownParameters : IOpenIddictClientHandler<HandleUserinfoResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleUserinfoResponseContext>()
                    .UseSingletonHandler<ValidateWellKnownParameters>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleUserinfoResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Ignore the response instance if a userinfo token was extracted.
                if (!string.IsNullOrEmpty(context.UserinfoToken))
                {
                    return default;
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

                    // The following parameters MUST be formatted as unique strings:
                    Claims.Subject => ((JsonElement) value).ValueKind is JsonValueKind.String,

                    // Parameters that are not in the well-known list can be of any type.
                    _ => true
                };
            }
        }

        /// <summary>
        /// Contains the logic responsible for surfacing potential errors from the userinfo response.
        /// </summary>
        public class HandleErrorResponse : IOpenIddictClientHandler<HandleUserinfoResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleUserinfoResponseContext>()
                    .UseSingletonHandler<HandleErrorResponse>()
                    .SetOrder(ValidateWellKnownParameters.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleUserinfoResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // For more information, see https://openid.net/specs/openid-connect-core-1_0.html#UserInfoError.
                if (!string.IsNullOrEmpty(context.Response.Error))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6207), context.Response);

                    context.Reject(
                        error: context.Response.Error switch
                        {
                            Errors.InsufficientScope => Errors.InsufficientScope,
                            Errors.InvalidRequest    => Errors.InvalidRequest,
                            Errors.InvalidToken      => Errors.InvalidToken,
                            _                        => Errors.ServerError
                        },
                        description: SR.GetResourceString(SR.ID2148),
                        uri: SR.FormatID8000(SR.ID2148));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the claims from the introspection response.
        /// </summary>
        public class PopulateClaims : IOpenIddictClientHandler<HandleUserinfoResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleUserinfoResponseContext>()
                    .UseSingletonHandler<PopulateClaims>()
                    .SetOrder(HandleErrorResponse.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleUserinfoResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Ignore the response instance if a userinfo token was extracted.
                if (!string.IsNullOrEmpty(context.UserinfoToken))
                {
                    return default;
                }

                // Create a new claims-based identity using the same authentication type
                // and the name/role claims as the one used by IdentityModel for JWT tokens.
                var identity = new ClaimsIdentity(
                    context.Registration.TokenValidationParameters.AuthenticationType,
                    context.Registration.TokenValidationParameters.NameClaimType,
                    context.Registration.TokenValidationParameters.RoleClaimType);

                // Resolve the issuer that will be attached to the claims created by this handler.
                // Note: at this stage, the optional issuer extracted from the response is assumed
                // to be valid, as it is guarded against unknown values by the ValidateIssuer handler.
                var issuer = (string?) context.Response[Claims.Issuer] ?? context.Configuration.Issuer!.AbsoluteUri;

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
                            identity.AddClaims(parameter.Key, value, issuer);
                            break;

                        case { ValueKind: _ } value:
                            identity.AddClaim(parameter.Key, value, issuer);
                            break;
                    }
                }

                context.Principal = new ClaimsPrincipal(identity);

                return default;
            }
        }
    }
}
