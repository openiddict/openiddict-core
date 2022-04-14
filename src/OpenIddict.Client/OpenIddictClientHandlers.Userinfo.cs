/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;

namespace OpenIddict.Client;

public static partial class OpenIddictClientHandlers
{
    public static class Userinfo
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Userinfo response handling:
             */
            HandleErrorResponse<HandleUserinfoResponseContext>.Descriptor,
            ValidateWellKnownClaims.Descriptor,
            PopulateClaims.Descriptor);

        /// <summary>
        /// Contains the logic responsible for validating the well-known parameters contained in the userinfo response.
        /// </summary>
        public class ValidateWellKnownClaims : IOpenIddictClientHandler<HandleUserinfoResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleUserinfoResponseContext>()
                    .UseSingletonHandler<ValidateWellKnownClaims>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleUserinfoResponseContext context!!)
            {
                // Ignore the response instance if a userinfo token was extracted.
                if (!string.IsNullOrEmpty(context.UserinfoToken))
                {
                    return default;
                }

                foreach (var parameter in context.Response.GetParameters())
                {
                    if (ValidateClaimType(parameter.Key, parameter.Value))
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

                // Note: in the typical case, the response parameters should be deserialized from a
                // JSON response and thus natively stored as System.Text.Json.JsonElement instances.
                //
                // In the rare cases where the underlying value wouldn't be a JsonElement instance
                // (e.g when custom parameters are manually added to the response), the static
                // conversion operator would take care of converting the underlying value to a
                // JsonElement instance using the same value type as the original parameter value.
                static bool ValidateClaimType(string name, OpenIddictParameter value) => name switch
                {
                    // The 'sub' parameter MUST be formatted as a unique string value.
                    Claims.Subject => ((JsonElement) value).ValueKind is JsonValueKind.String,

                    // Parameters that are not in the well-known list can be of any type.
                    _ => true
                };
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
                    .SetOrder(ValidateWellKnownClaims.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(HandleUserinfoResponseContext context!!)
            {
                // Ignore the response instance if a userinfo token was extracted.
                if (!string.IsNullOrEmpty(context.UserinfoToken))
                {
                    return;
                }

                var configuration = await context.Registration.ConfigurationManager.GetConfigurationAsync(default) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0140));

                // Ensure the issuer resolved from the configuration matches the expected value.
                if (configuration.Issuer != context.Issuer)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0307));
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
                var issuer = (string?) context.Response[Claims.Issuer] ?? configuration.Issuer!.AbsoluteUri;

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
                                    valueType     : GetClaimValueType(item.ValueKind),
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
                                valueType     : GetClaimValueType(value.ValueKind),
                                issuer        : issuer,
                                originalIssuer: issuer,
                                subject       : identity));
                            break;
                    }
                }

                context.Principal = new ClaimsPrincipal(identity);

                static string GetClaimValueType(JsonValueKind kind) => kind switch
                {
                    JsonValueKind.String                          => ClaimValueTypes.String,
                    JsonValueKind.Number                          => ClaimValueTypes.Integer64,
                    JsonValueKind.True or JsonValueKind.False     => ClaimValueTypes.Boolean,
                    JsonValueKind.Null or JsonValueKind.Undefined => JsonClaimValueTypes.JsonNull,
                    JsonValueKind.Array                           => JsonClaimValueTypes.JsonArray,
                    JsonValueKind.Object or _                     => JsonClaimValueTypes.Json
                };
            }
        }
    }
}
