/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Globalization;
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
        /// Contains the logic responsible of validating the well-known parameters contained in the userinfo response.
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
                    // The 'sub' parameter MUST be formatted as a string value.
                    Claims.Subject => value is string or JsonElement { ValueKind: JsonValueKind.String },

                    // Parameters that are not in the well-known list can be of any type.
                    _ => true
                };
            }
        }

        /// <summary>
        /// Contains the logic responsible of extracting the claims from the introspection response.
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
