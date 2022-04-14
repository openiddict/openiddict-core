/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Client;

public static partial class OpenIddictClientHandlers
{
    public static class Discovery
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Configuration response handling:
             */
            HandleErrorResponse<HandleConfigurationResponseContext>.Descriptor,
            ValidateWellKnownConfigurationParameters.Descriptor,
            ValidateIssuer.Descriptor,
            ExtractAuthorizationEndpoint.Descriptor,
            ExtractCryptographyEndpoint.Descriptor,
            ExtractTokenEndpoint.Descriptor,
            ExtractUserinfoEndpoint.Descriptor,
            ExtractGrantTypes.Descriptor,
            ExtractResponseModes.Descriptor,
            ExtractResponseTypes.Descriptor,
            ExtractCodeChallengeMethods.Descriptor,
            ExtractScopes.Descriptor,
            ExtractIssuerParameterRequirement.Descriptor,
            ExtractTokenEndpointClientAuthenticationMethods.Descriptor,

            /*
             * Cryptography response handling:
             */
            HandleErrorResponse<HandleCryptographyResponseContext>.Descriptor,
            ValidateWellKnownCryptographyParameters.Descriptor,
            ExtractSigningKeys.Descriptor);

        /// <summary>
        /// Contains the logic responsible for validating the well-known parameters contained in the configuration response.
        /// </summary>
        public class ValidateWellKnownConfigurationParameters : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ValidateWellKnownConfigurationParameters>()
                    .SetOrder(HandleErrorResponse<HandleConfigurationResponseContext>.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context!!)
            {
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
                    // The following parameters MUST be formatted as unique strings:
                    Metadata.AuthorizationEndpoint or
                    Metadata.Issuer                or
                    Metadata.JwksUri               or
                    Metadata.TokenEndpoint         or
                    Metadata.UserinfoEndpoint
                        => ((JsonElement) value).ValueKind is JsonValueKind.String,

                    // The following parameters MUST be formatted as arrays of strings:
                    Metadata.CodeChallengeMethodsSupported or
                    Metadata.GrantTypesSupported           or
                    Metadata.ResponseModesSupported        or
                    Metadata.ResponseTypesSupported        or
                    Metadata.ScopesSupported               or
                    Metadata.TokenEndpointAuthMethodsSupported
                        => ((JsonElement) value) is JsonElement element &&
                            element.ValueKind is JsonValueKind.Array && ValidateStringArray(element),

                    // The following parameters MUST be formatted as booleans:
                    Metadata.AuthorizationResponseIssParameterSupported
                        => ((JsonElement) value).ValueKind is JsonValueKind.True or JsonValueKind.False,

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
        /// Contains the logic responsible for extracting the issuer from the discovery document.
        /// </summary>
        public class ValidateIssuer : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ValidateIssuer>()
                    .SetOrder(ValidateWellKnownConfigurationParameters.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context!!)
            {
                // The issuer returned in the discovery document must exactly match the URL used to access it.
                // See https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationClient.
                var issuer = (string?) context.Response[Metadata.Issuer];
                if (string.IsNullOrEmpty(issuer))
                {
                    context.Reject(
                        error: Errors.ServerError,
                        description: SR.GetResourceString(SR.ID2096),
                        uri: SR.FormatID8000(SR.ID2096));

                    return default;
                }

                if (!Uri.TryCreate(issuer, UriKind.Absolute, out Uri? address))
                {
                    context.Reject(
                        error: Errors.ServerError,
                        description: SR.GetResourceString(SR.ID2097),
                        uri: SR.FormatID8000(SR.ID2097));

                    return default;
                }

                context.Configuration.Issuer = address;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the authorization endpoint address from the discovery document.
        /// </summary>
        public class ExtractAuthorizationEndpoint : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractAuthorizationEndpoint>()
                    .SetOrder(ValidateIssuer.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context!!)
            {
                // Note: the authorization_endpoint node is required by the OpenID Connect discovery specification
                // but is optional in the OAuth 2.0 authorization server metadata specification. To make OpenIddict
                // compatible with the newer OAuth 2.0 specification, null/empty and missing values are allowed here.
                //
                // Handlers that require a non-null authorization endpoint URL are expected to return an error
                // if the authorization endpoint URL couldn't be resolved from the authorization server metadata.
                // See https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationClient
                // and https://datatracker.ietf.org/doc/html/rfc8414#section-2 for more information.
                //
                var address = (string?) context.Response[Metadata.AuthorizationEndpoint];
                if (!string.IsNullOrEmpty(address))
                {
                    if (!Uri.TryCreate(address, UriKind.Absolute, out Uri? uri) || !uri.IsWellFormedOriginalString())
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: SR.FormatID2100(Metadata.AuthorizationEndpoint),
                            uri: SR.FormatID8000(SR.ID2100));

                        return default;
                    }

                    context.Configuration.AuthorizationEndpoint = uri;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the JWKS endpoint address from the discovery document.
        /// </summary>
        public class ExtractCryptographyEndpoint : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractCryptographyEndpoint>()
                    .SetOrder(ExtractAuthorizationEndpoint.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context!!)
            {
                // Note: the jwks_uri node is required by the OpenID Connect discovery specification.
                // See https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationClient.
                var address = (string?) context.Response[Metadata.JwksUri];
                if (string.IsNullOrEmpty(address))
                {
                    context.Reject(
                        error: Errors.ServerError,
                        description: SR.GetResourceString(SR.ID2099),
                        uri: SR.FormatID8000(SR.ID2099));

                    return default;
                }

                if (!Uri.TryCreate(address, UriKind.Absolute, out Uri? uri) || !uri.IsWellFormedOriginalString())
                {
                    context.Reject(
                        error: Errors.ServerError,
                        description: SR.FormatID2100(Metadata.JwksUri),
                        uri: SR.FormatID8000(SR.ID2100));

                    return default;
                }

                context.Configuration.JwksUri = uri;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the token endpoint address from the discovery document.
        /// </summary>
        public class ExtractTokenEndpoint : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractTokenEndpoint>()
                    .SetOrder(ExtractCryptographyEndpoint.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context!!)
            {
                var address = (string?) context.Response[Metadata.TokenEndpoint];
                if (!string.IsNullOrEmpty(address))
                {
                    if (!Uri.TryCreate(address, UriKind.Absolute, out Uri? uri) || !uri.IsWellFormedOriginalString())
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: SR.FormatID2100(Metadata.TokenEndpoint),
                            uri: SR.FormatID8000(SR.ID2100));

                        return default;
                    }

                    context.Configuration.TokenEndpoint = uri;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the userinfo endpoint address from the discovery document.
        /// </summary>
        public class ExtractUserinfoEndpoint : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractUserinfoEndpoint>()
                    .SetOrder(ExtractTokenEndpoint.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context!!)
            {
                var address = (string?) context.Response[Metadata.UserinfoEndpoint];
                if (!string.IsNullOrEmpty(address))
                {
                    if (!Uri.TryCreate(address, UriKind.Absolute, out Uri? uri) || !uri.IsWellFormedOriginalString())
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: SR.FormatID2100(Metadata.UserinfoEndpoint),
                            uri: SR.FormatID8000(SR.ID2100));

                        return default;
                    }

                    context.Configuration.UserinfoEndpoint = uri;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the supported grant types from the discovery document.
        /// </summary>
        public class ExtractGrantTypes : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractGrantTypes>()
                    .SetOrder(ExtractAuthorizationEndpoint.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context!!)
            {
                // Resolve the grant types supported by the authorization endpoint, if available.
                var types = context.Response[Metadata.GrantTypesSupported]?.GetUnnamedParameters();
                if (types is { Count: > 0 })
                {
                    for (var index = 0; index < types.Count; index++)
                    {
                        // Note: custom values are allowed in this case.
                        var type = (string?) types[index];
                        if (!string.IsNullOrEmpty(type))
                        {
                            context.Configuration.GrantTypesSupported.Add(type);
                        }
                    }
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the supported response types from the discovery document.
        /// </summary>
        public class ExtractResponseModes : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractResponseModes>()
                    .SetOrder(ExtractAuthorizationEndpoint.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context!!)
            {
                // Resolve the response modes supported by the authorization endpoint, if available.
                var modes = context.Response[Metadata.ResponseModesSupported]?.GetUnnamedParameters();
                if (modes is { Count: > 0 })
                {
                    for (var index = 0; index < modes.Count; index++)
                    {
                        // Note: custom values are allowed in this case.
                        var mode = (string?) modes[index];
                        if (!string.IsNullOrEmpty(mode))
                        {
                            context.Configuration.ResponseModesSupported.Add(mode);
                        }
                    }
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the supported response types from the discovery document.
        /// </summary>
        public class ExtractResponseTypes : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractResponseTypes>()
                    .SetOrder(ExtractResponseModes.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context!!)
            {
                // Resolve the response types supported by the authorization endpoint, if available.
                var types = context.Response[Metadata.ResponseTypesSupported]?.GetUnnamedParameters();
                if (types is { Count: > 0 })
                {
                    for (var index = 0; index < types.Count; index++)
                    {
                        // Note: custom values are allowed in this case.
                        var type = (string?) types[index];
                        if (!string.IsNullOrEmpty(type))
                        {
                            context.Configuration.ResponseTypesSupported.Add(type);
                        }
                    }
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the supported code challenge methods from the discovery document.
        /// </summary>
        public class ExtractCodeChallengeMethods : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractCodeChallengeMethods>()
                    .SetOrder(ExtractResponseTypes.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context!!)
            {
                // Resolve the code challenge methods supported by the authorization endpoint, if available.
                var methods = context.Response[Metadata.CodeChallengeMethodsSupported]?.GetUnnamedParameters();
                if (methods is { Count: > 0 })
                {
                    for (var index = 0; index < methods.Count; index++)
                    {
                        // Note: custom values are allowed in this case.
                        var method = (string?) methods[index];
                        if (!string.IsNullOrEmpty(method))
                        {
                            context.Configuration.CodeChallengeMethodsSupported.Add(method);
                        }
                    }
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the supported scopes from the discovery document.
        /// </summary>
        public class ExtractScopes : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractScopes>()
                    .SetOrder(ExtractCodeChallengeMethods.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context!!)
            {
                // Resolve the scopes supported by the remote server, if available.
                var scopes = context.Response[Metadata.ScopesSupported]?.GetUnnamedParameters();
                if (scopes is { Count: > 0 })
                {
                    for (var index = 0; index < scopes.Count; index++)
                    {
                        // Note: custom values are allowed in this case.
                        var scope = (string?) scopes[index];
                        if (!string.IsNullOrEmpty(scope))
                        {
                            context.Configuration.ScopesSupported.Add(scope);
                        }
                    }
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the flag indicating
        /// whether the "iss" parameter is supported from the discovery document.
        /// </summary>
        public class ExtractIssuerParameterRequirement : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractIssuerParameterRequirement>()
                    .SetOrder(ExtractScopes.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context!!)
            {
                context.Configuration.AuthorizationResponseIssParameterSupported = (bool?)
                    context.Response[Metadata.AuthorizationResponseIssParameterSupported];

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the authentication methods
        /// supported by the token endpoint from the discovery document.
        /// </summary>
        public class ExtractTokenEndpointClientAuthenticationMethods : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractTokenEndpoint>()
                    .SetOrder(ExtractIssuerParameterRequirement.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context!!)
            {
                // Resolve the client authentication methods supported by the token endpoint, if available.
                var methods = context.Response[Metadata.TokenEndpointAuthMethodsSupported]?.GetUnnamedParameters();
                if (methods is { Count: > 0 })
                {
                    for (var index = 0; index < methods.Count; index++)
                    {
                        // Note: custom values are allowed in this case.
                        var method = (string?) methods[index];
                        if (!string.IsNullOrEmpty(method))
                        {
                            context.Configuration.TokenEndpointAuthMethodsSupported.Add(method);
                        }
                    }
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating the well-known parameters contained in the JWKS response.
        /// </summary>
        public class ValidateWellKnownCryptographyParameters : IOpenIddictClientHandler<HandleCryptographyResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleCryptographyResponseContext>()
                    .UseSingletonHandler<ValidateWellKnownCryptographyParameters>()
                    .SetOrder(HandleErrorResponse<HandleCryptographyResponseContext>.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleCryptographyResponseContext context!!)
            {
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
                    // The following parameters MUST be formatted as arrays of objects:
                    JsonWebKeySetParameterNames.Keys => ((JsonElement) value) is JsonElement element &&
                        element.ValueKind is JsonValueKind.Array && ValidateObjectArray(element),

                    // Parameters that are not in the well-known list can be of any type.
                    _ => true
                };

                static bool ValidateObjectArray(JsonElement element)
                {
                    foreach (var item in element.EnumerateArray())
                    {
                        if (item.ValueKind is not JsonValueKind.Object)
                        {
                            return false;
                        }
                    }

                    return true;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the signing keys from the JWKS document.
        /// </summary>
        public class ExtractSigningKeys : IOpenIddictClientHandler<HandleCryptographyResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleCryptographyResponseContext>()
                    .UseSingletonHandler<ExtractSigningKeys>()
                    .SetOrder(ValidateWellKnownCryptographyParameters.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleCryptographyResponseContext context!!)
            {
                var keys = context.Response[JsonWebKeySetParameterNames.Keys]?.GetUnnamedParameters();
                if (keys is not { Count: > 0 })
                {
                    context.Reject(
                        error: Errors.ServerError,
                        description: SR.FormatID2102(JsonWebKeySetParameterNames.Keys),
                        uri: SR.FormatID8000(SR.ID2102));

                    return default;
                }

                for (var index = 0; index < keys.Count; index++)
                {
                    // Note: the "use" parameter is defined as optional by the specification.
                    // To prevent key swapping attacks, OpenIddict requires that this parameter
                    // be present and will ignore keys that don't include a "use" parameter.
                    var use = (string?) keys[index][JsonWebKeyParameterNames.Use];
                    if (string.IsNullOrEmpty(use))
                    {
                        continue;
                    }

                    // Ignore security keys that are not used for signing.
                    if (!string.Equals(use, JsonWebKeyUseNames.Sig, StringComparison.Ordinal))
                    {
                        continue;
                    }

                    var key = (string?) keys[index][JsonWebKeyParameterNames.Kty] switch
                    {
                        JsonWebAlgorithmsKeyTypes.RSA => new JsonWebKey
                        {
                            Kty = JsonWebAlgorithmsKeyTypes.RSA,
                            E = (string?) keys[index][JsonWebKeyParameterNames.E],
                            N = (string?) keys[index][JsonWebKeyParameterNames.N]
                        },

                        JsonWebAlgorithmsKeyTypes.EllipticCurve => new JsonWebKey
                        {
                            Kty = JsonWebAlgorithmsKeyTypes.EllipticCurve,
                            Crv = (string?) keys[index][JsonWebKeyParameterNames.Crv],
                            X = (string?) keys[index][JsonWebKeyParameterNames.X],
                            Y = (string?) keys[index][JsonWebKeyParameterNames.Y]
                        },

                        _ => null
                    };

                    if (key is null)
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: SR.GetResourceString(SR.ID2103),
                            uri: SR.FormatID8000(SR.ID2103));

                        return default;
                    }

                    // If the key is a RSA key, ensure the mandatory parameters are all present.
                    if (string.Equals(key.Kty, JsonWebAlgorithmsKeyTypes.RSA, StringComparison.Ordinal) &&
                       (string.IsNullOrEmpty(key.E) || string.IsNullOrEmpty(key.N)))
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: SR.GetResourceString(SR.ID2104),
                            uri: SR.FormatID8000(SR.ID2104));

                        return default;
                    }

                    // If the key is an EC key, ensure the mandatory parameters are all present.
                    if (string.Equals(key.Kty, JsonWebAlgorithmsKeyTypes.EllipticCurve, StringComparison.Ordinal) &&
                       (string.IsNullOrEmpty(key.Crv) || string.IsNullOrEmpty(key.X) || string.IsNullOrEmpty(key.Y)))
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: SR.GetResourceString(SR.ID2104),
                            uri: SR.FormatID8000(SR.ID2104));

                        return default;
                    }

                    key.KeyId = (string?) keys[index][JsonWebKeyParameterNames.Kid];
                    key.X5t = (string?) keys[index][JsonWebKeyParameterNames.X5t];
                    key.X5tS256 = (string?) keys[index][JsonWebKeyParameterNames.X5tS256];

                    if (keys[index].TryGetNamedParameter(JsonWebKeyParameterNames.X5c, out var chain))
                    {
                        foreach (string? certificate in chain.GetUnnamedParameters())
                        {
                            if (string.IsNullOrEmpty(certificate))
                            {
                                continue;
                            }

                            key.X5c.Add(certificate);
                        }
                    }

                    context.SecurityKeys.Keys.Add(key);
                }

                return default;
            }
        }
    }
}
