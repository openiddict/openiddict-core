/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Validation;

public static partial class OpenIddictValidationHandlers
{
    public static class Discovery
    {
        public static ImmutableArray<OpenIddictValidationHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Configuration response handling:
             */
            ValidateWellKnownConfigurationParameters.Descriptor,
            HandleConfigurationErrorResponse.Descriptor,
            ValidateIssuer.Descriptor,
            ExtractCryptographyEndpoint.Descriptor,
            ExtractIntrospectionEndpoint.Descriptor,
            ExtractIntrospectionEndpointClientAuthenticationMethods.Descriptor,

            /*
             * Cryptography response handling:
             */
            ValidateWellKnownCryptographyParameters.Descriptor,
            HandleCryptographyErrorResponse.Descriptor,
            ExtractSigningKeys.Descriptor);

        /// <summary>
        /// Contains the logic responsible for validating the well-known parameters contained in the configuration response.
        /// </summary>
        public sealed class ValidateWellKnownConfigurationParameters : IOpenIddictValidationHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ValidateWellKnownConfigurationParameters>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
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

                    // The following parameters MUST be formatted as unique strings:
                    Metadata.IntrospectionEndpoint or
                    Metadata.Issuer
                        => ((JsonElement) value).ValueKind is JsonValueKind.String,

                    // The following parameters MUST be formatted as arrays of strings:
                    Metadata.IntrospectionEndpointAuthMethodsSupported
                        => ((JsonElement) value) is JsonElement element &&
                            element.ValueKind is JsonValueKind.Array && ValidateStringArray(element),

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
        /// Contains the logic responsible for surfacing potential errors from the configuration response.
        /// </summary>
        public sealed class HandleConfigurationErrorResponse : IOpenIddictValidationHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<HandleConfigurationErrorResponse>()
                    .SetOrder(ValidateWellKnownConfigurationParameters.Descriptor.Order + 1_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Note: the specification doesn't define a standard way to return an error other than
                // returning a 4xx status code. That said, some implementations are known to return
                // JSON payloads similar to standard errored token responses. For more information, see
                // https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse.
                if (!string.IsNullOrEmpty(context.Response.Error))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6203), context.Response);

                    context.Reject(
                        error: Errors.ServerError,
                        description: SR.GetResourceString(SR.ID2144),
                        uri: SR.FormatID8000(SR.ID2144));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the issuer from the discovery document.
        /// </summary>
        public sealed class ValidateIssuer : IOpenIddictValidationHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ValidateIssuer>()
                    .SetOrder(HandleConfigurationErrorResponse.Descriptor.Order + 1_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Note: the issuer returned in the discovery document must exactly match the URI used to access it.
                // See https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation.

                var issuer = (string?) context.Response[Metadata.Issuer];
                if (string.IsNullOrEmpty(issuer))
                {
                    context.Reject(
                        error: Errors.ServerError,
                        description: SR.GetResourceString(SR.ID2096),
                        uri: SR.FormatID8000(SR.ID2096));

                    return default;
                }

                if (!Uri.TryCreate(issuer, UriKind.Absolute, out Uri? uri))
                {
                    context.Reject(
                        error: Errors.ServerError,
                        description: SR.GetResourceString(SR.ID2097),
                        uri: SR.FormatID8000(SR.ID2097));

                    return default;
                }

                // Ensure the issuer matches the expected value.
                if (uri != context.Options.Issuer)
                {
                    context.Reject(
                        error: Errors.ServerError,
                        description: SR.GetResourceString(SR.ID2098),
                        uri: SR.FormatID8000(SR.ID2098));

                    return default;
                }

                context.Configuration.Issuer = uri;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the JWKS endpoint URI from the discovery document.
        /// </summary>
        public sealed class ExtractCryptographyEndpoint : IOpenIddictValidationHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractCryptographyEndpoint>()
                    .SetOrder(ValidateIssuer.Descriptor.Order + 1_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Note: the jwks_uri node is required by the OpenID Connect discovery specification.
                // See https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation.
                var endpoint = (string?) context.Response[Metadata.JwksUri];
                if (string.IsNullOrEmpty(endpoint))
                {
                    context.Reject(
                        error: Errors.ServerError,
                        description: SR.GetResourceString(SR.ID2099),
                        uri: SR.FormatID8000(SR.ID2099));

                    return default;
                }

                if (!Uri.TryCreate(endpoint, UriKind.Absolute, out Uri? uri) || !uri.IsWellFormedOriginalString())
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
        /// Contains the logic responsible for extracting the introspection endpoint URI from the discovery document.
        /// </summary>
        public sealed class ExtractIntrospectionEndpoint : IOpenIddictValidationHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractIntrospectionEndpoint>()
                    .SetOrder(ExtractCryptographyEndpoint.Descriptor.Order + 1_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var endpoint = (string?) context.Response[Metadata.IntrospectionEndpoint];
                if (!string.IsNullOrEmpty(endpoint))
                {
                    if (!Uri.TryCreate(endpoint, UriKind.Absolute, out Uri? uri) || !uri.IsWellFormedOriginalString())
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: SR.FormatID2100(Metadata.IntrospectionEndpoint),
                            uri: SR.FormatID8000(SR.ID2100));

                        return default;
                    }

                    context.Configuration.IntrospectionEndpoint = uri;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the authentication methods
        /// supported by the introspection endpoint from the discovery document.
        /// </summary>
        public sealed class ExtractIntrospectionEndpointClientAuthenticationMethods : IOpenIddictValidationHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractIntrospectionEndpointClientAuthenticationMethods>()
                    .SetOrder(ExtractIntrospectionEndpoint.Descriptor.Order + 1_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Resolve the client authentication methods supported by the introspection endpoint, if available.
                var methods = context.Response[Metadata.IntrospectionEndpointAuthMethodsSupported]?.GetUnnamedParameters();
                if (methods is { Count: > 0 })
                {
                    for (var index = 0; index < methods.Count; index++)
                    {
                        // Note: custom values are allowed in this case.
                        var method = (string?) methods[index];
                        if (!string.IsNullOrEmpty(method))
                        {
                            context.Configuration.IntrospectionEndpointAuthMethodsSupported.Add(method);
                        }
                    }
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating the well-known parameters contained in the JWKS response.
        /// </summary>
        public sealed class ValidateWellKnownCryptographyParameters : IOpenIddictValidationHandler<HandleCryptographyResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<HandleCryptographyResponseContext>()
                    .UseSingletonHandler<ValidateWellKnownCryptographyParameters>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleCryptographyResponseContext context)
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
        /// Contains the logic responsible for surfacing potential errors from the cryptography response.
        /// </summary>
        public sealed class HandleCryptographyErrorResponse : IOpenIddictValidationHandler<HandleCryptographyResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<HandleCryptographyResponseContext>()
                    .UseSingletonHandler<HandleCryptographyErrorResponse>()
                    .SetOrder(ValidateWellKnownCryptographyParameters.Descriptor.Order + 1_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleCryptographyResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Note: the specification doesn't define a standard way to return an error other than
                // returning a 4xx status code. That said, some implementations are known to return
                // JSON payloads similar to standard errored token responses. For more information, see
                // https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse.
                if (!string.IsNullOrEmpty(context.Response.Error))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6204), context.Response);

                    context.Reject(
                        error: Errors.ServerError,
                        description: SR.GetResourceString(SR.ID2145),
                        uri: SR.FormatID8000(SR.ID2145));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the signing keys from the JWKS document.
        /// </summary>
        public sealed class ExtractSigningKeys : IOpenIddictValidationHandler<HandleCryptographyResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<HandleCryptographyResponseContext>()
                    .UseSingletonHandler<ExtractSigningKeys>()
                    .SetOrder(HandleCryptographyErrorResponse.Descriptor.Order + 1_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleCryptographyResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

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
