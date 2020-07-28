/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Validation.OpenIddictValidationEvents;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.Validation
{
    public static partial class OpenIddictValidationHandlers
    {
        public static class Discovery
        {
            public static ImmutableArray<OpenIddictValidationHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
                /*
                 * Configuration response handling:
                 */
                HandleErrorResponse<HandleConfigurationResponseContext>.Descriptor,
                ValidateIssuer.Descriptor,
                ExtractCryptographyEndpoint.Descriptor,
                ExtractIntrospectionEndpoint.Descriptor,

                /*
                 * Cryptography response handling:
                 */
                HandleErrorResponse<HandleCryptographyResponseContext>.Descriptor,
                ExtractSigningKeys.Descriptor);

            /// <summary>
            /// Contains the logic responsible of extracting the issuer from the discovery document.
            /// </summary>
            public class ValidateIssuer : IOpenIddictValidationHandler<HandleConfigurationResponseContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                    = OpenIddictValidationHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                        .UseSingletonHandler<ValidateIssuer>()
                        .SetOrder(HandleErrorResponse<HandleConfigurationResponseContext>.Descriptor.Order + 1_000)
                        .SetType(OpenIddictValidationHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public ValueTask HandleAsync(HandleConfigurationResponseContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // The issuer returned in the discovery document must exactly match the URL used to access it.
                    // See https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation.
                    var issuer = (string?) context.Response[Metadata.Issuer];
                    if (string.IsNullOrEmpty(issuer))
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: context.Localizer[SR.ID3096]);

                        return default;
                    }

                    if (!Uri.TryCreate(issuer, UriKind.Absolute, out Uri? address))
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: context.Localizer[SR.ID3097]);

                        return default;
                    }

                    if (context.Issuer != null && context.Issuer != address)
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: context.Localizer[SR.ID3098]);

                        return default;
                    }

                    context.Configuration.Issuer = issuer;

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of extracting the JWKS endpoint address from the discovery document.
            /// </summary>
            public class ExtractCryptographyEndpoint : IOpenIddictValidationHandler<HandleConfigurationResponseContext>
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
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // Note: the jwks_uri node is required by the OpenID Connect discovery specification.
                    // See https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation.
                    var address = (string?) context.Response[Metadata.JwksUri];
                    if (string.IsNullOrEmpty(address))
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: context.Localizer[SR.ID3099]);

                        return default;
                    }

                    if (!Uri.IsWellFormedUriString(address, UriKind.Absolute))
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: context.Localizer[SR.ID3100]);

                        return default;
                    }

                    context.Configuration.JwksUri = address;

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of extracting the introspection endpoint address from the discovery document.
            /// </summary>
            public class ExtractIntrospectionEndpoint : IOpenIddictValidationHandler<HandleConfigurationResponseContext>
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
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    var address = (string?) context.Response[Metadata.IntrospectionEndpoint];
                    if (!string.IsNullOrEmpty(address) && !Uri.IsWellFormedUriString(address, UriKind.Absolute))
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: context.Localizer[SR.ID3101]);

                        return default;
                    }

                    context.Configuration.IntrospectionEndpoint = address;

                    // Resolve the client authentication methods supported by the introspection endpoint, if available.
                    if (context.Response.TryGetParameter(Metadata.IntrospectionEndpointAuthMethodsSupported, out var methods))
                    {
                        foreach (var method in methods.GetUnnamedParameters())
                        {
                            var value = (string?) method;
                            if (string.IsNullOrEmpty(value))
                            {
                                continue;
                            }

                            context.Configuration.IntrospectionEndpointAuthMethodsSupported.Add(value);
                        }
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of extracting the signing keys from the JWKS document.
            /// </summary>
            public class ExtractSigningKeys : IOpenIddictValidationHandler<HandleCryptographyResponseContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                    = OpenIddictValidationHandlerDescriptor.CreateBuilder<HandleCryptographyResponseContext>()
                        .UseSingletonHandler<ExtractSigningKeys>()
                        .SetOrder(HandleErrorResponse<HandleCryptographyResponseContext>.Descriptor.Order + 1_000)
                        .SetType(OpenIddictValidationHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public ValueTask HandleAsync(HandleCryptographyResponseContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    var keys = context.Response[JsonWebKeySetParameterNames.Keys]?.GetUnnamedParameters();
                    if (keys == null || keys.Count == 0)
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: context.Localizer[SR.ID3102, JsonWebKeySetParameterNames.Keys]);

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

                        if (key == null)
                        {
                            context.Reject(
                                error: Errors.ServerError,
                                description: context.Localizer[SR.ID3103]);

                            return default;
                        }

                        // If the key is a RSA key, ensure the mandatory parameters are all present.
                        if (string.Equals(key.Kty, JsonWebAlgorithmsKeyTypes.RSA, StringComparison.Ordinal) &&
                           (string.IsNullOrEmpty(key.E) || string.IsNullOrEmpty(key.N)))
                        {
                            context.Reject(
                                error: Errors.ServerError,
                                description: context.Localizer[SR.ID3104]);

                            return default;
                        }

                        // If the key is an EC key, ensure the mandatory parameters are all present.
                        if (string.Equals(key.Kty, JsonWebAlgorithmsKeyTypes.EllipticCurve, StringComparison.Ordinal) &&
                           (string.IsNullOrEmpty(key.Crv) || string.IsNullOrEmpty(key.X) || string.IsNullOrEmpty(key.Y)))
                        {
                            context.Reject(
                                error: Errors.ServerError,
                                description: context.Localizer[SR.ID3104]);

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
}
