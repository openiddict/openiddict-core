/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.IdentityModel.Tokens;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Validation.OpenIddictValidationEvents;

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
                ExtractCryptographyEndpointUri.Descriptor,
                ExtractIntrospectionEndpointUri.Descriptor,

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
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] HandleConfigurationResponseContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // The issuer returned in the discovery document must exactly match the URL used to access it.
                    // See https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation.
                    var issuer = (string) context.Response[Metadata.Issuer];
                    if (string.IsNullOrEmpty(issuer))
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: "No issuer could be found in the discovery document.");

                        return default;
                    }

                    if (!Uri.TryCreate(issuer, UriKind.Absolute, out Uri address))
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: "A discovery response containing an invalid issuer was returned.");

                        return default;
                    }

                    if (context.Issuer != null && context.Issuer != address)
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: "The issuer returned by the discovery endpoint is not valid.");

                        return default;
                    }

                    context.Configuration.Issuer = issuer;

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of extracting the JWKS endpoint address from the discovery document.
            /// </summary>
            public class ExtractCryptographyEndpointUri : IOpenIddictValidationHandler<HandleConfigurationResponseContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                    = OpenIddictValidationHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                        .UseSingletonHandler<ExtractCryptographyEndpointUri>()
                        .SetOrder(ValidateIssuer.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] HandleConfigurationResponseContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // Note: the jwks_uri node is required by the OpenID Connect discovery specification.
                    // See https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation.
                    var address = (string) context.Response[Metadata.JwksUri];
                    if (string.IsNullOrEmpty(address))
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: "No JWKS endpoint could be found in the discovery document.");

                        return default;
                    }

                    if (!Uri.IsWellFormedUriString(address, UriKind.Absolute))
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: "A discovery response containing an invalid JWKS endpoint URL was returned.");

                        return default;
                    }

                    context.Configuration.JwksUri = address;

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of extracting the introspection endpoint address from the discovery document.
            /// </summary>
            public class ExtractIntrospectionEndpointUri : IOpenIddictValidationHandler<HandleConfigurationResponseContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                    = OpenIddictValidationHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                        .UseSingletonHandler<ExtractIntrospectionEndpointUri>()
                        .SetOrder(ExtractCryptographyEndpointUri.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] HandleConfigurationResponseContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    var address = (string) context.Response[Metadata.IntrospectionEndpoint];
                    if (!string.IsNullOrEmpty(address) && !Uri.IsWellFormedUriString(address, UriKind.Absolute))
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: "A discovery response containing an invalid introspection endpoint URL was returned.");

                        return default;
                    }

                    context.Configuration.IntrospectionEndpoint = address;

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
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] HandleCryptographyResponseContext context)
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
                            description: "The JWKS document didn't contain a valid 'jwks' node with at least one key.");

                        return default;
                    }

                    for (var index = 0; index < keys.Count; index++)
                    {
                        // Note: the "use" parameter is defined as optional by the specification.
                        // To prevent key swapping attacks, OpenIddict requires that this parameter
                        // be present and will ignore keys that don't include a "use" parameter.
                        var use = (string) keys[index][JsonWebKeyParameterNames.Use];
                        if (string.IsNullOrEmpty(use))
                        {
                            continue;
                        }

                        // Ignore security keys that are not used for signing.
                        if (!string.Equals(use, JsonWebKeyUseNames.Sig, StringComparison.Ordinal))
                        {
                            continue;
                        }

                        var key = (string) keys[index][JsonWebKeyParameterNames.Kty] switch
                        {
                            JsonWebAlgorithmsKeyTypes.RSA => new JsonWebKey
                            {
                                Kty = JsonWebAlgorithmsKeyTypes.RSA,
                                E = (string) keys[index][JsonWebKeyParameterNames.E],
                                N = (string) keys[index][JsonWebKeyParameterNames.N]
                            },

                            JsonWebAlgorithmsKeyTypes.EllipticCurve => new JsonWebKey
                            {
                                Kty = JsonWebAlgorithmsKeyTypes.EllipticCurve,
                                Crv = (string) keys[index][JsonWebKeyParameterNames.Crv],
                                X = (string) keys[index][JsonWebKeyParameterNames.X],
                                Y = (string) keys[index][JsonWebKeyParameterNames.Y]
                            },

                            _ => null
                        };

                        if (key == null)
                        {
                            context.Reject(
                                error: Errors.ServerError,
                                description: "A JWKS response containing an unsupported key was returned.");

                            return default;
                        }

                        key.KeyId = (string) keys[index][JsonWebKeyParameterNames.Kid];
                        key.X5t = (string) keys[index][JsonWebKeyParameterNames.X5t];
                        key.X5tS256 = (string) keys[index][JsonWebKeyParameterNames.X5tS256];

                        if (keys[index].TryGetParameter(JsonWebKeyParameterNames.X5c, out var chain))
                        {
                            foreach (var certificate in chain.GetNamedParameters())
                            {
                                var value = (string) certificate.Value;
                                if (string.IsNullOrEmpty(value))
                                {
                                    context.Reject(
                                        error: Errors.ServerError,
                                        description: "A JWKS response containing an invalid key was returned.");

                                    return default;
                                }

                                key.X5c.Add(value);
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
