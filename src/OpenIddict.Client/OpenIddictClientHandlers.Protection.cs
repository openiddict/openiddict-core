/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Client;

public static partial class OpenIddictClientHandlers
{
    public static class Protection
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Token validation:
             */
            ResolveTokenValidationParameters.Descriptor,
            ValidateIdentityModelToken.Descriptor,
            MapInternalClaims.Descriptor,
            ValidatePrincipal.Descriptor,
            ValidateExpirationDate.Descriptor,

            /*
            * Token generation:
            */
            AttachSecurityCredentials.Descriptor,
            GenerateIdentityModelToken.Descriptor);

        /// <summary>
        /// Contains the logic responsible of resolving the validation parameters used to validate tokens.
        /// </summary>
        public class ResolveTokenValidationParameters : IOpenIddictClientHandler<ValidateTokenContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .UseSingletonHandler<ResolveTokenValidationParameters>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateTokenContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // The OpenIddict client is expected to validate tokens it creates (e.g state tokens) and
                // tokens that are created by one or multiple authorization servers (e.g identity tokens).
                //
                // While state tokens could also be created by the authorization servers themselves,
                // this scenario is currently not supported. To simplify the token validation parameters
                // selection logic, an exception is thrown if multiple token types are considered valid
                // and contain tokens issued by the authorization server and tokens issued by the client.
                //
                // See https://datatracker.ietf.org/doc/html/draft-bradley-oauth-jwt-encoded-state-09#section-4.3
                // for more information.
                if (context.ValidTokenTypes.Count > 1 && context.ValidTokenTypes.Contains(TokenTypeHints.StateToken))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0308));
                }

                var parameters = context.ValidTokenTypes.Count switch
                {
                    // When only state tokens are considered valid, use the token validation parameters of the client.
                    1 when context.ValidTokenTypes.Contains(TokenTypeHints.StateToken)
                        => GetClientTokenValidationParameters(context.Options),

                    // Otherwise, use the token validation parameters of the authorization server.
                    _ => await GetServerTokenValidationParametersAsync(context.Registration)
                };

                context.SecurityTokenHandler = context.Options.JsonWebTokenHandler;
                context.TokenValidationParameters = parameters;

                static TokenValidationParameters GetClientTokenValidationParameters(OpenIddictClientOptions options)
                {
                    var parameters = options.TokenValidationParameters.Clone();
                    parameters.ValidateIssuer = false;

                    // For state tokens, only the short "oi_stet+jwt" form is valid.
                    parameters.ValidTypes = new[] { JsonWebTokenTypes.Private.StateToken };

                    return parameters;
                }

                static async Task<TokenValidationParameters> GetServerTokenValidationParametersAsync(
                    OpenIddictClientRegistration registration)
                {
                    var configuration = await registration.ConfigurationManager.GetConfigurationAsync(default) ??
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID0140));

                    // Ensure the issuer resolved from the configuration matches the expected value.
                    if (configuration.Issuer != registration!.Issuer)
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID0307));
                    }

                    var parameters = registration!.TokenValidationParameters.Clone();

                    parameters.ValidIssuer ??= configuration.Issuer?.AbsoluteUri ?? registration.Issuer?.AbsoluteUri;
                    parameters.ValidateIssuer = !string.IsNullOrEmpty(parameters.ValidIssuer);

                    // Combine the signing keys registered statically in the token validation parameters
                    // with the signing keys resolved from the OpenID Connect server configuration.
                    parameters.IssuerSigningKeys =
                        parameters.IssuerSigningKeys?.Concat(configuration.SigningKeys) ?? configuration.SigningKeys;

                    // For maximum compatibility, all "typ" values are accepted for all types of JSON Web Tokens,
                    // which typically includes identity tokens but can also include access tokens, authorization
                    // codes or refresh tokens for non-standard implementations that need to read these tokens.
                    //
                    // To prevent token mix-up/confused deputy attacks, additional checks (e.g audience validation)
                    // are expected to be made by specialized handlers later in the token validation processing.
                    parameters.ValidTypes = null;

                    return parameters;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of validating tokens generated using IdentityModel.
        /// </summary>
        public class ValidateIdentityModelToken : IOpenIddictClientHandler<ValidateTokenContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .UseSingletonHandler<ValidateIdentityModelToken>()
                    .SetOrder(ResolveTokenValidationParameters.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateTokenContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If a principal was already attached, don't overwrite it.
                if (context.Principal is not null)
                {
                    return;
                }

                // If the token cannot be read, don't return an error to allow another handler to validate it.
                if (!context.SecurityTokenHandler.CanReadToken(context.Token))
                {
                    return;
                }

                var result = await context.SecurityTokenHandler.ValidateTokenAsync(context.Token, context.TokenValidationParameters);
                if (!result.IsValid)
                {
                    context.Logger.LogTrace(result.Exception, SR.GetResourceString(SR.ID6000), context.Token);

                    context.Reject(
                        error: Errors.InvalidToken,
                        description: result.Exception switch
                        {
                            SecurityTokenInvalidTypeException          => SR.GetResourceString(SR.ID2089),
                            SecurityTokenInvalidIssuerException        => SR.GetResourceString(SR.ID2088),
                            SecurityTokenSignatureKeyNotFoundException => SR.GetResourceString(SR.ID2090),
                            SecurityTokenInvalidSignatureException     => SR.GetResourceString(SR.ID2091),

                            _ => SR.GetResourceString(SR.ID2004)
                        },
                        uri: result.Exception switch
                        {
                            SecurityTokenInvalidTypeException          => SR.FormatID8000(SR.ID2089),
                            SecurityTokenInvalidIssuerException        => SR.FormatID8000(SR.ID2088),
                            SecurityTokenSignatureKeyNotFoundException => SR.FormatID8000(SR.ID2090),
                            SecurityTokenInvalidSignatureException     => SR.FormatID8000(SR.ID2091),

                            _ => SR.FormatID8000(SR.ID2004)
                        });

                    return;
                }

                // Get the JWT token. If the token is encrypted using JWE, retrieve the inner token.
                var token = (JsonWebToken) result.SecurityToken;
                if (token.InnerToken is not null)
                {
                    token = token.InnerToken;
                }

                // Clone the identity and remove OpenIddict-specific claims from tokens that are not fully trusted.
                var identity = result.ClaimsIdentity.Clone(claim => claim switch
                {
                    // Exclude claims starting with "oi_", unless the token is a state token.
                    { Type: string type } when type.StartsWith(Claims.Prefixes.Private) &&
                        result.TokenType is not JsonWebTokenTypes.Private.StateToken => false,

                    _ => true // Allow any other claim.
                });

                // Attach the principal extracted from the token to the parent event context and store
                // the token type (resolved from "typ" or "token_usage") as a special private claim.
                context.Principal = new ClaimsPrincipal(identity).SetTokenType(result.TokenType switch
                {
                    null or { Length: 0 } => throw new InvalidOperationException(SR.GetResourceString(SR.ID0025)),

                    // Both JWT and application/JWT are supported for identity tokens.
                    JsonWebTokenTypes.IdentityToken or JsonWebTokenTypes.Prefixes.Application + JsonWebTokenTypes.IdentityToken
                        => TokenTypeHints.IdToken,

                    JsonWebTokenTypes.Private.StateToken => TokenTypeHints.StateToken,

                    _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0003))
                });

                // Store the resolved signing algorithm from the token and attach it to the principal.
                context.Principal.SetClaim(Claims.Private.SigningAlgorithm, token.Alg);

                context.Logger.LogTrace(SR.GetResourceString(SR.ID6001), context.Token, context.Principal.Claims);
            }
        }

        /// <summary>
        /// Contains the logic responsible of mapping internal claims used by OpenIddict.
        /// </summary>
        public class MapInternalClaims : IOpenIddictClientHandler<ValidateTokenContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .UseSingletonHandler<MapInternalClaims>()
                    .SetOrder(ValidateIdentityModelToken.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateTokenContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Note: only map the private claims from fully trusted tokens.
                if (context.Principal is null || !context.Principal.HasTokenType(TokenTypeHints.StateToken))
                {
                    return default;
                }

                // In OpenIddict 3.0, the creation date of a token is stored in "oi_crt_dt".
                // If the claim doesn't exist, try to infer it from the standard "iat" JWT claim.
                if (!context.Principal.HasClaim(Claims.Private.CreationDate))
                {
                    var date = context.Principal.GetClaim(Claims.IssuedAt);
                    if (!string.IsNullOrEmpty(date) &&
                        long.TryParse(date, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value))
                    {
                        context.Principal.SetCreationDate(DateTimeOffset.FromUnixTimeSeconds(value));
                    }
                }

                // In OpenIddict 3.0, the expiration date of a token is stored in "oi_exp_dt".
                // If the claim doesn't exist, try to infer it from the standard "exp" JWT claim.
                if (!context.Principal.HasClaim(Claims.Private.ExpirationDate))
                {
                    var date = context.Principal.GetClaim(Claims.ExpiresAt);
                    if (!string.IsNullOrEmpty(date) &&
                        long.TryParse(date, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value))
                    {
                        context.Principal.SetExpirationDate(DateTimeOffset.FromUnixTimeSeconds(value));
                    }
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of rejecting authentication demands for which no valid principal was resolved.
        /// </summary>
        public class ValidatePrincipal : IOpenIddictClientHandler<ValidateTokenContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .UseSingletonHandler<ValidatePrincipal>()
                    .SetOrder(MapInternalClaims.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateTokenContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (context.Principal is null)
                {
                    context.Reject(
                        error: Errors.InvalidToken,
                        description: SR.GetResourceString(SR.ID2004),
                        uri: SR.FormatID8000(SR.ID2004));

                    return default;
                }

                // When using JWT or Data Protection tokens, the correct token type is always enforced by IdentityModel
                // (using the "typ" header) or by ASP.NET Core Data Protection (using per-token-type purposes strings).
                // To ensure tokens deserialized using a custom routine are of the expected type, a manual check is used,
                // which requires that a special claim containing the token type be present in the security principal.
                var type = context.Principal.GetTokenType();
                if (string.IsNullOrEmpty(type))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0004));
                }

                if (context.ValidTokenTypes.Count > 0 && !context.ValidTokenTypes.Contains(type))
                {
                    throw new InvalidOperationException(SR.FormatID0005(type, string.Join(", ", context.ValidTokenTypes)));
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of rejecting authentication demands that use an expired token.
        /// </summary>
        public class ValidateExpirationDate : IOpenIddictClientHandler<ValidateTokenContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .UseSingletonHandler<ValidateExpirationDate>()
                    .SetOrder(ValidatePrincipal.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateTokenContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

                var date = context.Principal.GetExpirationDate();
                if (date.HasValue && date.Value < DateTimeOffset.UtcNow)
                {
                    context.Reject(
                        error: Errors.InvalidToken,
                        description: SR.GetResourceString(SR.ID2019),
                        uri: SR.FormatID8000(SR.ID2019));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of resolving the signing and encryption credentials used to protect tokens.
        /// </summary>
        public class AttachSecurityCredentials : IOpenIddictClientHandler<GenerateTokenContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<GenerateTokenContext>()
                    .UseSingletonHandler<AttachSecurityCredentials>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(GenerateTokenContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                context.SecurityTokenHandler = context.Options.JsonWebTokenHandler;

                context.EncryptionCredentials = context.Options.EncryptionCredentials.First();
                context.SigningCredentials = context.Options.SigningCredentials.First();

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating a token using IdentityModel.
        /// </summary>
        public class GenerateIdentityModelToken : IOpenIddictClientHandler<GenerateTokenContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<GenerateTokenContext>()
                    .UseSingletonHandler<GenerateIdentityModelToken>()
                    .SetOrder(AttachSecurityCredentials.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(GenerateTokenContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If a token was already attached by another handler, don't overwrite it.
                if (!string.IsNullOrEmpty(context.Token))
                {
                    return default;
                }

                if (context.Principal is not { Identity: ClaimsIdentity })
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0022));
                }

                // Clone the principal and exclude the private claims mapped to standard JWT claims.
                var principal = context.Principal.Clone(claim => claim.Type switch
                {
                    Claims.Private.CreationDate or Claims.Private.ExpirationDate or Claims.Private.TokenType => false,

                    Claims.Private.Audience when context.TokenType is TokenTypeHints.StateToken => false,

                    _ => true
                });

                Debug.Assert(principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

                var claims = new Dictionary<string, object>(StringComparer.Ordinal);

                // For state tokens, set the public audience claims using
                // the private audience claims from the security principal.
                if (context.TokenType is TokenTypeHints.StateToken)
                {
                    var audiences = context.Principal.GetAudiences();
                    if (audiences.Any())
                    {
                        claims.Add(Claims.Audience, audiences.Length switch
                        {
                            1 => audiences.ElementAt(0),
                            _ => audiences
                        });
                    }
                }

                var descriptor = new SecurityTokenDescriptor
                {
                    Claims = claims,
                    EncryptingCredentials = context.EncryptionCredentials,
                    Expires = context.Principal.GetExpirationDate()?.UtcDateTime,
                    IssuedAt = context.Principal.GetCreationDate()?.UtcDateTime,
                    SigningCredentials = context.SigningCredentials,
                    Subject = (ClaimsIdentity) principal.Identity,
                    TokenType = context.TokenType switch
                    {
                        null or { Length: 0 } => throw new InvalidOperationException(SR.GetResourceString(SR.ID0025)),

                        TokenTypeHints.StateToken => JsonWebTokenTypes.Private.StateToken,

                        _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0003))
                    }
                };

                context.Token = context.SecurityTokenHandler.CreateToken(descriptor);

                context.Logger.LogTrace(SR.GetResourceString(SR.ID6013), context.TokenType, context.Token, principal.Claims);

                return default;
            }
        }
    }
}
