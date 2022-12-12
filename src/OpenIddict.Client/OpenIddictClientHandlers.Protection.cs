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
using OpenIddict.Extensions;

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
            ValidateReferenceTokenIdentifier.Descriptor,
            ValidateIdentityModelToken.Descriptor,
            MapInternalClaims.Descriptor,
            RestoreTokenEntryProperties.Descriptor,
            ValidatePrincipal.Descriptor,
            ValidateExpirationDate.Descriptor,
            ValidateTokenEntry.Descriptor,

            /*
             * Token generation:
             */
            AttachSecurityCredentials.Descriptor,
            CreateTokenEntry.Descriptor,
            GenerateIdentityModelToken.Descriptor,
            AttachTokenPayload.Descriptor);

        /// <summary>
        /// Contains the logic responsible for resolving the validation parameters used to validate tokens.
        /// </summary>
        public sealed class ResolveTokenValidationParameters : IOpenIddictClientHandler<ValidateTokenContext>
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
            public ValueTask HandleAsync(ValidateTokenContext context)
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
                        => GetClientTokenValidationParameters(),

                    // Otherwise, use the token validation parameters of the authorization server.
                    _ => GetServerTokenValidationParameters()
                };

                context.SecurityTokenHandler = context.Options.JsonWebTokenHandler;
                context.TokenValidationParameters = parameters;

                return default;

                TokenValidationParameters GetClientTokenValidationParameters()
                {
                    var parameters = context.Options.TokenValidationParameters.Clone();

                    parameters.ValidIssuers ??= (context.Options.ClientUri ?? context.BaseUri) switch
                    {
                        null => null,

                        // If the client URI doesn't contain any query/fragment, allow both http://www.fabrikam.com
                        // and http://www.fabrikam.com/ (the recommended URI representation) to be considered valid.
                        // See https://datatracker.ietf.org/doc/html/rfc3986#section-6.2.3 for more information.
                        { AbsolutePath: "/", Query.Length: 0, Fragment.Length: 0 } uri => new[]
                        {
                            uri.AbsoluteUri, // Uri.AbsoluteUri is normalized and always contains a trailing slash.
                            uri.AbsoluteUri[..^1]
                        },

                        // When properly normalized, Uri.AbsolutePath should never be empty and should at least
                        // contain a leading slash. While dangerous, System.Uri now offers a way to create a URI
                        // instance without applying the default canonicalization logic. To support such URIs,
                        // a special case is added here to add back the missing trailing slash when necessary.
                        { AbsolutePath.Length: 0, Query.Length: 0, Fragment.Length: 0 } uri => new[]
                        {
                            uri.AbsoluteUri,
                            uri.AbsoluteUri + "/"
                        },

                        Uri uri => new[] { uri.AbsoluteUri }
                    };

                    parameters.ValidateIssuer = parameters.ValidIssuers is not null;

                    // For state tokens, only the short "oi_stet+jwt" form is valid.
                    parameters.ValidTypes = new[] { JsonWebTokenTypes.Private.StateToken };

                    return parameters;
                }

                TokenValidationParameters GetServerTokenValidationParameters()
                {
                    var parameters = context.Registration.TokenValidationParameters.Clone();

                    parameters.ValidIssuers ??= context.Configuration.Issuer switch
                    {
                        null => null,

                        // If the issuer URI doesn't contain any query/fragment, allow both http://www.fabrikam.com
                        // and http://www.fabrikam.com/ (the recommended URI representation) to be considered valid.
                        // See https://datatracker.ietf.org/doc/html/rfc3986#section-6.2.3 for more information.
                        { AbsolutePath: "/", Query.Length: 0, Fragment.Length: 0 } uri => new[]
                        {
                            uri.AbsoluteUri, // Uri.AbsoluteUri is normalized and always contains a trailing slash.
                            uri.AbsoluteUri[..^1]
                        },

                        // When properly normalized, Uri.AbsolutePath should never be empty and should at least
                        // contain a leading slash. While dangerous, System.Uri now offers a way to create a URI
                        // instance without applying the default canonicalization logic. To support such URIs,
                        // a special case is added here to add back the missing trailing slash when necessary.
                        { AbsolutePath.Length: 0, Query.Length: 0, Fragment.Length: 0 } uri => new[]
                        {
                            uri.AbsoluteUri,
                            uri.AbsoluteUri + "/"
                        },

                        Uri uri => new[] { uri.AbsoluteUri }
                    };

                    parameters.ValidateIssuer = parameters.ValidIssuers is not null;

                    // Combine the signing keys registered statically in the token validation parameters
                    // with the signing keys resolved from the OpenID Connect server configuration.
                    parameters.IssuerSigningKeys =
                        parameters.IssuerSigningKeys?.Concat(context.Configuration.SigningKeys) ?? context.Configuration.SigningKeys;

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
        /// Contains the logic responsible for validating reference token identifiers.
        /// Note: this handler is not used when token storage is disabled.
        /// </summary>
        public sealed class ValidateReferenceTokenIdentifier : IOpenIddictClientHandler<ValidateTokenContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public ValidateReferenceTokenIdentifier() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0318));

            public ValidateReferenceTokenIdentifier(IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager ?? throw new ArgumentNullException(nameof(tokenManager));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .UseScopedHandler<ValidateReferenceTokenIdentifier>()
                    .SetOrder(ResolveTokenValidationParameters.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            public async ValueTask HandleAsync(ValidateTokenContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If the reference token cannot be found, don't return an error to allow another handler to validate it.
                var token = await _tokenManager.FindByReferenceIdAsync(context.Token);
                if (token is null)
                {
                    return;
                }

                // If the type associated with the token entry doesn't match one of the expected types, return an error.
                if (!(context.ValidTokenTypes.Count switch
                {
                    0 => true, // If no specific token type is expected, accept all token types at this stage.
                    1 => await _tokenManager.HasTypeAsync(token, context.ValidTokenTypes.ElementAt(0)),
                    _ => await _tokenManager.HasTypeAsync(token, context.ValidTokenTypes.ToImmutableArray())
                }))
                {
                    context.Reject(
                        error: Errors.InvalidToken,
                        description: SR.GetResourceString(SR.ID2004),
                        uri: SR.FormatID8000(SR.ID2004));

                    return;
                }

                var payload = await _tokenManager.GetPayloadAsync(token);
                if (string.IsNullOrEmpty(payload))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0026));
                }

                // Replace the token parameter by the payload resolved from the token entry
                // and store the identifier of the reference token so it can be later
                // used to restore the properties associated with the token.
                context.IsReferenceToken = true;
                context.Token = payload;
                context.TokenId = await _tokenManager.GetIdAsync(token);
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating tokens generated using IdentityModel.
        /// </summary>
        public sealed class ValidateIdentityModelToken : IOpenIddictClientHandler<ValidateTokenContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .UseSingletonHandler<ValidateIdentityModelToken>()
                    .SetOrder(ValidateReferenceTokenIdentifier.Descriptor.Order + 1_000)
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
                    // If validation failed because of an unrecognized key identifier and a client
                    // registration is available, inform the configuration manager that the configuration
                    // MAY have be refreshed by sending a new discovery request to the authorization server.
                    if (context.Registration is not null && result.Exception is SecurityTokenSignatureKeyNotFoundException)
                    {
                        context.Registration.ConfigurationManager.RequestRefresh();
                    }

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

                if (context.ValidTokenTypes.Contains(TokenTypeHints.StateToken))
                {
                    // Attach the principal extracted from the token to the parent event context and store
                    // the token type (resolved from "typ" or "token_usage") as a special private claim.
                    context.Principal = new ClaimsPrincipal(identity).SetTokenType(result.TokenType switch
                    {
                        null or { Length: 0 } => throw new InvalidOperationException(SR.GetResourceString(SR.ID0025)),

                        JsonWebTokenTypes.Private.StateToken => TokenTypeHints.StateToken,

                        _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0003))
                    });
                }

                else if (context.ValidTokenTypes.Count is 1)
                {
                    // JSON Web Tokens defined by the OpenID Connect core specification (e.g identity or userinfo tokens)
                    // don't have to include a specific "typ" header and all values are allowed. As such, the tokens
                    // as assumed to be of the type that is expected by the authentication routine. Additional checks
                    // like audience validation can be implemented to prevent tokens mix-up/confused deputy attacks.
                    context.Principal = new ClaimsPrincipal(identity).SetTokenType(context.ValidTokenTypes.Single());
                }

                else
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0308));
                }

                // Store the resolved signing algorithm from the token and attach it to the principal.
                context.Principal.SetClaim(Claims.Private.SigningAlgorithm, token.Alg);

                context.Logger.LogTrace(SR.GetResourceString(SR.ID6001), context.Token, context.Principal.Claims);
            }
        }

        /// <summary>
        /// Contains the logic responsible for mapping internal claims used by OpenIddict.
        /// </summary>
        public sealed class MapInternalClaims : IOpenIddictClientHandler<ValidateTokenContext>
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
        /// Contains the logic responsible for restoring the properties associated with a token entry.
        /// Note: this handler is not used when token storage is disabled.
        /// </summary>
        public sealed class RestoreTokenEntryProperties : IOpenIddictClientHandler<ValidateTokenContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public RestoreTokenEntryProperties() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0318));

            public RestoreTokenEntryProperties(IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager ?? throw new ArgumentNullException(nameof(tokenManager));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .UseScopedHandler<RestoreTokenEntryProperties>()
                    .SetOrder(MapInternalClaims.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            public async ValueTask HandleAsync(ValidateTokenContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (context.Principal is null)
                {
                    return;
                }

                // Extract the token identifier from the authentication principal.
                //
                // If no token identifier can be found, this indicates that the token
                // has no backing database entry (e.g if token storage was disabled).
                var identifier = context.Principal.GetTokenId();
                if (string.IsNullOrEmpty(identifier))
                {
                    return;
                }

                // If the token entry cannot be found, return a generic error.
                var token = await _tokenManager.FindByIdAsync(identifier);
                if (token is null)
                {
                    context.Reject(
                        error: Errors.InvalidToken,
                        description: SR.GetResourceString(SR.ID2019),
                        uri: SR.FormatID8000(SR.ID2019));

                    return;
                }

                // Restore the creation/expiration dates/identifiers from the token entry metadata.
                context.Principal
                    .SetCreationDate(await _tokenManager.GetCreationDateAsync(token))
                    .SetExpirationDate(await _tokenManager.GetExpirationDateAsync(token))
                    .SetTokenId(context.TokenId = await _tokenManager.GetIdAsync(token))
                    .SetTokenType(await _tokenManager.GetTypeAsync(token));
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting authentication demands for which no valid principal was resolved.
        /// </summary>
        public sealed class ValidatePrincipal : IOpenIddictClientHandler<ValidateTokenContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .UseSingletonHandler<ValidatePrincipal>()
                    .SetOrder(RestoreTokenEntryProperties.Descriptor.Order + 1_000)
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
        /// Contains the logic responsible for rejecting authentication demands that use an expired token.
        /// </summary>
        public sealed class ValidateExpirationDate : IOpenIddictClientHandler<ValidateTokenContext>
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
        /// Contains the logic responsible for authentication demands a token whose
        /// associated token entry is no longer valid (e.g was revoked).
        /// Note: this handler is not used when token storage is disabled.
        /// </summary>
        public sealed class ValidateTokenEntry : IOpenIddictClientHandler<ValidateTokenContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public ValidateTokenEntry() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0139));

            public ValidateTokenEntry(IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager ?? throw new ArgumentNullException(nameof(tokenManager));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .AddFilter<RequireTokenIdResolved>()
                    .UseScopedHandler<ValidateTokenEntry>()
                    .SetOrder(ValidateExpirationDate.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateTokenContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));
                Debug.Assert(!string.IsNullOrEmpty(context.TokenId), SR.GetResourceString(SR.ID4017));

                var token = await _tokenManager.FindByIdAsync(context.TokenId) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0021));

                if (await _tokenManager.HasStatusAsync(token, Statuses.Redeemed))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6002), context.TokenId);

                    context.Reject(
                        error: Errors.InvalidToken,
                        description: context.Principal.GetTokenType() switch
                        {
                            TokenTypeHints.StateToken => SR.GetResourceString(SR.ID2139),

                            _ => SR.GetResourceString(SR.ID2013)
                        },
                        uri: context.Principal.GetTokenType() switch
                        {
                            TokenTypeHints.StateToken => SR.FormatID8000(SR.ID2139),

                            _ => SR.FormatID8000(SR.ID2013)
                        });

                    return;
                }

                if (!await _tokenManager.HasStatusAsync(token, Statuses.Valid))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6005), context.TokenId);

                    context.Reject(
                        error: Errors.InvalidToken,
                        description: SR.GetResourceString(SR.ID2019),
                        uri: SR.FormatID8000(SR.ID2019));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for resolving the signing and encryption credentials used to protect tokens.
        /// </summary>
        public sealed class AttachSecurityCredentials : IOpenIddictClientHandler<GenerateTokenContext>
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

                context.EncryptionCredentials = context.TokenType switch
                {
                    // For client assertions, use the encryption credentials
                    // configured for the client registration, if available.
                    TokenTypeHints.ClientAssertionToken
                        => context.Registration.EncryptionCredentials.FirstOrDefault(),

                    // For other types of tokens, use the global encryption credentials.
                    _ => context.Options.EncryptionCredentials.First()
                };

                context.SigningCredentials = context.TokenType switch
                {
                    // For client assertions, use the signing credentials configured for the client registration.
                    TokenTypeHints.ClientAssertionToken
                        => context.Registration.SigningCredentials.First(),

                    // For other types of tokens, use the global signing credentials.
                    _ => context.Options.SigningCredentials.First()
                };

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for creating a token entry.
        /// Note: this handler is not used when token storage is disabled.
        /// </summary>
        public sealed class CreateTokenEntry : IOpenIddictClientHandler<GenerateTokenContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public CreateTokenEntry() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0318));

            public CreateTokenEntry(IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager ?? throw new ArgumentNullException(nameof(tokenManager));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<GenerateTokenContext>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .AddFilter<RequireTokenEntryCreated>()
                    .UseScopedHandler<CreateTokenEntry>()
                    .SetOrder(AttachSecurityCredentials.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(GenerateTokenContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var descriptor = new OpenIddictTokenDescriptor
                {
                    AuthorizationId = context.Principal.GetAuthorizationId(),
                    CreationDate = context.Principal.GetCreationDate(),
                    ExpirationDate = context.Principal.GetExpirationDate(),
                    Principal = context.Principal,
                    Status = Statuses.Valid,
                    Subject = null,
                    Type = context.TokenType
                };

                // Tokens produced by the client stack cannot have an application attached.

                var token = await _tokenManager.CreateAsync(descriptor) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0019));

                var identifier = await _tokenManager.GetIdAsync(token);

                // Attach the token identifier to the principal so that it can be stored in the token.
                context.Principal.SetTokenId(identifier);

                context.Logger.LogTrace(SR.GetResourceString(SR.ID6012), context.TokenType, identifier);
            }
        }

        /// <summary>
        /// Contains the logic responsible for generating a token using IdentityModel.
        /// </summary>
        public sealed class GenerateIdentityModelToken : IOpenIddictClientHandler<GenerateTokenContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<GenerateTokenContext>()
                    .AddFilter<RequireJsonWebTokenFormat>()
                    .UseSingletonHandler<GenerateIdentityModelToken>()
                    .SetOrder(CreateTokenEntry.Descriptor.Order + 1_000)
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
                    Claims.Private.CreationDate or Claims.Private.ExpirationDate or
                    Claims.Private.Issuer       or Claims.Private.TokenType => false,

                    Claims.Private.Audience when context.TokenType is
                        TokenTypeHints.ClientAssertionToken or TokenTypeHints.StateToken => false,

                    _ => true
                });

                Debug.Assert(principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

                var claims = new Dictionary<string, object>(StringComparer.Ordinal);

                // For client assertion tokens, set the public audience claims
                // using the private audience claims from the security principal.
                if (context.TokenType is TokenTypeHints.ClientAssertionToken)
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
                    Issuer = context.Principal.GetClaim(Claims.Private.Issuer),
                    SigningCredentials = context.SigningCredentials,
                    Subject = (ClaimsIdentity) principal.Identity,
                    TokenType = context.TokenType switch
                    {
                        null or { Length: 0 } => throw new InvalidOperationException(SR.GetResourceString(SR.ID0025)),

                        // For client assertion tokens, use the generic "JWT" type.
                        TokenTypeHints.ClientAssertionToken => JsonWebTokenTypes.Jwt,

                        // For state tokens, use its private representation.
                        TokenTypeHints.StateToken => JsonWebTokenTypes.Private.StateToken,

                        _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0003))
                    }
                };

                context.Token = context.SecurityTokenHandler.CreateToken(descriptor);

                context.Logger.LogTrace(SR.GetResourceString(SR.ID6013), context.TokenType, context.Token, principal.Claims);

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the token payload to the token entry.
        /// Note: this handler is not used when token storage is disabled.
        /// </summary>
        public sealed class AttachTokenPayload : IOpenIddictClientHandler<GenerateTokenContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public AttachTokenPayload() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0318));

            public AttachTokenPayload(IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager ?? throw new ArgumentNullException(nameof(tokenManager));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<GenerateTokenContext>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .AddFilter<RequireTokenPayloadPersisted>()
                    .UseScopedHandler<AttachTokenPayload>()
                    .SetOrder(GenerateIdentityModelToken.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(GenerateTokenContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var identifier = context.Principal.GetTokenId();
                if (string.IsNullOrEmpty(identifier))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0009));
                }

                var token = await _tokenManager.FindByIdAsync(identifier) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0021));

                var descriptor = new OpenIddictTokenDescriptor();
                await _tokenManager.PopulateAsync(descriptor, token);

                // Attach the generated token to the token entry.
                descriptor.Payload = context.Token;
                descriptor.Principal = context.Principal;

                if (context.IsReferenceToken)
                {
                    descriptor.ReferenceId = Base64UrlEncoder.Encode(OpenIddictHelpers.CreateRandomArray(size: 256));
                }

                await _tokenManager.UpdateAsync(token, descriptor);

                context.Logger.LogTrace(SR.GetResourceString(SR.ID6014), context.Token, identifier, context.TokenType);

                // Replace the returned token by the reference identifier, if applicable.
                if (context.IsReferenceToken)
                {
                    context.Token = descriptor.ReferenceId;
                    context.Logger.LogTrace(SR.GetResourceString(SR.ID6015), descriptor.ReferenceId, identifier, context.TokenType);
                }
            }
        }
    }
}
