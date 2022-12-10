/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics;
using System.Globalization;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Extensions;

namespace OpenIddict.Server;

public static partial class OpenIddictServerHandlers
{
    public static class Protection
    {
        public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Token validation:
             */
            ResolveTokenValidationParameters.Descriptor,
            ValidateReferenceTokenIdentifier.Descriptor,
            ValidateIdentityModelToken.Descriptor,
            NormalizeScopeClaims.Descriptor,
            MapInternalClaims.Descriptor,
            RestoreReferenceTokenProperties.Descriptor,
            ValidatePrincipal.Descriptor,
            ValidateExpirationDate.Descriptor,
            ValidateTokenEntry.Descriptor,
            ValidateAuthorizationEntry.Descriptor,

            /*
            * Token generation:
            */
            AttachSecurityCredentials.Descriptor,
            CreateTokenEntry.Descriptor,
            GenerateIdentityModelToken.Descriptor,
            ConvertReferenceToken.Descriptor,
            BeautifyToken.Descriptor);

        /// <summary>
        /// Contains the logic responsible for resolving the validation parameters used to validate tokens.
        /// </summary>
        public sealed class ResolveTokenValidationParameters : IOpenIddictServerHandler<ValidateTokenContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .UseSingletonHandler<ResolveTokenValidationParameters>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateTokenContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var parameters = context.Options.TokenValidationParameters.Clone();

                parameters.ValidIssuers ??= (context.Options.Issuer ?? context.BaseUri) switch
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

                parameters.ValidTypes = context.ValidTokenTypes.Count switch
                {
                    // If no specific token type is expected, accept all token types at this stage.
                    // Additional filtering can be made based on the resolved/actual token type.
                    0 => null,

                    // Otherwise, map the token types to their JWT public or internal representation.
                    _ => context.ValidTokenTypes.SelectMany(type => type switch
                    {
                        // For access tokens, both "at+jwt" and "application/at+jwt" are valid.
                        TokenTypeHints.AccessToken => new[]
                        {
                            JsonWebTokenTypes.AccessToken,
                            JsonWebTokenTypes.Prefixes.Application + JsonWebTokenTypes.AccessToken
                        },

                        // For identity tokens, both "JWT" and "application/jwt" are valid.
                        TokenTypeHints.IdToken => new[]
                        {
                            JsonWebTokenTypes.Jwt,
                            JsonWebTokenTypes.Prefixes.Application + JsonWebTokenTypes.Jwt
                        },

                        // For authorization codes, only the short "oi_auc+jwt" form is valid.
                        TokenTypeHints.AuthorizationCode => new[] { JsonWebTokenTypes.Private.AuthorizationCode },

                        // For device codes, only the short "oi_dvc+jwt" form is valid.
                        TokenTypeHints.DeviceCode => new[] { JsonWebTokenTypes.Private.DeviceCode },

                        // For refresh tokens, only the short "oi_reft+jwt" form is valid.
                        TokenTypeHints.RefreshToken => new[] { JsonWebTokenTypes.Private.RefreshToken },

                        // For user codes, only the short "oi_usrc+jwt" form is valid.
                        TokenTypeHints.UserCode => new[] { JsonWebTokenTypes.Private.UserCode },

                        _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0003))
                    })
                };

                context.SecurityTokenHandler = context.Options.JsonWebTokenHandler;
                context.TokenValidationParameters = parameters;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating reference token identifiers.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public sealed class ValidateReferenceTokenIdentifier : IOpenIddictServerHandler<ValidateTokenContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public ValidateReferenceTokenIdentifier() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public ValidateReferenceTokenIdentifier(IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager ?? throw new ArgumentNullException(nameof(tokenManager));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .UseScopedHandler<ValidateReferenceTokenIdentifier>()
                    .SetOrder(ResolveTokenValidationParameters.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            public async ValueTask HandleAsync(ValidateTokenContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var token = context.Token.Length switch
                {
                    // 12 may correspond to a normalized user code and 43 to any
                    // other base64url-encoded 256-bit reference token identifier.
                    12 or 43 => await _tokenManager.FindByReferenceIdAsync(context.Token),

                    // A value higher than 12 (but lower than 50) may correspond to a user code
                    // containing dashes or any other non-digit character added by the end user.
                    // In this case, normalize the reference identifier before making the database lookup.
                    > 12 and < 50 => await _tokenManager.FindByReferenceIdAsync(NormalizeUserCode(context.Token)),

                    // If the token length differs, the token cannot be a reference token.
                    _ => null
                };

                // If the reference token cannot be found, don't return an error to allow another handler to validate it.
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
                        description: context.ValidTokenTypes.Count switch
                        {
                            1 when context.ValidTokenTypes.Contains(TokenTypeHints.AuthorizationCode)
                                => SR.GetResourceString(SR.ID2001),
                            1 when context.ValidTokenTypes.Contains(TokenTypeHints.DeviceCode)
                                => SR.GetResourceString(SR.ID2002),
                            1 when context.ValidTokenTypes.Contains(TokenTypeHints.RefreshToken)
                                => SR.GetResourceString(SR.ID2003),

                            _ => SR.GetResourceString(SR.ID2004)
                        },
                        uri: context.ValidTokenTypes.Count switch
                        {
                            1 when context.ValidTokenTypes.Contains(TokenTypeHints.AuthorizationCode)
                                => SR.FormatID8000(SR.ID2001),
                            1 when context.ValidTokenTypes.Contains(TokenTypeHints.DeviceCode)
                                => SR.FormatID8000(SR.ID2002),
                            1 when context.ValidTokenTypes.Contains(TokenTypeHints.RefreshToken)
                                => SR.FormatID8000(SR.ID2003),

                            _ => SR.FormatID8000(SR.ID2004),
                        });

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
                context.Token = payload;
                context.TokenId = await _tokenManager.GetIdAsync(token);

                // Note: unlike other tokens, user codes may be potentially entered manually by users in a web form.
                // To make that easier, user codes are generally "beautified" by adding intermediate dashes to
                // make them easier to read and type. Since these additional characters are not part of the original
                // user codes, non-digit characters are filtered from the reference identifier using this local method.
                static string NormalizeUserCode(string token)
                {
                    var builder = new StringBuilder(token);
                    for (var index = builder.Length - 1; index >= 0; index--)
                    {
                        var character = builder[index];
                        if (character < '0' || character > '9')
                        {
                            builder.Remove(index, 1);
                        }
                    }

                    return builder.ToString();
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating tokens generated using IdentityModel.
        /// </summary>
        public sealed class ValidateIdentityModelToken : IOpenIddictServerHandler<ValidateTokenContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .UseSingletonHandler<ValidateIdentityModelToken>()
                    .SetOrder(ValidateReferenceTokenIdentifier.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
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

                // Special endpoints like introspection or revocation use a single parameter to convey
                // multiple types of tokens (typically but not limited to access and refresh tokens).
                //
                // To speed up the token resolution process, the client can send a "token_type_hint"
                // containing the type of the token: if the parameter doesn't match the actual type,
                // the authorization server MUST use a fallback mechanism to determine whether the
                // token can be introspected or revoked even if it's of a different type.
                //
                // This logic is not used by OpenIddict for IdentityModel tokens, as processing
                // tokens of different type doesn't require re-parsing and re-validating them
                // multiple times. As such, the "token_type_hint" parameter is only used in the
                // Data Protection integration package and is ignored for IdentityModel tokens.
                //
                // For more information, see https://datatracker.ietf.org/doc/html/rfc7009#section-2.1
                // and https://datatracker.ietf.org/doc/html/rfc7662#section-2.1.

                var result = await context.SecurityTokenHandler.ValidateTokenAsync(context.Token, context.TokenValidationParameters);
                if (!result.IsValid)
                {
                    context.Logger.LogTrace(result.Exception, SR.GetResourceString(SR.ID6000), context.Token);

                    context.Reject(
                        error: Errors.InvalidToken,
                        description: result.Exception switch
                        {
                            SecurityTokenInvalidTypeException => context.ValidTokenTypes.Count switch
                            {
                                1 when context.ValidTokenTypes.Contains(TokenTypeHints.AuthorizationCode)
                                    => SR.GetResourceString(SR.ID2005),

                                1 when context.ValidTokenTypes.Contains(TokenTypeHints.DeviceCode)
                                    => SR.GetResourceString(SR.ID2006),

                                1 when context.ValidTokenTypes.Contains(TokenTypeHints.RefreshToken)
                                    => SR.GetResourceString(SR.ID2007),

                                1 when context.ValidTokenTypes.Contains(TokenTypeHints.AccessToken)
                                    => SR.GetResourceString(SR.ID2008),

                                _ => SR.GetResourceString(SR.ID2089)
                            },

                            SecurityTokenInvalidIssuerException        => SR.GetResourceString(SR.ID2088),
                            SecurityTokenSignatureKeyNotFoundException => SR.GetResourceString(SR.ID2090),
                            SecurityTokenInvalidSignatureException     => SR.GetResourceString(SR.ID2091),

                            _ => SR.GetResourceString(SR.ID2004)
                        },
                        uri: result.Exception switch
                        {
                            SecurityTokenInvalidTypeException => context.ValidTokenTypes.Count switch
                            {
                                1 when context.ValidTokenTypes.Contains(TokenTypeHints.AuthorizationCode)
                                    => SR.FormatID8000(SR.ID2005),

                                1 when context.ValidTokenTypes.Contains(TokenTypeHints.DeviceCode)
                                    => SR.FormatID8000(SR.ID2006),

                                1 when context.ValidTokenTypes.Contains(TokenTypeHints.RefreshToken)
                                    => SR.FormatID8000(SR.ID2007),

                                1 when context.ValidTokenTypes.Contains(TokenTypeHints.AccessToken)
                                    => SR.FormatID8000(SR.ID2008),

                                _ => SR.FormatID8000(SR.ID2089)
                            },

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

                // Attach the principal extracted from the token to the parent event context and store
                // the token type (resolved from "typ" or "token_usage") as a special private claim.
                context.Principal = new ClaimsPrincipal(result.ClaimsIdentity).SetTokenType(result.TokenType switch
                {
                    null or { Length: 0 } => throw new InvalidOperationException(SR.GetResourceString(SR.ID0025)),

                    // Both at+jwt and application/at+jwt are supported for access tokens.
                    JsonWebTokenTypes.AccessToken or JsonWebTokenTypes.Prefixes.Application + JsonWebTokenTypes.AccessToken
                        => TokenTypeHints.AccessToken,

                    // Both JWT and application/JWT are supported for identity tokens.
                    JsonWebTokenTypes.Jwt or JsonWebTokenTypes.Prefixes.Application + JsonWebTokenTypes.Jwt
                        => TokenTypeHints.IdToken,

                    JsonWebTokenTypes.Private.AuthorizationCode => TokenTypeHints.AuthorizationCode,
                    JsonWebTokenTypes.Private.DeviceCode        => TokenTypeHints.DeviceCode,
                    JsonWebTokenTypes.Private.RefreshToken      => TokenTypeHints.RefreshToken,
                    JsonWebTokenTypes.Private.UserCode          => TokenTypeHints.UserCode,

                    _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0003))
                });

                // Restore the claim destinations from the special oi_cl_dstn claim (represented as a dictionary/JSON object).
                if (token.TryGetPayloadValue(Claims.Private.ClaimDestinationsMap, out ImmutableDictionary<string, string[]> destinations))
                {
                    context.Principal.SetDestinations(destinations);
                }

                context.Logger.LogTrace(SR.GetResourceString(SR.ID6001), context.Token, context.Principal.Claims);
            }
        }

        /// <summary>
        /// Contains the logic responsible for normalizing the scope claims stored in the tokens.
        /// </summary>
        public sealed class NormalizeScopeClaims : IOpenIddictServerHandler<ValidateTokenContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .UseSingletonHandler<NormalizeScopeClaims>()
                    .SetOrder(ValidateIdentityModelToken.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
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
                    return default;
                }

                // Note: in previous OpenIddict versions, scopes were represented as a JSON array
                // and deserialized as multiple claims. In OpenIddict 3.0, the public "scope" claim
                // is formatted as a unique space-separated string containing all the granted scopes.
                // To ensure access tokens generated by previous versions are still correctly handled,
                // both formats (unique space-separated string or multiple scope claims) must be supported.
                // To achieve that, all the "scope" claims are combined into a single one containg all the values.
                // Visit https://datatracker.ietf.org/doc/html/rfc9068 for more information.
                var scopes = context.Principal.GetClaims(Claims.Scope);
                if (scopes.Length > 1)
                {
                    context.Principal.SetClaim(Claims.Scope, string.Join(" ", scopes));
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for mapping internal claims used by OpenIddict.
        /// </summary>
        public sealed class MapInternalClaims : IOpenIddictServerHandler<ValidateTokenContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .UseSingletonHandler<MapInternalClaims>()
                    .SetOrder(NormalizeScopeClaims.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
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
                    return default;
                }

                // To reduce the size of tokens, some of the private claims used by OpenIddict
                // are mapped to their standard equivalent before being removed from the token.
                // This handler is responsible for adding back the private claims to the principal
                // when receiving the token (e.g "oi_prst" is resolved from the "scope" claim).

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

                // In OpenIddict 3.0, the audiences allowed to receive a token are stored in "oi_aud".
                // If no such claim exists, try to infer them from the standard "aud" JWT claims.
                if (!context.Principal.HasClaim(Claims.Private.Audience))
                {
                    var audiences = context.Principal.GetClaims(Claims.Audience);
                    if (audiences.Any())
                    {
                        context.Principal.SetAudiences(audiences);
                    }
                }

                // In OpenIddict 3.0, the presenters allowed to use a token are stored in "oi_prst".
                // If no such claim exists, try to infer them from the standard "azp" and "client_id" JWT claims.
                //
                // Note: in previous OpenIddict versions, the presenters were represented in JWT tokens
                // using the "azp" claim (defined by OpenID Connect), for which a single value could be
                // specified. To ensure presenters stored in JWT tokens created by OpenIddict 1.x/2.x
                // can still be read with OpenIddict 3.0, the presenter is automatically inferred from
                // the "azp" or "client_id" claim if no "oi_prst" claim was found in the principal.
                if (!context.Principal.HasClaim(Claims.Private.Presenter))
                {
                    var presenter = context.Principal.GetClaim(Claims.AuthorizedParty) ??
                                    context.Principal.GetClaim(Claims.ClientId);

                    if (!string.IsNullOrEmpty(presenter))
                    {
                        context.Principal.SetPresenters(presenter);
                    }
                }

                // In OpenIddict 3.0, the scopes granted to an application are stored in "oi_scp".
                // If no such claim exists, try to infer them from the standard "scope" JWT claim,
                // which is guaranteed to be a unique space-separated claim containing all the values.
                if (!context.Principal.HasClaim(Claims.Private.Scope))
                {
                    var scope = context.Principal.GetClaim(Claims.Scope);
                    if (!string.IsNullOrEmpty(scope))
                    {
                        context.Principal.SetScopes(scope.Split(Separators.Space, StringSplitOptions.RemoveEmptyEntries));
                    }
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for restoring the properties associated with a reference token entry.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public sealed class RestoreReferenceTokenProperties : IOpenIddictServerHandler<ValidateTokenContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public RestoreReferenceTokenProperties() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public RestoreReferenceTokenProperties(IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager ?? throw new ArgumentNullException(nameof(tokenManager));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .UseScopedHandler<RestoreReferenceTokenProperties>()
                    .SetOrder(MapInternalClaims.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            public async ValueTask HandleAsync(ValidateTokenContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (context.Principal is null || string.IsNullOrEmpty(context.TokenId))
                {
                    return;
                }

                var token = await _tokenManager.FindByIdAsync(context.TokenId) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0021));

                // Restore the creation/expiration dates/identifiers from the token entry metadata.
                context.Principal.SetCreationDate(await _tokenManager.GetCreationDateAsync(token))
                                 .SetExpirationDate(await _tokenManager.GetExpirationDateAsync(token))
                                 .SetAuthorizationId(await _tokenManager.GetAuthorizationIdAsync(token))
                                 .SetTokenId(await _tokenManager.GetIdAsync(token))
                                 .SetTokenType(await _tokenManager.GetTypeAsync(token));
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting authentication demands for which no valid principal was resolved.
        /// </summary>
        public sealed class ValidatePrincipal : IOpenIddictServerHandler<ValidateTokenContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .UseSingletonHandler<ValidatePrincipal>()
                    .SetOrder(RestoreReferenceTokenProperties.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
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
                        description: context.ValidTokenTypes.Count switch
                        {
                            1 when context.ValidTokenTypes.Contains(TokenTypeHints.AuthorizationCode)
                                => SR.GetResourceString(SR.ID2001),
                            1 when context.ValidTokenTypes.Contains(TokenTypeHints.DeviceCode)
                                => SR.GetResourceString(SR.ID2002),
                            1 when context.ValidTokenTypes.Contains(TokenTypeHints.RefreshToken)
                                => SR.GetResourceString(SR.ID2003),
                            1 when context.ValidTokenTypes.Contains(TokenTypeHints.IdToken)
                                => SR.GetResourceString(SR.ID2009),

                            _ => SR.GetResourceString(SR.ID2004)
                        },
                        uri: context.ValidTokenTypes.Count switch
                        {
                            1 when context.ValidTokenTypes.Contains(TokenTypeHints.AuthorizationCode)
                                => SR.FormatID8000(SR.ID2001),
                            1 when context.ValidTokenTypes.Contains(TokenTypeHints.DeviceCode)
                                => SR.FormatID8000(SR.ID2002),
                            1 when context.ValidTokenTypes.Contains(TokenTypeHints.RefreshToken)
                                => SR.FormatID8000(SR.ID2003),
                            1 when context.ValidTokenTypes.Contains(TokenTypeHints.IdToken)
                                => SR.FormatID8000(SR.ID2009),

                            _ => SR.FormatID8000(SR.ID2004)
                        });


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
        public sealed class ValidateExpirationDate : IOpenIddictServerHandler<ValidateTokenContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .AddFilter<RequireTokenLifetimeValidationEnabled>()
                    .UseSingletonHandler<ValidateExpirationDate>()
                    .SetOrder(ValidatePrincipal.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
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
                        error: context.Principal.GetTokenType() switch
                        {
                            TokenTypeHints.DeviceCode => Errors.ExpiredToken,
                            _                         => Errors.InvalidToken
                        },
                        description: context.Principal.GetTokenType() switch
                        {
                            TokenTypeHints.AuthorizationCode => SR.GetResourceString(SR.ID2016),
                            TokenTypeHints.DeviceCode        => SR.GetResourceString(SR.ID2017),
                            TokenTypeHints.RefreshToken      => SR.GetResourceString(SR.ID2018),

                            _ => SR.GetResourceString(SR.ID2019)
                        },
                        uri: context.Principal.GetTokenType() switch
                        {
                            TokenTypeHints.AuthorizationCode => SR.FormatID8000(SR.ID2016),
                            TokenTypeHints.DeviceCode        => SR.FormatID8000(SR.ID2017),
                            TokenTypeHints.RefreshToken      => SR.FormatID8000(SR.ID2018),

                            _ => SR.FormatID8000(SR.ID2019)
                        });

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting authentication demands that
        /// use a token whose entry is no longer valid (e.g was revoked).
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public sealed class ValidateTokenEntry : IOpenIddictServerHandler<ValidateTokenContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public ValidateTokenEntry() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public ValidateTokenEntry(IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager ?? throw new ArgumentNullException(nameof(tokenManager));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .UseScopedHandler<ValidateTokenEntry>()
                    .SetOrder(ValidateExpirationDate.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            public async ValueTask HandleAsync(ValidateTokenContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

                // Extract the token identifier from the authentication principal.
                // If no token identifier can be found, this indicates that the token
                // has no backing database entry (e.g an access token or an identity token).
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
                        description: context.Principal.GetTokenType() switch
                        {
                            TokenTypeHints.AuthorizationCode => SR.GetResourceString(SR.ID2001),
                            TokenTypeHints.DeviceCode        => SR.GetResourceString(SR.ID2002),
                            TokenTypeHints.RefreshToken      => SR.GetResourceString(SR.ID2003),

                            _ => SR.GetResourceString(SR.ID2004)
                        },
                        uri: context.Principal.GetTokenType() switch
                        {
                            TokenTypeHints.AuthorizationCode => SR.FormatID8000(SR.ID2001),
                            TokenTypeHints.DeviceCode        => SR.FormatID8000(SR.ID2002),
                            TokenTypeHints.RefreshToken      => SR.FormatID8000(SR.ID2003),

                            _ => SR.FormatID8000(SR.ID2004)
                        });

                    return;
                }

                // If the token is already marked as redeemed, this may indicate that it was compromised.
                // In this case, revoke the entire chain of tokens associated with the authorization.
                // Special logic is used to avoid revoking refresh tokens already marked as redeemed to allow for a small leeway.
                // Note: the authorization itself is not revoked to allow the legitimate client to start a new flow.
                // See https://tools.ietf.org/html/rfc6749#section-10.5 for more information.
                if (await _tokenManager.HasStatusAsync(token, Statuses.Redeemed))
                {
                    if (!context.Principal.HasTokenType(TokenTypeHints.RefreshToken) || !await IsReusableAsync(token))
                    {
                        context.Logger.LogInformation(SR.GetResourceString(SR.ID6002), identifier);

                        context.Reject(
                            error: Errors.InvalidToken,
                            description: context.Principal.GetTokenType() switch
                            {
                                TokenTypeHints.AuthorizationCode => SR.GetResourceString(SR.ID2010),
                                TokenTypeHints.DeviceCode        => SR.GetResourceString(SR.ID2011),
                                TokenTypeHints.RefreshToken      => SR.GetResourceString(SR.ID2012),

                                _ => SR.GetResourceString(SR.ID2013)
                            },
                            uri: context.Principal.GetTokenType() switch
                            {
                                TokenTypeHints.AuthorizationCode => SR.FormatID8000(SR.ID2010),
                                TokenTypeHints.DeviceCode        => SR.FormatID8000(SR.ID2011),
                                TokenTypeHints.RefreshToken      => SR.FormatID8000(SR.ID2012),

                                _ => SR.FormatID8000(SR.ID2013)
                            });

                        // Revoke all the token entries associated with the authorization.
                        await TryRevokeChainAsync(await _tokenManager.GetAuthorizationIdAsync(token));

                        return;
                    }

                    return;
                }

                // If the token is not marked as valid yet, return an authorization_pending error.
                if (await _tokenManager.HasStatusAsync(token, Statuses.Inactive))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6003), identifier);

                    context.Reject(
                        error: Errors.AuthorizationPending,
                        description: SR.GetResourceString(SR.ID2014),
                        uri: SR.FormatID8000(SR.ID2014));

                    return;
                }

                // If the token is marked as rejected, return an access_denied error.
                if (await _tokenManager.HasStatusAsync(token, Statuses.Rejected))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6004), identifier);

                    context.Reject(
                        error: Errors.AccessDenied,
                        description: SR.GetResourceString(SR.ID2015),
                        uri: SR.FormatID8000(SR.ID2015));

                    return;
                }

                if (!await _tokenManager.HasStatusAsync(token, Statuses.Valid))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6005), identifier);

                    context.Reject(
                        error: Errors.InvalidToken,
                        description: context.Principal.GetTokenType() switch
                        {
                            TokenTypeHints.AuthorizationCode => SR.GetResourceString(SR.ID2016),
                            TokenTypeHints.DeviceCode        => SR.GetResourceString(SR.ID2017),
                            TokenTypeHints.RefreshToken      => SR.GetResourceString(SR.ID2018),

                            _ => SR.GetResourceString(SR.ID2019)
                        },
                        uri: context.Principal.GetTokenType() switch
                        {
                            TokenTypeHints.AuthorizationCode => SR.FormatID8000(SR.ID2016),
                            TokenTypeHints.DeviceCode        => SR.FormatID8000(SR.ID2017),
                            TokenTypeHints.RefreshToken      => SR.FormatID8000(SR.ID2018),

                            _ => SR.FormatID8000(SR.ID2019)
                        });

                    return;
                }

                // Restore the creation/expiration dates/identifiers from the token entry metadata.
                context.Principal.SetCreationDate(await _tokenManager.GetCreationDateAsync(token))
                                 .SetExpirationDate(await _tokenManager.GetExpirationDateAsync(token))
                                 .SetAuthorizationId(await _tokenManager.GetAuthorizationIdAsync(token))
                                 .SetTokenId(await _tokenManager.GetIdAsync(token))
                                 .SetTokenType(await _tokenManager.GetTypeAsync(token));

                async ValueTask<bool> IsReusableAsync(object token)
                {
                    // If the reuse leeway was set to null, return false to indicate
                    // that the refresh token is already redeemed and cannot be reused.
                    if (context.Options.RefreshTokenReuseLeeway is null)
                    {
                        return false;
                    }

                    var date = await _tokenManager.GetRedemptionDateAsync(token);
                    if (date is null || DateTimeOffset.UtcNow < date + context.Options.RefreshTokenReuseLeeway)
                    {
                        return true;
                    }

                    return false;
                }

                async ValueTask TryRevokeChainAsync(string? identifier)
                {
                    if (string.IsNullOrEmpty(identifier))
                    {
                        return;
                    }

                    // Revoke all the token entries associated with the authorization,
                    // including the redeemed token that was used in the token request.
                    await foreach (var token in _tokenManager.FindByAuthorizationIdAsync(identifier))
                    {
                        await _tokenManager.TryRevokeAsync(token);
                    }
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for authentication demands a token whose
        /// associated authorization entry is no longer valid (e.g was revoked).
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public sealed class ValidateAuthorizationEntry : IOpenIddictServerHandler<ValidateTokenContext>
        {
            private readonly IOpenIddictAuthorizationManager _authorizationManager;

            public ValidateAuthorizationEntry() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public ValidateAuthorizationEntry(IOpenIddictAuthorizationManager authorizationManager)
                => _authorizationManager = authorizationManager ?? throw new ArgumentNullException(nameof(authorizationManager));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireAuthorizationStorageEnabled>()
                    .UseScopedHandler<ValidateAuthorizationEntry>()
                    .SetOrder(ValidateTokenEntry.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            public async ValueTask HandleAsync(ValidateTokenContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

                var identifier = context.Principal.GetAuthorizationId();
                if (string.IsNullOrEmpty(identifier))
                {
                    return;
                }

                var authorization = await _authorizationManager.FindByIdAsync(identifier);
                if (authorization is null || !await _authorizationManager.HasStatusAsync(authorization, Statuses.Valid))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6006), identifier);

                    context.Reject(
                        error: Errors.InvalidToken,
                        description: context.Principal.GetTokenType() switch
                        {
                            TokenTypeHints.AuthorizationCode => SR.GetResourceString(SR.ID2020),
                            TokenTypeHints.DeviceCode        => SR.GetResourceString(SR.ID2021),
                            TokenTypeHints.RefreshToken      => SR.GetResourceString(SR.ID2022),

                            _ => SR.GetResourceString(SR.ID2023)
                        },
                        uri: context.Principal.GetTokenType() switch
                        {
                            TokenTypeHints.AuthorizationCode => SR.FormatID8000(SR.ID2020),
                            TokenTypeHints.DeviceCode        => SR.FormatID8000(SR.ID2021),
                            TokenTypeHints.RefreshToken      => SR.FormatID8000(SR.ID2022),

                            _ => SR.FormatID8000(SR.ID2023)
                        });

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for resolving the signing and encryption credentials used to protect tokens.
        /// </summary>
        public sealed class AttachSecurityCredentials : IOpenIddictServerHandler<GenerateTokenContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<GenerateTokenContext>()
                    .UseSingletonHandler<AttachSecurityCredentials>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
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
                    // Note: unlike other tokens, encryption can be disabled for access tokens.
                    TokenTypeHints.AccessToken when context.Options.DisableAccessTokenEncryption => null,
                    TokenTypeHints.IdToken => null,

                    _ => context.Options.EncryptionCredentials.First()
                };

                context.SigningCredentials = context.TokenType switch
                {
                    // Note: unlike other tokens, identity tokens can only be signed using an asymmetric key
                    // as they are meant to be validated by clients using the public keys exposed by the server.
                    TokenTypeHints.IdToken => context.Options.SigningCredentials.First(credentials =>
                        credentials.Key is AsymmetricSecurityKey),

                    _ => context.Options.SigningCredentials.First()
                };

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for creating a token entry.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public sealed class CreateTokenEntry : IOpenIddictServerHandler<GenerateTokenContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;
            private readonly IOpenIddictTokenManager _tokenManager;

            public CreateTokenEntry() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public CreateTokenEntry(
                IOpenIddictApplicationManager applicationManager,
                IOpenIddictTokenManager tokenManager)
            {
                _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));
                _tokenManager = tokenManager ?? throw new ArgumentNullException(nameof(tokenManager));
            }

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<GenerateTokenContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .AddFilter<RequireTokenEntryCreated>()
                    .UseScopedHandler<CreateTokenEntry>()
                    .SetOrder(AttachSecurityCredentials.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
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
                    Type = context.TokenType
                };

                descriptor.Status = context.TokenType switch
                {
                    // When initially created, device codes are marked as inactive. When the user
                    // approves the authorization demand, the UpdateReferenceDeviceCodeEntry handler
                    // changes the status to "active" and attaches a new payload with the claims
                    // corresponding the user, which allows the client to redeem the device code.
                    TokenTypeHints.DeviceCode => Statuses.Inactive,

                    // For all other tokens, "valid" is the default status.
                    _ => Statuses.Valid
                };

                descriptor.Subject = context.TokenType switch
                {
                    // Device and user codes are not bound to a user, until authorization is granted.
                    TokenTypeHints.DeviceCode or TokenTypeHints.UserCode => null,

                    // For all other tokens, the subject is resolved from the principal.
                    _ => context.Principal.GetClaim(Claims.Subject)
                };

                // If the client application is known, associate it with the token.
                if (!string.IsNullOrEmpty(context.ClientId))
                {
                    var application = await _applicationManager.FindByClientIdAsync(context.ClientId) ??
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID0017));

                    descriptor.ApplicationId = await _applicationManager.GetIdAsync(application);
                }

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
        public sealed class GenerateIdentityModelToken : IOpenIddictServerHandler<GenerateTokenContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<GenerateTokenContext>()
                    .AddFilter<RequireJsonWebTokenFormat>()
                    .UseSingletonHandler<GenerateIdentityModelToken>()
                    .SetOrder(CreateTokenEntry.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
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

                    Claims.Private.Audience
                        when context.TokenType is TokenTypeHints.AccessToken or TokenTypeHints.IdToken => false,

                    Claims.Private.Scope when context.TokenType is TokenTypeHints.AccessToken => false,

                    _ => true
                });

                Debug.Assert(principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

                var claims = new Dictionary<string, object>(StringComparer.Ordinal);

                // For access and identity tokens, set the public audience claims
                // using the private audience claims from the security principal.
                if (context.TokenType is TokenTypeHints.AccessToken or TokenTypeHints.IdToken)
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

                // For access tokens, set the public scope claim using the private scope
                // claims from the principal and add a jti claim containing a random identifier
                // (separate from the token identifier used by OpenIddict to attach a database
                // entry to the token) that can be used by the resource servers to determine
                // whether an access token has already been used or blacklist them if necessary.
                //
                // Note: scopes are deliberately formatted as a single space-separated 
                // string to respect the usual representation of the standard scope claim.
                //
                // See https://datatracker.ietf.org/doc/html/rfc9068 for more information.
                if (context.TokenType is TokenTypeHints.AccessToken)
                {
                    var scopes = context.Principal.GetScopes();
                    if (scopes.Any())
                    {
                        claims.Add(Claims.Scope, string.Join(" ", scopes));
                    }

                    claims.Add(Claims.JwtId, Guid.NewGuid().ToString());
                }

                // For authorization/device/user codes and refresh tokens,
                // attach claims destinations to the JWT claims collection.
                if (context.TokenType is TokenTypeHints.AuthorizationCode or TokenTypeHints.DeviceCode or 
                                         TokenTypeHints.RefreshToken      or TokenTypeHints.UserCode)
                {
                    var destinations = principal.GetDestinations();
                    if (destinations.Count is not 0)
                    {
                        claims.Add(Claims.Private.ClaimDestinationsMap, destinations);
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

                        TokenTypeHints.AccessToken       => JsonWebTokenTypes.AccessToken,
                        TokenTypeHints.IdToken           => JsonWebTokenTypes.Jwt,
                        TokenTypeHints.AuthorizationCode => JsonWebTokenTypes.Private.AuthorizationCode,
                        TokenTypeHints.DeviceCode        => JsonWebTokenTypes.Private.DeviceCode,
                        TokenTypeHints.RefreshToken      => JsonWebTokenTypes.Private.RefreshToken,
                        TokenTypeHints.UserCode          => JsonWebTokenTypes.Private.UserCode,

                        _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0003))
                    }
                };

                context.Token = context.SecurityTokenHandler.CreateToken(descriptor);

                context.Logger.LogTrace(SR.GetResourceString(SR.ID6013), context.TokenType, context.Token, principal.Claims);

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for converting the token to a reference token.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public sealed class ConvertReferenceToken : IOpenIddictServerHandler<GenerateTokenContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public ConvertReferenceToken() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public ConvertReferenceToken(IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager ?? throw new ArgumentNullException(nameof(tokenManager));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<GenerateTokenContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .AddFilter<RequireTokenPayloadPersisted>()
                    .UseScopedHandler<ConvertReferenceToken>()
                    .SetOrder(GenerateIdentityModelToken.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
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

                if (context.TokenType is TokenTypeHints.UserCode)
                {
                    do
                    {
                        // Note: unlike other reference tokens, user codes are meant to be used by humans,
                        // who may have to enter it in a web form. To ensure it remains easy enough to type
                        // even by users with non-Latin keyboards, user codes generated by OpenIddict are
                        // only compound of 12 digits, generated using a crypto-secure random number generator.
                        // In this case, the resulting user code is estimated to have at most ~40 bits of entropy.

                        static string CreateRandomNumericCode(int length) => OpenIddictHelpers.CreateRandomString(
                            charset: stackalloc[] { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' },
                            length: length);

                        descriptor.ReferenceId = CreateRandomNumericCode(length: 12);
                    }

                    // User codes are relatively short. To help reduce the risks of collisions with
                    // existing entries, a database check is performed here before updating the entry.
                    while (await _tokenManager.FindByReferenceIdAsync(descriptor.ReferenceId) is not null);
                }

                else
                {
                    // For other tokens, generate a base64url-encoded 256-bit random identifier.
                    descriptor.ReferenceId = Base64UrlEncoder.Encode(OpenIddictHelpers.CreateRandomArray(size: 256));
                }

                await _tokenManager.UpdateAsync(token, descriptor);

                // Replace the returned token by the reference identifier.
                context.Token = descriptor.ReferenceId;

                context.Logger.LogTrace(SR.GetResourceString(SR.ID6014), context.TokenType, identifier, descriptor.ReferenceId);
            }
        }

        /// <summary>
        /// Contains the logic responsible for beautifying user-typed tokens.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public sealed class BeautifyToken : IOpenIddictServerHandler<GenerateTokenContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<GenerateTokenContext>()
                    // Technically, this handler doesn't require that the degraded mode be disabled
                    // but the default CreateReferenceEntry handler that creates the user code
                    // reference identifiers only works when the degraded mode is disabled.
                    .AddFilter<RequireDegradedModeDisabled>()
                    .UseSingletonHandler<BeautifyToken>()
                    .SetOrder(ConvertReferenceToken.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(GenerateTokenContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // To make user codes easier to read and type by humans, a dash is automatically
                // appended before each new block of 4 integers. These dashes are expected to be
                // stripped from the user codes when receiving them at the verification endpoint.
                if (context.TokenType is TokenTypeHints.UserCode)
                {
                    var builder = new StringBuilder(context.Token);
                    if (builder.Length % 4 != 0)
                    {
                        return default;
                    }

                    for (var index = builder.Length; index >= 0; index -= 4)
                    {
                        if (index != 0 && index != builder.Length)
                        {
                            builder.Insert(index, Separators.Dash[0]);
                        }
                    }

                    context.Token = builder.ToString();
                }

                return default;
            }
        }
    }
}
