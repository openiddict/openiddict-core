/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlerFilters;
using Properties = OpenIddict.Server.OpenIddictServerConstants.Properties;
using SR = OpenIddict.Abstractions.Resources.OpenIddictResources;

namespace OpenIddict.Server
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static partial class OpenIddictServerHandlers
    {
        public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Authentication processing:
             */
            ValidateAuthenticationDemand.Descriptor,
            ValidateTokenParameter.Descriptor,
            NormalizeUserCode.Descriptor,
            ValidateReferenceTokenIdentifier.Descriptor,
            ValidateIdentityModelToken.Descriptor,
            NormalizeScopeClaims.Descriptor,
            MapInternalClaims.Descriptor,
            RestoreReferenceTokenProperties.Descriptor,
            ValidatePrincipal.Descriptor,
            ValidateTokenEntry.Descriptor,
            ValidateAuthorizationEntry.Descriptor,
            ValidateExpirationDate.Descriptor,

            /*
             * Challenge processing:
             */
            ValidateChallengeDemand.Descriptor,
            AttachDefaultChallengeError.Descriptor,
            RejectDeviceCodeEntry.Descriptor,
            RejectUserCodeEntry.Descriptor,

            /*
            * Sign-in processing:
            */
            ValidateSignInDemand.Descriptor,
            RestoreInternalClaims.Descriptor,
            AttachDefaultScopes.Descriptor,
            AttachDefaultPresenters.Descriptor,
            InferResources.Descriptor,
            EvaluateReturnedTokens.Descriptor,
            AttachAuthorization.Descriptor,

            PrepareAccessTokenPrincipal.Descriptor,
            PrepareAuthorizationCodePrincipal.Descriptor,
            PrepareDeviceCodePrincipal.Descriptor,
            PrepareRefreshTokenPrincipal.Descriptor,
            PrepareIdentityTokenPrincipal.Descriptor,
            PrepareUserCodePrincipal.Descriptor,

            RedeemTokenEntry.Descriptor,
            RevokeExistingTokenEntries.Descriptor,
            ExtendRefreshTokenEntry.Descriptor,

            CreateAccessTokenEntry.Descriptor,
            GenerateIdentityModelAccessToken.Descriptor,
            ConvertReferenceAccessToken.Descriptor,

            CreateAuthorizationCodeEntry.Descriptor,
            GenerateIdentityModelAuthorizationCode.Descriptor,
            ConvertReferenceAuthorizationCode.Descriptor,

            CreateDeviceCodeEntry.Descriptor,
            GenerateIdentityModelDeviceCode.Descriptor,
            ConvertReferenceDeviceCode.Descriptor,
            UpdateReferenceDeviceCodeEntry.Descriptor,

            CreateRefreshTokenEntry.Descriptor,
            GenerateIdentityModelRefreshToken.Descriptor,
            ConvertReferenceRefreshToken.Descriptor,

            CreateUserCodeEntry.Descriptor,
            AttachDeviceCodeIdentifier.Descriptor,
            GenerateIdentityModelUserCode.Descriptor,
            ConvertReferenceUserCode.Descriptor,

            AttachTokenDigests.Descriptor,
            CreateIdentityTokenEntry.Descriptor,
            GenerateIdentityModelIdentityToken.Descriptor,

            BeautifyUserCode.Descriptor,
            AttachAccessTokenProperties.Descriptor,
            AttachDeviceCodeProperties.Descriptor,

            /*
             * Sign-out processing:
             */
            ValidateSignOutDemand.Descriptor)

            .AddRange(Authentication.DefaultHandlers)
            .AddRange(Device.DefaultHandlers)
            .AddRange(Discovery.DefaultHandlers)
            .AddRange(Exchange.DefaultHandlers)
            .AddRange(Introspection.DefaultHandlers)
            .AddRange(Revocation.DefaultHandlers)
            .AddRange(Session.DefaultHandlers)
            .AddRange(Userinfo.DefaultHandlers);

        /// <summary>
        /// Contains the logic responsible of rejecting authentication demands made from unsupported endpoints.
        /// </summary>
        public class ValidateAuthenticationDemand : IOpenIddictServerHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .UseSingletonHandler<ValidateAuthenticationDemand>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessAuthenticationContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                switch (context.EndpointType)
                {
                    case OpenIddictServerEndpointType.Authorization:
                    case OpenIddictServerEndpointType.Introspection:
                    case OpenIddictServerEndpointType.Logout:
                    case OpenIddictServerEndpointType.Revocation:
                    case OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType():
                    case OpenIddictServerEndpointType.Token when context.Request.IsDeviceCodeGrantType():
                    case OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType():
                    case OpenIddictServerEndpointType.Userinfo:
                    case OpenIddictServerEndpointType.Verification:
                        return default;

                    case OpenIddictServerEndpointType.Token:
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID1000));

                    default: throw new InvalidOperationException(SR.GetResourceString(SR.ID1001));
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of resolving the token from the incoming request.
        /// </summary>
        public class ValidateTokenParameter : IOpenIddictServerHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .UseSingletonHandler<ValidateTokenParameter>()
                    .SetOrder(ValidateAuthenticationDemand.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessAuthenticationContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var (token, type) = context.EndpointType switch
                {
                    OpenIddictServerEndpointType.Authorization => (context.Request.IdTokenHint, TokenTypeHints.IdToken),
                    OpenIddictServerEndpointType.Logout        => (context.Request.IdTokenHint, TokenTypeHints.IdToken),

                    // Tokens received by the introspection and revocation endpoints can be of any type.
                    // Additional token type filtering is made by the endpoint themselves, if needed.
                    OpenIddictServerEndpointType.Introspection => (context.Request.Token, null),
                    OpenIddictServerEndpointType.Revocation    => (context.Request.Token, null),

                    OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType()
                        => (context.Request.Code, TokenTypeHints.AuthorizationCode),
                    OpenIddictServerEndpointType.Token when context.Request.IsDeviceCodeGrantType()
                        => (context.Request.DeviceCode, TokenTypeHints.DeviceCode),
                    OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                        => (context.Request.RefreshToken, TokenTypeHints.RefreshToken),

                    OpenIddictServerEndpointType.Userinfo => (context.Request.AccessToken, TokenTypeHints.AccessToken),

                    OpenIddictServerEndpointType.Verification => (context.Request.UserCode, TokenTypeHints.UserCode),

                    _ => (null, null)
                };

                if (string.IsNullOrEmpty(token))
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: context.Localizer[SR.ID3000]);

                    return default;
                }

                context.Token = token;
                context.TokenType = type;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of normalizing user codes.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class NormalizeUserCode : IOpenIddictServerHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    // Technically, this handler doesn't require that the degraded mode be disabled
                    // but the default CreateReferenceUserCodeEntry that creates the user code
                    // reference identifiers only works when the degraded mode is disabled.
                    .AddFilter<RequireDegradedModeDisabled>()
                    .UseSingletonHandler<NormalizeUserCode>()
                    .SetOrder(ValidateTokenParameter.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessAuthenticationContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (!string.Equals(context.TokenType, TokenTypeHints.UserCode, StringComparison.OrdinalIgnoreCase))
                {
                    return default;
                }

                // Note: unlike other tokens, user codes may be potentially entered manually by users in a web form.
                // To make that easier, user codes are generally "beautified" by adding intermediate dashes to
                // make them easier to read and type. Since these additional characters are not part of the original
                // user codes, non-digit characters are automatically filtered from the reference identifier.

                var builder = new StringBuilder(context.Token);
                for (var index = builder.Length - 1; index >= 0; index--)
                {
                    var character = builder[index];
                    if (character < '0' || character > '9')
                    {
                        builder.Remove(index, 1);
                    }
                }

                context.Token = builder.ToString();

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of validating reference token identifiers.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ValidateReferenceTokenIdentifier : IOpenIddictServerHandler<ProcessAuthenticationContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public ValidateReferenceTokenIdentifier() => throw new InvalidOperationException(SR.GetResourceString(SR.ID1015));

            public ValidateReferenceTokenIdentifier([NotNull] IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .UseScopedHandler<ValidateReferenceTokenIdentifier>()
                    .SetOrder(NormalizeUserCode.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            public async ValueTask HandleAsync([NotNull] ProcessAuthenticationContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Reference tokens are base64url-encoded payloads of exactly 256 bits,
                // except reference user codes, whose length is exactly 12 characters.
                // If the token length differs, the token cannot be a reference token.
                if (string.IsNullOrEmpty(context.Token) || (context.Token.Length != 12 && context.Token.Length != 43))
                {
                    return;
                }

                // If the reference token cannot be found, don't return an error to allow another handler to validate it.
                var token = await _tokenManager.FindByReferenceIdAsync(context.Token);
                if (token == null)
                {
                    return;
                }

                // If the type associated with the token entry doesn't match the expected type, return an error.
                if (!string.IsNullOrEmpty(context.TokenType) && !await _tokenManager.HasTypeAsync(token, context.TokenType))
                {
                    context.Reject(
                        error: context.EndpointType switch
                        {
                            OpenIddictServerEndpointType.Token => Errors.InvalidGrant,
                            _                                  => Errors.InvalidToken
                        },
                        description: context.EndpointType switch
                        {
                            OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType()
                                => context.Localizer[SR.ID3001],
                            OpenIddictServerEndpointType.Token when context.Request.IsDeviceCodeGrantType()
                                => context.Localizer[SR.ID3002],
                            OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                                => context.Localizer[SR.ID3003],

                            _ => context.Localizer[SR.ID3004]
                        });

                    return;
                }

                var payload = await _tokenManager.GetPayloadAsync(token);
                if (string.IsNullOrEmpty(payload))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1025));
                }

                // Replace the token parameter by the payload resolved from the token entry.
                context.Token = payload;

                // Store the identifier of the reference token in the transaction properties
                // so it can be later used to restore the properties associated with the token.
                context.Transaction.Properties[Properties.ReferenceTokenIdentifier] = await _tokenManager.GetIdAsync(token);
            }
        }

        /// <summary>
        /// Contains the logic responsible of validating tokens generated using IdentityModel.
        /// </summary>
        public class ValidateIdentityModelToken : IOpenIddictServerHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .UseSingletonHandler<ValidateIdentityModelToken>()
                    .SetOrder(ValidateReferenceTokenIdentifier.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessAuthenticationContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If a principal was already attached, don't overwrite it.
                if (context.Principal != null)
                {
                    return default;
                }

                // If the token cannot be read, don't return an error to allow another handler to validate it.
                if (!context.Options.JsonWebTokenHandler.CanReadToken(context.Token))
                {
                    return default;
                }

                var parameters = context.Options.TokenValidationParameters.Clone();
                parameters.ValidIssuer ??= context.Issuer?.AbsoluteUri;
                parameters.ValidateIssuer = !string.IsNullOrEmpty(parameters.ValidIssuer);
                parameters.ValidTypes = context.TokenType switch
                {
                    // If no specific token type is expected, accept all token types at this stage.
                    // Additional filtering can be made based on the resolved/actual token type.
                    var type when string.IsNullOrEmpty(type) => null,

                    // For access tokens, both "at+jwt" and "application/at+jwt" are valid.
                    TokenTypeHints.AccessToken => new[]
                    {
                        JsonWebTokenTypes.AccessToken,
                        JsonWebTokenTypes.Prefixes.Application + JsonWebTokenTypes.AccessToken
                    },

                    // For identity tokens, both "JWT" and "application/jwt" are valid.
                    TokenTypeHints.IdToken => new[]
                    {
                        JsonWebTokenTypes.IdentityToken,
                        JsonWebTokenTypes.Prefixes.Application + JsonWebTokenTypes.IdentityToken
                    },

                    // For authorization codes, only the short "oi_auc+jwt" form is valid.
                    TokenTypeHints.AuthorizationCode => new[] { JsonWebTokenTypes.Private.AuthorizationCode },

                    // For device codes, only the short "oi_dvc+jwt" form is valid.
                    TokenTypeHints.DeviceCode => new[] { JsonWebTokenTypes.Private.DeviceCode },

                    // For refresh tokens, only the short "oi_reft+jwt" form is valid.
                    TokenTypeHints.RefreshToken => new[] { JsonWebTokenTypes.Private.RefreshToken },

                    // For user codes, only the short "oi_usrc+jwt" form is valid.
                    TokenTypeHints.UserCode => new[] { JsonWebTokenTypes.Private.UserCode },

                    _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID1002))
                };

                var result = context.Options.JsonWebTokenHandler.ValidateToken(context.Token, parameters);
                if (!result.IsValid)
                {
                    context.Logger.LogTrace(result.Exception, SR.GetResourceString(SR.ID7000), context.Token);

                    context.Reject(
                        error: context.EndpointType switch
                        {
                            OpenIddictServerEndpointType.Token => Errors.InvalidGrant,
                            _                                  => Errors.InvalidToken
                        },
                        description: (result.Exception, context.EndpointType) switch
                        {
                            (SecurityTokenInvalidTypeException _, OpenIddictServerEndpointType.Token)
                                when context.Request.IsAuthorizationCodeGrantType() => context.Localizer[SR.ID3005],

                            (SecurityTokenInvalidTypeException _, OpenIddictServerEndpointType.Token)
                                when context.Request.IsDeviceCodeGrantType() => context.Localizer[SR.ID3006],

                            (SecurityTokenInvalidTypeException _, OpenIddictServerEndpointType.Token)
                                when context.Request.IsRefreshTokenGrantType() => context.Localizer[SR.ID3007],

                            (SecurityTokenInvalidTypeException _, OpenIddictServerEndpointType.Userinfo) => context.Localizer[SR.ID3008],

                            _ => context.Localizer[SR.ID3027]
                        });

                    return default;
                }

                // Get the JWT token. If the token is encrypted using JWE, retrieve the inner token.
                var token = (JsonWebToken) result.SecurityToken;
                if (token.InnerToken != null)
                {
                    token = token.InnerToken;
                }

                // Attach the principal extracted from the token to the parent event context.
                context.Principal = new ClaimsPrincipal(result.ClaimsIdentity);

                // Store the token type (resolved from "typ" or "token_usage") as a special private claim.
                context.Principal.SetTokenType(result.TokenType switch
                {
                    var type when string.IsNullOrEmpty(type) => throw new InvalidOperationException(SR.GetResourceString(SR.ID1024)),

                    JsonWebTokenTypes.AccessToken                                            => TokenTypeHints.AccessToken,
                    JsonWebTokenTypes.Prefixes.Application + JsonWebTokenTypes.AccessToken   => TokenTypeHints.AccessToken,

                    JsonWebTokenTypes.IdentityToken                                          => TokenTypeHints.IdToken,
                    JsonWebTokenTypes.Prefixes.Application + JsonWebTokenTypes.IdentityToken => TokenTypeHints.IdToken,

                    JsonWebTokenTypes.Private.AuthorizationCode => TokenTypeHints.AuthorizationCode,
                    JsonWebTokenTypes.Private.DeviceCode        => TokenTypeHints.DeviceCode,
                    JsonWebTokenTypes.Private.RefreshToken      => TokenTypeHints.RefreshToken,
                    JsonWebTokenTypes.Private.UserCode          => TokenTypeHints.UserCode,

                    _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID1002))
                });

                // Restore the claim destinations from the special oi_cl_dstn claim (represented as a dictionary/JSON object).
                if (token.TryGetPayloadValue(Claims.Private.ClaimDestinationsMap, out ImmutableDictionary<string, string[]> destinations))
                {
                    context.Principal.SetDestinations(destinations);
                }

                context.Logger.LogTrace(SR.GetResourceString(SR.ID7001), context.Token, context.Principal.Claims);

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of normalizing the scope claims stored in the tokens.
        /// </summary>
        public class NormalizeScopeClaims : IOpenIddictServerHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .UseSingletonHandler<NormalizeScopeClaims>()
                    .SetOrder(ValidateIdentityModelToken.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessAuthenticationContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (context.Principal == null)
                {
                    return default;
                }

                // Note: in previous OpenIddict versions, scopes were represented as a JSON array
                // and deserialized as multiple claims. In OpenIddict 3.0, the public "scope" claim
                // is formatted as a unique space-separated string containing all the granted scopes.
                // To ensure access tokens generated by previous versions are still correctly handled,
                // both formats (unique space-separated string or multiple scope claims) must be supported.
                // To achieve that, all the "scope" claims are combined into a single one containg all the values.
                // Visit https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-04 for more information.
                var scopes = context.Principal.GetClaims(Claims.Scope);
                if (scopes.Length > 1)
                {
                    context.Principal.SetClaim(Claims.Scope, string.Join(" ", scopes));
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of mapping internal claims used by OpenIddict.
        /// </summary>
        public class MapInternalClaims : IOpenIddictServerHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .UseSingletonHandler<MapInternalClaims>()
                    .SetOrder(NormalizeScopeClaims.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessAuthenticationContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (context.Principal == null)
                {
                    return default;
                }

                // To reduce the size of tokens, some of the private claims used by OpenIddict
                // are mapped to their standard equivalent before being removed from the token.
                // This handler is responsible of adding back the private claims to the principal
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
                if (!context.Principal.HasAudience())
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
                if (!context.Principal.HasPresenter())
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
                if (!context.Principal.HasScope())
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
        /// Contains the logic responsible of restoring the properties associated with a reference token entry.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class RestoreReferenceTokenProperties : IOpenIddictServerHandler<ProcessAuthenticationContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public RestoreReferenceTokenProperties() => throw new InvalidOperationException(SR.GetResourceString(SR.ID1015));

            public RestoreReferenceTokenProperties([NotNull] IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .UseScopedHandler<RestoreReferenceTokenProperties>()
                    .SetOrder(MapInternalClaims.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            public async ValueTask HandleAsync([NotNull] ProcessAuthenticationContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (context.Principal == null)
                {
                    return;
                }

                var identifier = context.Transaction.GetProperty<string>(Properties.ReferenceTokenIdentifier);
                if (string.IsNullOrEmpty(identifier))
                {
                    return;
                }

                var token = await _tokenManager.FindByIdAsync(identifier);
                if (token == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1020));
                }

                // Restore the creation/expiration dates/identifiers from the token entry metadata.
                context.Principal = context.Principal
                    .SetCreationDate(await _tokenManager.GetCreationDateAsync(token))
                    .SetExpirationDate(await _tokenManager.GetExpirationDateAsync(token))
                    .SetAuthorizationId(await _tokenManager.GetAuthorizationIdAsync(token))
                    .SetTokenId(await _tokenManager.GetIdAsync(token))
                    .SetTokenType(await _tokenManager.GetTypeAsync(token));
            }
        }

        /// <summary>
        /// Contains the logic responsible of rejecting authentication demands for which no valid principal was resolved.
        /// </summary>
        public class ValidatePrincipal : IOpenIddictServerHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .UseSingletonHandler<ValidatePrincipal>()
                    .SetOrder(RestoreReferenceTokenProperties.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessAuthenticationContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (context.Principal == null)
                {
                    context.Reject(
                        error: context.EndpointType switch
                        {
                            OpenIddictServerEndpointType.Token => Errors.InvalidGrant,
                            _                                  => Errors.InvalidToken
                        },
                        description: context.EndpointType switch
                        {
                            OpenIddictServerEndpointType.Authorization => context.Localizer[SR.ID3009],
                            OpenIddictServerEndpointType.Logout        => context.Localizer[SR.ID3009],

                            OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType()
                                => context.Localizer[SR.ID3001],
                            OpenIddictServerEndpointType.Token when context.Request.IsDeviceCodeGrantType()
                                => context.Localizer[SR.ID3002],
                            OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                                => context.Localizer[SR.ID3003],

                            _ => context.Localizer[SR.ID3004]
                        });


                    return default;
                }

                // When using JWT or Data Protection tokens, the correct token type is always enforced by IdentityModel
                // (using the "typ" header) or by ASP.NET Core Data Protection (using per-token-type purposes strings).
                // To ensure tokens deserialized using a custom routine are of the expected type, a manual check is used,
                // which requires that a special claim containing the token type be present in the security principal.
                if (!string.IsNullOrEmpty(context.TokenType))
                {
                    var type = context.Principal.GetTokenType();
                    if (string.IsNullOrEmpty(type))
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID1003));
                    }

                    if (!string.Equals(type, context.TokenType, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidOperationException(SR.FormatID1004(type, context.TokenType));
                    }
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of rejecting authentication demands that
        /// use a token whose entry is no longer valid (e.g was revoked).
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ValidateTokenEntry : IOpenIddictServerHandler<ProcessAuthenticationContext>
        {
            private readonly IOpenIddictAuthorizationManager _authorizationManager;
            private readonly IOpenIddictTokenManager _tokenManager;

            public ValidateTokenEntry() => throw new InvalidOperationException(SR.GetResourceString(SR.ID1015));

            public ValidateTokenEntry(
                [NotNull] IOpenIddictAuthorizationManager authorizationManager,
                [NotNull] IOpenIddictTokenManager tokenManager)
            {
                _authorizationManager = authorizationManager;
                _tokenManager = tokenManager;
            }

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .UseScopedHandler<ValidateTokenEntry>()
                    .SetOrder(ValidatePrincipal.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            public async ValueTask HandleAsync([NotNull] ProcessAuthenticationContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

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
                if (token == null)
                {
                    context.Reject(
                        error: context.EndpointType switch
                        {
                            OpenIddictServerEndpointType.Token => Errors.InvalidGrant,
                            _                                  => Errors.InvalidToken
                        },
                        description: context.EndpointType switch
                        {
                            OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType()
                                => context.Localizer[SR.ID3001],
                            OpenIddictServerEndpointType.Token when context.Request.IsDeviceCodeGrantType()
                                => context.Localizer[SR.ID3002],
                            OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                                => context.Localizer[SR.ID3003],

                            _ => context.Localizer[SR.ID3004]
                        });

                    return;
                }

                if (context.EndpointType == OpenIddictServerEndpointType.Token &&
                   (context.Request.IsAuthorizationCodeGrantType() ||
                    context.Request.IsDeviceCodeGrantType() ||
                    context.Request.IsRefreshTokenGrantType()))
                {
                    // If the authorization code/device code/refresh token is already marked as redeemed, this may indicate
                    // that it was compromised. In this case, revoke the authorization and all the associated tokens. 
                    // See https://tools.ietf.org/html/rfc6749#section-10.5 for more information.
                    if (await _tokenManager.HasStatusAsync(token, Statuses.Redeemed))
                    {
                        // First, mark the redeemed token submitted by the client as revoked.
                        await _tokenManager.TryRevokeAsync(token);

                        // Then, try to revoke the authorization and the associated token entries.
                        await TryRevokeAuthorizationChainAsync(context.Principal.GetAuthorizationId());

                        context.Logger.LogError(SR.GetResourceString(SR.ID7002), identifier);

                        context.Reject(
                            error: context.EndpointType switch
                            {
                                OpenIddictServerEndpointType.Token => Errors.InvalidGrant,
                                _                                  => Errors.InvalidToken
                            },
                            description: context.EndpointType switch
                            {
                                OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType()
                                    => context.Localizer[SR.ID3010],
                                OpenIddictServerEndpointType.Token when context.Request.IsDeviceCodeGrantType()
                                    => context.Localizer[SR.ID3011],
                                OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                                    => context.Localizer[SR.ID3012],

                                _ => context.Localizer[SR.ID3013]
                            });

                        return;
                    }

                    if (context.Request.IsDeviceCodeGrantType())
                    {
                        // If the device code is not marked as valid yet, return an authorization_pending error.
                        if (await _tokenManager.HasStatusAsync(token, Statuses.Inactive))
                        {
                            context.Logger.LogError(SR.GetResourceString(SR.ID7003), identifier);

                            context.Reject(
                                error: Errors.AuthorizationPending,
                                description: context.Localizer[SR.ID3014]);

                            return;
                        }

                        // If the device code is marked as rejected, return an authorization_pending error.
                        if (await _tokenManager.HasStatusAsync(token, Statuses.Rejected))
                        {
                            context.Logger.LogError(SR.GetResourceString(SR.ID7004), identifier);

                            context.Reject(
                                error: Errors.AccessDenied,
                                description: context.Localizer[SR.ID3015]);

                            return;
                        }
                    }
                }

                if (!await _tokenManager.HasStatusAsync(token, Statuses.Valid))
                {
                    context.Logger.LogError(SR.GetResourceString(SR.ID7005), identifier);

                    context.Reject(
                        error: context.EndpointType switch
                        {
                            OpenIddictServerEndpointType.Token => Errors.InvalidGrant,
                            _                                  => Errors.InvalidToken
                        },
                        description: context.EndpointType switch
                        {
                            OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType()
                                => context.Localizer[SR.ID3016],
                            OpenIddictServerEndpointType.Token when context.Request.IsDeviceCodeGrantType()
                                => context.Localizer[SR.ID3017],
                            OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                                => context.Localizer[SR.ID3018],

                            _ => context.Localizer[SR.ID3019]
                        });

                    return;
                }

                // Restore the creation/expiration dates/identifiers from the token entry metadata.
                context.Principal.SetCreationDate(await _tokenManager.GetCreationDateAsync(token))
                                 .SetExpirationDate(await _tokenManager.GetExpirationDateAsync(token))
                                 .SetAuthorizationId(await _tokenManager.GetAuthorizationIdAsync(token))
                                 .SetTokenId(await _tokenManager.GetIdAsync(token))
                                 .SetTokenType(await _tokenManager.GetTypeAsync(token));

                async ValueTask TryRevokeAuthorizationChainAsync(string identifier)
                {
                    if (context.Options.DisableAuthorizationStorage || string.IsNullOrEmpty(identifier))
                    {
                        return;
                    }

                    // Then, try to revoke the authorization and the associated token entries.

                    var authorization = await _authorizationManager.FindByIdAsync(identifier);
                    if (authorization != null)
                    {
                        await _authorizationManager.TryRevokeAsync(authorization);
                    }

                    await foreach (var token in _tokenManager.FindByAuthorizationIdAsync(identifier))
                    {
                        // Don't change the status of the token used in the token request.
                        if (string.Equals(context.Principal.GetTokenId(),
                            await _tokenManager.GetIdAsync(token), StringComparison.Ordinal))
                        {
                            continue;
                        }

                        await _tokenManager.TryRevokeAsync(token);
                    }
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of authentication demands a token whose
        /// associated authorization entry is no longer valid (e.g was revoked).
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ValidateAuthorizationEntry : IOpenIddictServerHandler<ProcessAuthenticationContext>
        {
            private readonly IOpenIddictAuthorizationManager _authorizationManager;

            public ValidateAuthorizationEntry() => throw new InvalidOperationException(SR.GetResourceString(SR.ID1015));

            public ValidateAuthorizationEntry([NotNull] IOpenIddictAuthorizationManager authorizationManager)
                => _authorizationManager = authorizationManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireAuthorizationStorageEnabled>()
                    .UseScopedHandler<ValidateAuthorizationEntry>()
                    .SetOrder(ValidateTokenEntry.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            public async ValueTask HandleAsync([NotNull] ProcessAuthenticationContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var identifier = context.Principal.GetAuthorizationId();
                if (string.IsNullOrEmpty(identifier))
                {
                    return;
                }

                var authorization = await _authorizationManager.FindByIdAsync(identifier);
                if (authorization == null || !await _authorizationManager.HasStatusAsync(authorization, Statuses.Valid))
                {
                    context.Logger.LogError(SR.GetResourceString(SR.ID7006), identifier);

                    context.Reject(
                        error: context.EndpointType switch
                        {
                            OpenIddictServerEndpointType.Token => Errors.InvalidGrant,
                            _                                  => Errors.InvalidToken
                        },
                        description: context.EndpointType switch
                        {
                            OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType()
                                => context.Localizer[SR.ID3020],
                            OpenIddictServerEndpointType.Token when context.Request.IsDeviceCodeGrantType()
                                => context.Localizer[SR.ID3021],
                            OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                                => context.Localizer[SR.ID3022],

                            _ => context.Localizer[SR.ID3023]
                        });

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of rejecting authentication demands that use an expired token.
        /// </summary>
        public class ValidateExpirationDate : IOpenIddictServerHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .UseSingletonHandler<ValidateExpirationDate>()
                    .SetOrder(ValidateTokenEntry.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessAuthenticationContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Don't validate the lifetime of id_tokens used as id_token_hints.
                switch (context.EndpointType)
                {
                    case OpenIddictServerEndpointType.Authorization:
                    case OpenIddictServerEndpointType.Logout:
                        return default;
                }

                var date = context.Principal.GetExpirationDate();
                if (date.HasValue && date.Value < DateTimeOffset.UtcNow)
                {
                    context.Reject(
                        error: context.EndpointType switch
                        {
                            OpenIddictServerEndpointType.Token when context.Request.IsDeviceCodeGrantType()
                                => Errors.ExpiredToken,

                            OpenIddictServerEndpointType.Token => Errors.InvalidGrant,

                            _ => Errors.InvalidToken
                        },
                        description: context.EndpointType switch
                        {
                            OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType()
                                => context.Localizer[SR.ID3016],
                            OpenIddictServerEndpointType.Token when context.Request.IsDeviceCodeGrantType()
                                => context.Localizer[SR.ID3017],
                            OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                                => context.Localizer[SR.ID3018],

                            _ => context.Localizer[SR.ID3019]
                        });

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of rejecting challenge demands made from unsupported endpoints.
        /// </summary>
        public class ValidateChallengeDemand : IOpenIddictServerHandler<ProcessChallengeContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                    .UseSingletonHandler<ValidateChallengeDemand>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessChallengeContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                switch (context.EndpointType)
                {
                    case OpenIddictServerEndpointType.Authorization:
                    case OpenIddictServerEndpointType.Token:
                    case OpenIddictServerEndpointType.Userinfo:
                    case OpenIddictServerEndpointType.Verification:
                        return default;

                    default: throw new InvalidOperationException(SR.GetResourceString(SR.ID1005));
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of ensuring that the challenge response contains an appropriate error.
        /// </summary>
        public class AttachDefaultChallengeError : IOpenIddictServerHandler<ProcessChallengeContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                    .UseSingletonHandler<AttachDefaultChallengeError>()
                    .SetOrder(ValidateChallengeDemand.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessChallengeContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                context.Response.Error ??= context.EndpointType switch
                {
                    OpenIddictServerEndpointType.Authorization => Errors.AccessDenied,
                    OpenIddictServerEndpointType.Token         => Errors.InvalidGrant,
                    OpenIddictServerEndpointType.Userinfo      => Errors.InsufficientAccess,
                    OpenIddictServerEndpointType.Verification  => Errors.AccessDenied,

                    _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID1005))
                };

                context.Response.ErrorDescription ??= context.EndpointType switch
                {
                    OpenIddictServerEndpointType.Authorization => context.Localizer[SR.ID3015],
                    OpenIddictServerEndpointType.Verification  => context.Localizer[SR.ID3015],
                    OpenIddictServerEndpointType.Token         => context.Localizer[SR.ID3024],
                    OpenIddictServerEndpointType.Userinfo      => context.Localizer[SR.ID3025],

                    _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID1005))
                };

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of rejecting the device code entry associated with the user code.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class RejectDeviceCodeEntry : IOpenIddictServerHandler<ProcessChallengeContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public RejectDeviceCodeEntry() => throw new InvalidOperationException(SR.GetResourceString(SR.ID1015));

            public RejectDeviceCodeEntry([NotNull] IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .UseScopedHandler<RejectDeviceCodeEntry>()
                    .SetOrder(AttachDefaultChallengeError.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async ValueTask HandleAsync([NotNull] ProcessChallengeContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (context.EndpointType != OpenIddictServerEndpointType.Verification)
                {
                    return;
                }

                var notification = context.Transaction.GetProperty<ProcessAuthenticationContext>(
                    typeof(ProcessAuthenticationContext).FullName) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1006));

                // Extract the device code identifier from the user code principal.
                var identifier = notification.Principal.GetClaim(Claims.Private.DeviceCodeId);
                if (string.IsNullOrEmpty(identifier))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1007));
                }

                var token = await _tokenManager.FindByIdAsync(identifier);
                if (token != null)
                {
                    await _tokenManager.TryRejectAsync(token);
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of rejecting the user code entry, if applicable.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class RejectUserCodeEntry : IOpenIddictServerHandler<ProcessChallengeContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public RejectUserCodeEntry() => throw new InvalidOperationException(SR.GetResourceString(SR.ID1015));

            public RejectUserCodeEntry([NotNull] IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .UseScopedHandler<RejectUserCodeEntry>()
                    .SetOrder(RejectDeviceCodeEntry.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async ValueTask HandleAsync([NotNull] ProcessChallengeContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (context.EndpointType != OpenIddictServerEndpointType.Verification)
                {
                    return;
                }

                var notification = context.Transaction.GetProperty<ProcessAuthenticationContext>(
                    typeof(ProcessAuthenticationContext).FullName) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1006));

                // Extract the device code identifier from the authentication principal.
                var identifier = notification.Principal.GetTokenId();
                if (string.IsNullOrEmpty(identifier))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1008));
                }

                var token = await _tokenManager.FindByIdAsync(identifier);
                if (token != null)
                {
                    await _tokenManager.TryRejectAsync(token);
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of ensuring that the sign-in demand
        /// is compatible with the type of the endpoint that handled the request.
        /// </summary>
        public class ValidateSignInDemand : IOpenIddictServerHandler<ProcessSignInContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .UseSingletonHandler<ValidateSignInDemand>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                switch (context.EndpointType)
                {
                    case OpenIddictServerEndpointType.Authorization:
                    case OpenIddictServerEndpointType.Device:
                    case OpenIddictServerEndpointType.Token:
                    case OpenIddictServerEndpointType.Verification:
                        break;

                    default: throw new InvalidOperationException(SR.GetResourceString(SR.ID1009));
                }

                if (context.Principal.Identity == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1010));
                }

                // Note: sign-in operations triggered from the device endpoint can't be associated to specific users
                // as users' identity is not known until they reach the verification endpoint and validate the user code.
                // As such, the principal used in this case cannot contain an authenticated identity or a subject claim.
                if (context.EndpointType == OpenIddictServerEndpointType.Device)
                {
                    if (context.Principal.Identity.IsAuthenticated)
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID1011));
                    }

                    if (!string.IsNullOrEmpty(context.Principal.GetClaim(Claims.Subject)))
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID1012));
                    }

                    return default;
                }

                if (!context.Principal.Identity.IsAuthenticated)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1013));
                }

                if (string.IsNullOrEmpty(context.Principal.GetClaim(Claims.Subject)))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1014));
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of re-attaching internal claims to the authentication principal.
        /// </summary>
        public class RestoreInternalClaims : IOpenIddictServerHandler<ProcessSignInContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .UseSingletonHandler<RestoreInternalClaims>()
                    .SetOrder(ValidateSignInDemand.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                switch (context.EndpointType)
                {
                    case OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType():
                    case OpenIddictServerEndpointType.Token when context.Request.IsDeviceCodeGrantType():
                    case OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType():
                    case OpenIddictServerEndpointType.Verification:
                        break;

                    default: return default;
                }

                var identity = (ClaimsIdentity) context.Principal.Identity;

                var notification = context.Transaction.GetProperty<ProcessAuthenticationContext>(
                    typeof(ProcessAuthenticationContext).FullName) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1006));

                // Restore the internal claims resolved from the authorization code/refresh token.
                foreach (var claims in notification.Principal.Claims
                    .Where(claim => claim.Type.StartsWith(Claims.Prefixes.Private))
                    .GroupBy(claim => claim.Type))
                {
                    // If the specified principal already contains one claim of the iterated type, ignore them.
                    if (context.Principal.Claims.Any(claim => claim.Type == claims.Key))
                    {
                        continue;
                    }

                    // When the request is a verification request, don't flow the scopes from the user code.
                    if (context.EndpointType == OpenIddictServerEndpointType.Verification &&
                        string.Equals(claims.Key, Claims.Private.Scope, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    identity.AddClaims(claims);
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of attaching default scopes to the authentication principal.
        /// </summary>
        public class AttachDefaultScopes : IOpenIddictServerHandler<ProcessSignInContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .UseSingletonHandler<AttachDefaultScopes>()
                    .SetOrder(RestoreInternalClaims.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Always include the "openid" scope when the developer doesn't explicitly call SetScopes.
                // Note: the application is allowed to specify a different "scopes": in this case,
                // don't replace the "scopes" property stored in the authentication ticket.
                if (!context.Principal.HasScope() && context.Request.HasScope(Scopes.OpenId))
                {
                    context.Principal.SetScopes(Scopes.OpenId);
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of attaching default presenters to the authentication principal.
        /// </summary>
        public class AttachDefaultPresenters : IOpenIddictServerHandler<ProcessSignInContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .UseSingletonHandler<AttachDefaultPresenters>()
                    .SetOrder(AttachDefaultScopes.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Add the validated client_id to the list of authorized presenters,
                // unless the presenters were explicitly set by the developer.
                if (!context.Principal.HasPresenter() && !string.IsNullOrEmpty(context.ClientId))
                {
                    context.Principal.SetPresenters(context.ClientId);
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of inferring resources from the audience claims if necessary.
        /// </summary>
        public class InferResources : IOpenIddictServerHandler<ProcessSignInContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .UseSingletonHandler<InferResources>()
                    .SetOrder(AttachDefaultPresenters.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // When a "resources" property cannot be found in the ticket, infer it from the "audiences" property.
                if (context.Principal.HasAudience() && !context.Principal.HasResource())
                {
                    context.Principal.SetResources(context.Principal.GetAudiences());
                }

                // Reset the audiences collection, as it's later set, based on the token type.
                context.Principal.SetAudiences(ImmutableArray.Create<string>());

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of selecting the token types returned to the client application.
        /// </summary>
        public class EvaluateReturnedTokens : IOpenIddictServerHandler<ProcessSignInContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .UseSingletonHandler<EvaluateReturnedTokens>()
                    .SetOrder(InferResources.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                context.IncludeAccessToken = context.EndpointType switch
                {
                    // For authorization requests, return an access token if a response type containing token was specified.
                    OpenIddictServerEndpointType.Authorization => context.Request.HasResponseType(ResponseTypes.Token),

                    // For token requests, always return an access token.
                    OpenIddictServerEndpointType.Token => true,

                    _ => false
                };

                context.IncludeAuthorizationCode = context.EndpointType switch
                {
                    // For authorization requests, return an authorization code if a response type containing code was specified.
                    OpenIddictServerEndpointType.Authorization => context.Request.HasResponseType(ResponseTypes.Code),

                    _ => false
                };

                context.IncludeDeviceCode = context.EndpointType switch
                {
                    // For device requests, always return a device code.
                    OpenIddictServerEndpointType.Device => true,

                    // Note: a device code is not directly returned by the verification endpoint (that generally
                    // returns an empty response or redirects the user agent to another page), but a device code
                    // must be generated to replace the payload of the device code initially returned to the client.
                    // In this case, the new device code is not returned as part of the response but persisted in the DB.
                    OpenIddictServerEndpointType.Verification => true,

                    _ => false
                };

                context.IncludeRefreshToken = context.EndpointType switch
                {
                    // For token requests, never return a refresh token if the offline_access scope was not granted.
                    OpenIddictServerEndpointType.Token when !context.Principal.HasScope(Scopes.OfflineAccess) => false,

                    // For grant_type=refresh_token token requests, only return a refresh token if rolling tokens are enabled.
                    OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                        => context.Options.UseRollingRefreshTokens,

                    // For token requests that don't meet the previous criteria, allow a refresh token to be returned.
                    OpenIddictServerEndpointType.Token => true,

                    _ => false
                };

                context.IncludeIdentityToken = context.EndpointType switch
                {
                    // For authorization requests, return an identity token if a response type containing code
                    // was specified and if the openid scope was explicitly or implicitly granted.
                    OpenIddictServerEndpointType.Authorization => context.Principal.HasScope(Scopes.OpenId) &&
                                                                  context.Request.HasResponseType(ResponseTypes.IdToken),

                    // For token requests, only return an identity token if the openid scope was granted.
                    OpenIddictServerEndpointType.Token => context.Principal.HasScope(Scopes.OpenId),

                    _ => false
                };

                context.IncludeUserCode = context.EndpointType switch
                {
                    // Only return a user code if the request is a device authorization request.
                    OpenIddictServerEndpointType.Device => true,

                    _ => false
                };

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of creating an ad-hoc authorization, if necessary.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class AttachAuthorization : IOpenIddictServerHandler<ProcessSignInContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;
            private readonly IOpenIddictAuthorizationManager _authorizationManager;

            public AttachAuthorization() => throw new InvalidOperationException(SR.GetResourceString(SR.ID1015));

            public AttachAuthorization(
                [NotNull] IOpenIddictApplicationManager applicationManager,
                [NotNull] IOpenIddictAuthorizationManager authorizationManager)
            {
                _applicationManager = applicationManager;
                _authorizationManager = authorizationManager;
            }

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireAuthorizationStorageEnabled>()
                    .UseScopedHandler<AttachAuthorization>()
                    .SetOrder(EvaluateReturnedTokens.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If no authorization code, device code or refresh token is returned, don't create an authorization.
                if (!context.IncludeAuthorizationCode && !context.IncludeDeviceCode && !context.IncludeRefreshToken)
                {
                    return;
                }

                // If an authorization identifier was explicitly specified, don't create an ad-hoc authorization.
                if (!string.IsNullOrEmpty(context.Principal.GetAuthorizationId()))
                {
                    return;
                }

                var descriptor = new OpenIddictAuthorizationDescriptor
                {
                    Principal = context.Principal,
                    Status = Statuses.Valid,
                    Subject = context.Principal.GetClaim(Claims.Subject),
                    Type = AuthorizationTypes.AdHoc
                };

                descriptor.Scopes.UnionWith(context.Principal.GetScopes());

                // If the client application is known, associate it to the authorization.
                if (!string.IsNullOrEmpty(context.Request.ClientId))
                {
                    var application = await _applicationManager.FindByClientIdAsync(context.Request.ClientId);
                    if (application == null)
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID1016));
                    }

                    descriptor.ApplicationId = await _applicationManager.GetIdAsync(application);
                }

                var authorization = await _authorizationManager.CreateAsync(descriptor);
                if (authorization == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1017));
                }

                var identifier = await _authorizationManager.GetIdAsync(authorization);

                if (string.IsNullOrEmpty(context.Request.ClientId))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID7007), identifier);
                }

                else
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID7008), context.Request.ClientId, identifier);
                }

                // Attach the unique identifier of the ad hoc authorization to the authentication principal
                // so that it is attached to all the derived tokens, allowing batched revocations support.
                context.Principal.SetAuthorizationId(identifier);
            }
        }

        /// <summary>
        /// Contains the logic responsible of preparing and attaching the claims principal
        /// used to generate the access token, if one is going to be returned.
        /// </summary>
        public class PrepareAccessTokenPrincipal : IOpenIddictServerHandler<ProcessSignInContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireAccessTokenIncluded>()
                    .UseSingletonHandler<PrepareAccessTokenPrincipal>()
                    .SetOrder(AttachAuthorization.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Create a new principal containing only the filtered claims.
                // Actors identities are also filtered (delegation scenarios).
                var principal = context.Principal.Clone(claim =>
                {
                    // Never exclude the subject and authorization identifier claims.
                    if (string.Equals(claim.Type, Claims.Subject, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.Private.AuthorizationId, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }

                    // Never exclude the presenters and scope private claims.
                    if (string.Equals(claim.Type, Claims.Private.Presenter, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.Private.Scope, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }

                    // Never include the public or internal token identifiers to ensure the identifiers
                    // that are automatically inherited from the parent token are not reused for the new token.
                    if (string.Equals(claim.Type, Claims.JwtId, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.Private.TokenId, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }

                    // Never include the creation and expiration dates that are automatically
                    // inherited from the parent token are not reused for the new token.
                    if (string.Equals(claim.Type, Claims.ExpiresAt, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.IssuedAt, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.NotBefore, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }

                    // Always exclude private claims, whose values must generally be kept secret.
                    if (claim.Type.StartsWith(Claims.Prefixes.Private, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }

                    // Claims whose destination is not explicitly referenced or doesn't
                    // contain "access_token" are not included in the access token.
                    if (!claim.HasDestination(Destinations.AccessToken))
                    {
                        context.Logger.LogDebug(SR.GetResourceString(SR.ID7009), claim.Type);

                        return false;
                    }

                    return true;
                });

                // Remove the destinations from the claim properties.
                foreach (var claim in principal.Claims)
                {
                    claim.Properties.Remove(OpenIddictConstants.Properties.Destinations);
                }

                principal.SetClaim(Claims.JwtId, Guid.NewGuid().ToString());
                principal.SetCreationDate(DateTimeOffset.UtcNow);

                var lifetime = context.Principal.GetAccessTokenLifetime() ?? context.Options.AccessTokenLifetime;
                if (lifetime.HasValue)
                {
                    principal.SetExpirationDate(principal.GetCreationDate() + lifetime.Value);
                }

                // Set the audiences based on the resource claims stored in the principal.
                principal.SetAudiences(context.Principal.GetResources());

                // Store the client identifier in the public client_id claim, if available.
                // See https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-04 for more information.
                principal.SetClaim(Claims.ClientId, context.ClientId);

                // When receiving a grant_type=refresh_token request, determine whether the client application
                // requests a limited set of scopes and immediately replace the scopes collection if necessary.
                if (context.EndpointType == OpenIddictServerEndpointType.Token &&
                    context.Request.IsRefreshTokenGrantType() && !string.IsNullOrEmpty(context.Request.Scope))
                {
                    var scopes = context.Request.GetScopes();
                    principal.SetScopes(scopes.Intersect(context.Principal.GetScopes()));

                    context.Logger.LogDebug(SR.GetResourceString(SR.ID7010), scopes);
                }

                context.AccessTokenPrincipal = principal;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of preparing and attaching the claims principal
        /// used to generate the authorization code, if one is going to be returned.
        /// </summary>
        public class PrepareAuthorizationCodePrincipal : IOpenIddictServerHandler<ProcessSignInContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireAuthorizationCodeIncluded>()
                    .UseSingletonHandler<PrepareAuthorizationCodePrincipal>()
                    .SetOrder(PrepareAccessTokenPrincipal.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Create a new principal containing only the filtered claims.
                // Actors identities are also filtered (delegation scenarios).
                var principal = context.Principal.Clone(claim =>
                {
                    // Never include the public or internal token identifiers to ensure the identifiers
                    // that are automatically inherited from the parent token are not reused for the new token.
                    if (string.Equals(claim.Type, Claims.JwtId, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.Private.TokenId, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }

                    // Never include the creation and expiration dates that are automatically
                    // inherited from the parent token are not reused for the new token.
                    if (string.Equals(claim.Type, Claims.ExpiresAt, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.IssuedAt, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.NotBefore, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }

                    // Other claims are always included in the authorization code, even private claims.
                    return true;
                });

                principal.SetClaim(Claims.JwtId, Guid.NewGuid().ToString());
                principal.SetCreationDate(DateTimeOffset.UtcNow);

                var lifetime = context.Principal.GetAuthorizationCodeLifetime() ?? context.Options.AuthorizationCodeLifetime;
                if (lifetime.HasValue)
                {
                    principal.SetExpirationDate(principal.GetCreationDate() + lifetime.Value);
                }

                // Attach the redirect_uri to allow for later comparison when
                // receiving a grant_type=authorization_code token request.
                principal.SetClaim(Claims.Private.RedirectUri, context.Request.RedirectUri);

                // Attach the code challenge and the code challenge methods to allow the ValidateCodeVerifier
                // handler to validate the code verifier sent by the client as part of the token request.
                if (!string.IsNullOrEmpty(context.Request.CodeChallenge))
                {
                    principal.SetClaim(Claims.Private.CodeChallenge, context.Request.CodeChallenge);

                    // Default to plain if no explicit code challenge method was specified.
                    principal.SetClaim(Claims.Private.CodeChallengeMethod,
                        !string.IsNullOrEmpty(context.Request.CodeChallengeMethod) ?
                        context.Request.CodeChallengeMethod : CodeChallengeMethods.Plain);
                }

                // Attach the nonce so that it can be later returned by
                // the token endpoint as part of the JWT identity token.
                principal.SetClaim(Claims.Private.Nonce, context.Request.Nonce);

                context.AuthorizationCodePrincipal = principal;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of preparing and attaching the claims principal
        /// used to generate the device code, if one is going to be returned.
        /// </summary>
        public class PrepareDeviceCodePrincipal : IOpenIddictServerHandler<ProcessSignInContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .UseSingletonHandler<PrepareDeviceCodePrincipal>()
                    .SetOrder(PrepareAuthorizationCodePrincipal.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Note: a device code principal is produced when a device code is included in the response or when a
                // device code entry is replaced when processing a sign-in response sent to the verification endpoint.
                if (context.EndpointType != OpenIddictServerEndpointType.Verification && !context.IncludeDeviceCode)
                {
                    return default;
                }

                // Create a new principal containing only the filtered claims.
                // Actors identities are also filtered (delegation scenarios).
                var principal = context.Principal.Clone(claim =>
                {
                    // Never include the public or internal token identifiers to ensure the identifiers
                    // that are automatically inherited from the parent token are not reused for the new token.
                    if (string.Equals(claim.Type, Claims.JwtId, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.Private.TokenId, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }

                    // Never include the creation and expiration dates that are automatically
                    // inherited from the parent token are not reused for the new token.
                    if (string.Equals(claim.Type, Claims.ExpiresAt, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.IssuedAt, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.NotBefore, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }

                    // Other claims are always included in the device code, even private claims.
                    return true;
                });

                principal.SetClaim(Claims.JwtId, Guid.NewGuid().ToString());
                principal.SetCreationDate(DateTimeOffset.UtcNow);

                var lifetime = context.Principal.GetDeviceCodeLifetime() ?? context.Options.DeviceCodeLifetime;
                if (lifetime.HasValue)
                {
                    principal.SetExpirationDate(principal.GetCreationDate() + lifetime.Value);
                }

                // Restore the device code internal token identifier from the principal
                // resolved from the user code used in the user code verification request.
                if (context.EndpointType == OpenIddictServerEndpointType.Verification)
                {
                    principal.SetClaim(Claims.Private.TokenId, context.Principal.GetClaim(Claims.Private.DeviceCodeId));
                }

                context.DeviceCodePrincipal = principal;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of preparing and attaching the claims principal
        /// used to generate the refresh token, if one is going to be returned.
        /// </summary>
        public class PrepareRefreshTokenPrincipal : IOpenIddictServerHandler<ProcessSignInContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireRefreshTokenIncluded>()
                    .UseSingletonHandler<PrepareRefreshTokenPrincipal>()
                    .SetOrder(PrepareDeviceCodePrincipal.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Create a new principal containing only the filtered claims.
                // Actors identities are also filtered (delegation scenarios).
                var principal = context.Principal.Clone(claim =>
                {
                    // Never include the public or internal token identifiers to ensure the identifiers
                    // that are automatically inherited from the parent token are not reused for the new token.
                    if (string.Equals(claim.Type, Claims.JwtId, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.Private.TokenId, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }

                    // Never include the creation and expiration dates that are automatically
                    // inherited from the parent token are not reused for the new token.
                    if (string.Equals(claim.Type, Claims.ExpiresAt, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.IssuedAt, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.NotBefore, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }

                    // Other claims are always included in the refresh token, even private claims.
                    return true;
                });

                principal.SetClaim(Claims.JwtId, Guid.NewGuid().ToString());
                principal.SetCreationDate(DateTimeOffset.UtcNow);

                // When sliding expiration is disabled, the expiration date of generated refresh tokens is fixed
                // and must exactly match the expiration date of the refresh token used in the token request.
                if (context.EndpointType == OpenIddictServerEndpointType.Token &&
                    context.Request.IsRefreshTokenGrantType() && !context.Options.DisableSlidingRefreshTokenExpiration)
                {
                    var notification = context.Transaction.GetProperty<ProcessAuthenticationContext>(
                        typeof(ProcessAuthenticationContext).FullName) ??
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID1006));

                    principal.SetExpirationDate(notification.Principal.GetExpirationDate());
                }

                else
                {
                    var lifetime = context.Principal.GetRefreshTokenLifetime() ?? context.Options.RefreshTokenLifetime;
                    if (lifetime.HasValue)
                    {
                        principal.SetExpirationDate(principal.GetCreationDate() + lifetime.Value);
                    }
                }

                context.RefreshTokenPrincipal = principal;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of preparing and attaching the claims principal
        /// used to generate the identity token, if one is going to be returned.
        /// </summary>
        public class PrepareIdentityTokenPrincipal : IOpenIddictServerHandler<ProcessSignInContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireIdentityTokenIncluded>()
                    .UseSingletonHandler<PrepareIdentityTokenPrincipal>()
                    .SetOrder(PrepareRefreshTokenPrincipal.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Replace the principal by a new one containing only the filtered claims.
                // Actors identities are also filtered (delegation scenarios).
                var principal = context.Principal.Clone(claim =>
                {
                    // Never exclude the subject and authorization identifier claims.
                    if (string.Equals(claim.Type, Claims.Subject, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.Private.AuthorizationId, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }

                    // Never include the public or internal token identifiers to ensure the identifiers
                    // that are automatically inherited from the parent token are not reused for the new token.
                    if (string.Equals(claim.Type, Claims.JwtId, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.Private.TokenId, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }

                    // Never include the creation and expiration dates that are automatically
                    // inherited from the parent token are not reused for the new token.
                    if (string.Equals(claim.Type, Claims.ExpiresAt, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.IssuedAt, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.NotBefore, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }

                    // Always exclude private claims by default, whose values must generally be kept secret.
                    if (claim.Type.StartsWith(Claims.Prefixes.Private, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }

                    // Claims whose destination is not explicitly referenced or doesn't
                    // contain "id_token" are not included in the identity token.
                    if (!claim.HasDestination(Destinations.IdentityToken))
                    {
                        context.Logger.LogDebug(SR.GetResourceString(SR.ID7011), claim.Type);

                        return false;
                    }

                    return true;
                });

                // Remove the destinations from the claim properties.
                foreach (var claim in principal.Claims)
                {
                    claim.Properties.Remove(OpenIddictConstants.Properties.Destinations);
                }

                principal.SetClaim(Claims.JwtId, Guid.NewGuid().ToString());
                principal.SetCreationDate(DateTimeOffset.UtcNow);

                var lifetime = context.Principal.GetIdentityTokenLifetime() ?? context.Options.IdentityTokenLifetime;
                if (lifetime.HasValue)
                {
                    principal.SetExpirationDate(principal.GetCreationDate() + lifetime.Value);
                }

                if (!string.IsNullOrEmpty(context.ClientId))
                {
                    principal.SetAudiences(context.ClientId);
                }

                // Use the client_id as the authorized party, if available.
                // See https://openid.net/specs/openid-connect-core-1_0.html#IDToken for more information.
                principal.SetClaim(Claims.AuthorizedParty, context.ClientId);

                // If a nonce was present in the authorization request, it MUST be included in the id_token generated
                // by the token endpoint. For that, OpenIddict simply flows the nonce as an authorization code claim.
                // See http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation for more information.
                principal.SetClaim(Claims.Nonce, context.EndpointType switch
                {
                    OpenIddictServerEndpointType.Authorization => context.Request.Nonce,
                    OpenIddictServerEndpointType.Token         => context.Principal.GetClaim(Claims.Private.Nonce),

                    _ => null
                });

                context.IdentityTokenPrincipal = principal;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of preparing and attaching the claims principal
        /// used to generate the user code, if one is going to be returned.
        /// </summary>
        public class PrepareUserCodePrincipal : IOpenIddictServerHandler<ProcessSignInContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireUserCodeIncluded>()
                    .UseSingletonHandler<PrepareUserCodePrincipal>()
                    .SetOrder(PrepareIdentityTokenPrincipal.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Create a new principal containing only the filtered claims.
                // Actors identities are also filtered (delegation scenarios).
                var principal = context.Principal.Clone(claim =>
                {
                    // Never include the public or internal token identifiers to ensure the identifiers
                    // that are automatically inherited from the parent token are not reused for the new token.
                    if (string.Equals(claim.Type, Claims.JwtId, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.Private.TokenId, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }

                    // Never include the creation and expiration dates that are automatically
                    // inherited from the parent token are not reused for the new token.
                    if (string.Equals(claim.Type, Claims.ExpiresAt, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.IssuedAt, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.NotBefore, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }

                    // Other claims are always included in the authorization code, even private claims.
                    return true;
                });

                principal.SetClaim(Claims.JwtId, Guid.NewGuid().ToString());
                principal.SetCreationDate(DateTimeOffset.UtcNow);

                var lifetime = context.Principal.GetUserCodeLifetime() ?? context.Options.UserCodeLifetime;
                if (lifetime.HasValue)
                {
                    principal.SetExpirationDate(principal.GetCreationDate() + lifetime.Value);
                }

                // Store the client_id as a public client_id claim.
                principal.SetClaim(Claims.ClientId, context.Request.ClientId);

                context.UserCodePrincipal = principal;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of redeeming the token entry corresponding to
        /// the received authorization code, device code, user code or refresh token.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class RedeemTokenEntry : IOpenIddictServerHandler<ProcessSignInContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public RedeemTokenEntry() => throw new InvalidOperationException(SR.GetResourceString(SR.ID1015));

            public RedeemTokenEntry([NotNull] IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .UseScopedHandler<RedeemTokenEntry>()
                    .SetOrder(100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (context.EndpointType != OpenIddictServerEndpointType.Token &&
                    context.EndpointType != OpenIddictServerEndpointType.Verification)
                {
                    return;
                }

                if (context.EndpointType == OpenIddictServerEndpointType.Token)
                {
                    if (!context.Request.IsAuthorizationCodeGrantType() &&
                        !context.Request.IsDeviceCodeGrantType() &&
                        !context.Request.IsRefreshTokenGrantType())
                    {
                        return;
                    }

                    if (context.Request.IsRefreshTokenGrantType() && !context.Options.UseRollingRefreshTokens)
                    {
                        return;
                    }
                }

                // Extract the token identifier from the authentication principal.
                // If no token identifier can be found, this indicates that the token has no backing database entry.
                var identifier = context.Principal.GetTokenId();
                if (string.IsNullOrEmpty(identifier))
                {
                    return;
                }

                // If rolling tokens are enabled or if the request is a a code or device code token request
                // or a user code verification request, mark the token as redeemed to prevent future reuses.
                // If the operation fails, return an error indicating the code/token is no longer valid.
                // See https://tools.ietf.org/html/rfc6749#section-6 for more information.
                var token = await _tokenManager.FindByIdAsync(identifier);
                if (token == null || !await _tokenManager.TryRedeemAsync(token))
                {
                    context.Reject(
                        error: Errors.InvalidGrant,
                        description: context.EndpointType switch
                        {
                            OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType()
                                => context.Localizer[SR.ID3016],
                            OpenIddictServerEndpointType.Token when context.Request.IsDeviceCodeGrantType()
                                => context.Localizer[SR.ID3017],
                            OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                                => context.Localizer[SR.ID3018],

                            OpenIddictServerEndpointType.Verification
                                => context.Localizer[SR.ID3026],

                            _ => context.Localizer[SR.ID3019]
                        });

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of revoking all the tokens that were previously issued.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class RevokeExistingTokenEntries : IOpenIddictServerHandler<ProcessSignInContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public RevokeExistingTokenEntries() => throw new InvalidOperationException(SR.GetResourceString(SR.ID1015));

            public RevokeExistingTokenEntries([NotNull] IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .AddFilter<RequireRollingRefreshTokensEnabled>()
                    .UseScopedHandler<RevokeExistingTokenEntries>()
                    .SetOrder(RedeemTokenEntry.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (context.EndpointType != OpenIddictServerEndpointType.Token || !context.Request.IsRefreshTokenGrantType())
                {
                    return;
                }

                // When rolling tokens are enabled, try to revoke all the previously issued tokens
                // associated with the authorization if the request is a refresh_token request.
                // If the operation fails, silently ignore the error and keep processing the request:
                // this may indicate that one of the revoked tokens was modified by a concurrent request.

                var identifier = context.Principal.GetAuthorizationId();
                if (string.IsNullOrEmpty(identifier))
                {
                    return;
                }

                await foreach (var token in _tokenManager.FindByAuthorizationIdAsync(identifier))
                {
                    // Don't change the status of the token used in the token request.
                    if (string.Equals(context.Principal.GetTokenId(),
                        await _tokenManager.GetIdAsync(token), StringComparison.Ordinal))
                    {
                        continue;
                    }

                    await _tokenManager.TryRevokeAsync(token);
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of extending the lifetime of the refresh token entry.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ExtendRefreshTokenEntry : IOpenIddictServerHandler<ProcessSignInContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public ExtendRefreshTokenEntry() => throw new InvalidOperationException(SR.GetResourceString(SR.ID1015));

            public ExtendRefreshTokenEntry([NotNull] IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .AddFilter<RequireSlidingRefreshTokenExpirationEnabled>()
                    .AddFilter<RequireRollingTokensDisabled>()
                    .UseScopedHandler<ExtendRefreshTokenEntry>()
                    .SetOrder(RevokeExistingTokenEntries.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (context.EndpointType != OpenIddictServerEndpointType.Token || !context.Request.IsRefreshTokenGrantType())
                {
                    return;
                }

                // Extract the token identifier from the authentication principal.
                // If no token identifier can be found, this indicates that the token has no backing database entry.
                var identifier = context.Principal.GetTokenId();
                if (string.IsNullOrEmpty(identifier))
                {
                    return;
                }

                var token = await _tokenManager.FindByIdAsync(identifier);
                if (token == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1264));
                }

                // Compute the new expiration date of the refresh token and update the token entry.
                var lifetime = context.Principal.GetRefreshTokenLifetime() ?? context.Options.RefreshTokenLifetime;
                if (lifetime.HasValue)
                {
                    await _tokenManager.TryExtendAsync(token, DateTimeOffset.UtcNow + lifetime.Value);
                }

                else
                {
                    await _tokenManager.TryExtendAsync(token, date: null);
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of creating an access token entry.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class CreateAccessTokenEntry : IOpenIddictServerHandler<ProcessSignInContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;
            private readonly IOpenIddictTokenManager _tokenManager;

            public CreateAccessTokenEntry() => throw new InvalidOperationException(SR.GetResourceString(SR.ID1015));

            public CreateAccessTokenEntry(
                [NotNull] IOpenIddictApplicationManager applicationManager,
                [NotNull] IOpenIddictTokenManager tokenManager)
            {
                _applicationManager = applicationManager;
                _tokenManager = tokenManager;
            }

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .AddFilter<RequireAccessTokenIncluded>()
                    .UseScopedHandler<CreateAccessTokenEntry>()
                    .SetOrder(ExtendRefreshTokenEntry.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var principal = context.AccessTokenPrincipal;
                if (principal == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1021));
                }

                var descriptor = new OpenIddictTokenDescriptor
                {
                    AuthorizationId = principal.GetAuthorizationId(),
                    CreationDate = principal.GetCreationDate(),
                    ExpirationDate = principal.GetExpirationDate(),
                    Principal = principal,
                    Status = Statuses.Valid,
                    Subject = principal.GetClaim(Claims.Subject),
                    Type = TokenTypeHints.AccessToken
                };

                // If the client application is known, associate it with the token.
                if (!string.IsNullOrEmpty(context.Request.ClientId))
                {
                    var application = await _applicationManager.FindByClientIdAsync(context.Request.ClientId);
                    if (application == null)
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID1016));
                    }

                    descriptor.ApplicationId = await _applicationManager.GetIdAsync(application);
                }

                var token = await _tokenManager.CreateAsync(descriptor);
                if (token == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1018));
                }

                var identifier = await _tokenManager.GetIdAsync(token);

                // Attach the token identifier to the principal so that it can be stored in the token.
                principal.SetTokenId(identifier);

                context.Logger.LogTrace(SR.GetResourceString(SR.ID7012), identifier);
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating an access token using IdentityModel.
        /// </summary>
        public class GenerateIdentityModelAccessToken : IOpenIddictServerHandler<ProcessSignInContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireAccessTokenIncluded>()
                    .UseSingletonHandler<GenerateIdentityModelAccessToken>()
                    .SetOrder(CreateAccessTokenEntry.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If an access token was already attached by another handler, don't overwrite it.
                if (!string.IsNullOrEmpty(context.Response.AccessToken))
                {
                    return default;
                }

                // Clone the principal and exclude the private claims mapped to standard JWT claims.
                var principal = context.AccessTokenPrincipal?.Clone(claim => claim.Type switch
                {
                    Claims.Private.Audience       => false,
                    Claims.Private.CreationDate   => false,
                    Claims.Private.ExpirationDate => false,
                    Claims.Private.Scope          => false,
                    Claims.Private.TokenType      => false,

                    _ => true
                });

                if (principal == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1019));
                }

                var claims = new Dictionary<string, object>(StringComparer.Ordinal);

                // Set the public audience claims using the private audience claims from the principal.
                // Note: when there's a single audience, represent it as a unique string claim.
                var audiences = context.AccessTokenPrincipal.GetAudiences();
                if (audiences.Any())
                {
                    claims.Add(Claims.Audience, audiences.Length switch
                    {
                        1 => audiences.ElementAt(0),
                        _ => audiences
                    });
                }

                // Set the public scope claim using the private scope claims from the principal.
                // Note: scopes are deliberately formatted as a single space-separated
                // string to respect the usual representation of the standard scope claim.
                // See https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-04.
                var scopes = context.AccessTokenPrincipal.GetScopes();
                if (scopes.Any())
                {
                    claims.Add(Claims.Scope, string.Join(" ", scopes));
                }

                var descriptor = new SecurityTokenDescriptor
                {
                    AdditionalHeaderClaims = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        [JwtHeaderParameterNames.Typ] = JsonWebTokenTypes.AccessToken
                    },
                    Claims = claims,
                    Expires = context.AccessTokenPrincipal.GetExpirationDate()?.UtcDateTime,
                    IssuedAt = context.AccessTokenPrincipal.GetCreationDate()?.UtcDateTime,
                    Issuer = context.Issuer?.AbsoluteUri,
                    SigningCredentials = context.Options.SigningCredentials.First(),
                    Subject = (ClaimsIdentity) principal.Identity
                };

                var token = context.Options.JsonWebTokenHandler.CreateToken(descriptor);

                if (!context.Options.DisableAccessTokenEncryption)
                {
                    token = context.Options.JsonWebTokenHandler.EncryptToken(token,
                        encryptingCredentials: context.Options.EncryptionCredentials.First(),
                        additionalHeaderClaims: descriptor.AdditionalHeaderClaims);
                }

                context.Response.AccessToken = token;

                context.Logger.LogTrace(SR.GetResourceString(SR.ID7013), principal.GetClaim(Claims.JwtId), token, principal.Claims);

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of converting the access token to a reference token.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ConvertReferenceAccessToken : IOpenIddictServerHandler<ProcessSignInContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public ConvertReferenceAccessToken() => throw new InvalidOperationException(SR.GetResourceString(SR.ID1015));

            public ConvertReferenceAccessToken([NotNull] IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .AddFilter<RequireReferenceAccessTokensEnabled>()
                    .AddFilter<RequireAccessTokenIncluded>()
                    .UseScopedHandler<ConvertReferenceAccessToken>()
                    .SetOrder(GenerateIdentityModelAccessToken.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (string.IsNullOrEmpty(context.Response.AccessToken))
                {
                    return;
                }

                var principal = context.AccessTokenPrincipal;
                if (principal == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1019));
                }

                var identifier = principal.GetTokenId();
                if (string.IsNullOrEmpty(identifier))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1008));
                }

                var token = await _tokenManager.FindByIdAsync(identifier);
                if (token == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1020));
                }

                // Generate a new crypto-secure random identifier that will be substituted to the token.
                var data = new byte[256 / 8];
#if SUPPORTS_STATIC_RANDOM_NUMBER_GENERATOR_METHODS
                RandomNumberGenerator.Fill(data);
#else
                using var generator = RandomNumberGenerator.Create();
                generator.GetBytes(data);
#endif
                var descriptor = new OpenIddictTokenDescriptor();
                await _tokenManager.PopulateAsync(descriptor, token);

                // Attach the generated token to the token entry, persist the change
                // and replace the returned token by the reference identifier.
                descriptor.Payload = context.Response.AccessToken;
                descriptor.Principal = principal;
                descriptor.ReferenceId = Base64UrlEncoder.Encode(data);

                await _tokenManager.UpdateAsync(token, descriptor);

                context.Response.AccessToken = descriptor.ReferenceId;

                context.Logger.LogTrace(SR.GetResourceString(SR.ID7014), identifier, descriptor.ReferenceId);
            }
        }

        /// <summary>
        /// Contains the logic responsible of creating an authorization code entry.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class CreateAuthorizationCodeEntry : IOpenIddictServerHandler<ProcessSignInContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;
            private readonly IOpenIddictTokenManager _tokenManager;

            public CreateAuthorizationCodeEntry() => throw new InvalidOperationException(SR.GetResourceString(SR.ID1015));

            public CreateAuthorizationCodeEntry(
                [NotNull] IOpenIddictApplicationManager applicationManager,
                [NotNull] IOpenIddictTokenManager tokenManager)
            {
                _applicationManager = applicationManager;
                _tokenManager = tokenManager;
            }

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .AddFilter<RequireAuthorizationCodeIncluded>()
                    .UseScopedHandler<CreateAuthorizationCodeEntry>()
                    .SetOrder(ConvertReferenceAccessToken.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var principal = context.AuthorizationCodePrincipal;
                if (principal == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1019));
                }

                var descriptor = new OpenIddictTokenDescriptor
                {
                    AuthorizationId = principal.GetAuthorizationId(),
                    CreationDate = principal.GetCreationDate(),
                    ExpirationDate = principal.GetExpirationDate(),
                    Principal = principal,
                    Status = Statuses.Valid,
                    Subject = principal.GetClaim(Claims.Subject),
                    Type = TokenTypeHints.AuthorizationCode
                };

                // If the client application is known, associate it with the token.
                if (!string.IsNullOrEmpty(context.Request.ClientId))
                {
                    var application = await _applicationManager.FindByClientIdAsync(context.Request.ClientId);
                    if (application == null)
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID1016));
                    }

                    descriptor.ApplicationId = await _applicationManager.GetIdAsync(application);
                }

                var token = await _tokenManager.CreateAsync(descriptor);
                if (token == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1018));
                }

                var identifier = await _tokenManager.GetIdAsync(token);

                // Attach the token identifier to the principal so that it can be stored in the token.
                principal.SetTokenId(identifier);

                context.Logger.LogTrace(SR.GetResourceString(SR.ID7015), identifier);
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating an authorization code using IdentityModel.
        /// </summary>
        public class GenerateIdentityModelAuthorizationCode : IOpenIddictServerHandler<ProcessSignInContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireAuthorizationCodeIncluded>()
                    .UseSingletonHandler<GenerateIdentityModelAuthorizationCode>()
                    .SetOrder(CreateAuthorizationCodeEntry.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If an authorization code was already attached by another handler, don't overwrite it.
                if (!string.IsNullOrEmpty(context.Response.Code))
                {
                    return default;
                }

                // Clone the principal and exclude the claim mapped to standard JWT claims.
                var principal = context.AuthorizationCodePrincipal?.Clone(claim => claim.Type switch
                {
                    Claims.Private.CreationDate   => false,
                    Claims.Private.ExpirationDate => false,
                    Claims.Private.TokenType      => false,

                    _ => true
                });

                if (principal == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1021));
                }

                var descriptor = new SecurityTokenDescriptor
                {
                    AdditionalHeaderClaims = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        [JwtHeaderParameterNames.Typ] = JsonWebTokenTypes.Private.AuthorizationCode
                    },
                    Expires = context.AuthorizationCodePrincipal.GetExpirationDate()?.UtcDateTime,
                    IssuedAt = context.AuthorizationCodePrincipal.GetCreationDate()?.UtcDateTime,
                    Issuer = context.Issuer?.AbsoluteUri,
                    SigningCredentials = context.Options.SigningCredentials.First(),
                    Subject = (ClaimsIdentity) principal.Identity
                };

                // Attach claims destinations to the JWT claims collection.
                var destinations = principal.GetDestinations();
                if (destinations.Count != 0)
                {
                    descriptor.Claims = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        [Claims.Private.ClaimDestinationsMap] = destinations
                    };
                }

                // Sign and encrypt the authorization code.
                var token = context.Options.JsonWebTokenHandler.CreateToken(descriptor);

                token = context.Options.JsonWebTokenHandler.EncryptToken(token,
                    encryptingCredentials: context.Options.EncryptionCredentials.First(),
                    additionalHeaderClaims: descriptor.AdditionalHeaderClaims);

                context.Response.Code = token;

                context.Logger.LogTrace(SR.GetResourceString(SR.ID7016), principal.GetClaim(Claims.JwtId), token, principal.Claims);

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of converting the authorization code to a reference token.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ConvertReferenceAuthorizationCode : IOpenIddictServerHandler<ProcessSignInContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public ConvertReferenceAuthorizationCode() => throw new InvalidOperationException(SR.GetResourceString(SR.ID1015));

            public ConvertReferenceAuthorizationCode([NotNull] IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .AddFilter<RequireAuthorizationCodeIncluded>()
                    .UseScopedHandler<ConvertReferenceAuthorizationCode>()
                    .SetOrder(GenerateIdentityModelAuthorizationCode.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (string.IsNullOrEmpty(context.Response.Code))
                {
                    return;
                }

                var principal = context.AuthorizationCodePrincipal;
                if (principal == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1019));
                }

                var identifier = principal.GetTokenId();
                if (string.IsNullOrEmpty(identifier))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1008));
                }

                var token = await _tokenManager.FindByIdAsync(identifier);
                if (token == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1020));
                }

                // Generate a new crypto-secure random identifier that will be substituted to the token.
                var data = new byte[256 / 8];
#if SUPPORTS_STATIC_RANDOM_NUMBER_GENERATOR_METHODS
                RandomNumberGenerator.Fill(data);
#else
                using var generator = RandomNumberGenerator.Create();
                generator.GetBytes(data);
#endif
                var descriptor = new OpenIddictTokenDescriptor();
                await _tokenManager.PopulateAsync(descriptor, token);

                // Attach the generated token to the token entry, persist the change
                // and replace the returned token by the reference identifier.
                descriptor.Payload = context.Response.Code;
                descriptor.Principal = principal;
                descriptor.ReferenceId = Base64UrlEncoder.Encode(data);

                await _tokenManager.UpdateAsync(token, descriptor);

                context.Response.Code = descriptor.ReferenceId;

                context.Logger.LogTrace(SR.GetResourceString(SR.ID7017), identifier, descriptor.ReferenceId);
            }
        }

        /// <summary>
        /// Contains the logic responsible of creating an access token entry.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class CreateDeviceCodeEntry : IOpenIddictServerHandler<ProcessSignInContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;
            private readonly IOpenIddictTokenManager _tokenManager;

            public CreateDeviceCodeEntry() => throw new InvalidOperationException(SR.GetResourceString(SR.ID1015));

            public CreateDeviceCodeEntry(
                [NotNull] IOpenIddictApplicationManager applicationManager,
                [NotNull] IOpenIddictTokenManager tokenManager)
            {
                _applicationManager = applicationManager;
                _tokenManager = tokenManager;
            }

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .AddFilter<RequireDeviceCodeIncluded>()
                    .UseScopedHandler<CreateDeviceCodeEntry>()
                    .SetOrder(ConvertReferenceAuthorizationCode.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (context.EndpointType == OpenIddictServerEndpointType.Verification)
                {
                    return;
                }

                var principal = context.DeviceCodePrincipal;
                if (principal == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1019));
                }

                var descriptor = new OpenIddictTokenDescriptor
                {
                    AuthorizationId = principal.GetAuthorizationId(),
                    CreationDate = principal.GetCreationDate(),
                    ExpirationDate = principal.GetExpirationDate(),
                    Principal = principal,
                    Status = Statuses.Inactive,
                    Subject = null, // Device codes are not bound to a user, which is not known until the user code is populated.
                    Type = TokenTypeHints.DeviceCode
                };

                // If the client application is known, associate it with the token.
                if (!string.IsNullOrEmpty(context.Request.ClientId))
                {
                    var application = await _applicationManager.FindByClientIdAsync(context.Request.ClientId);
                    if (application == null)
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID1016));
                    }

                    descriptor.ApplicationId = await _applicationManager.GetIdAsync(application);
                }

                var token = await _tokenManager.CreateAsync(descriptor);
                if (token == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1018));
                }

                var identifier = await _tokenManager.GetIdAsync(token);

                // Attach the token identifier to the principal so that it can be stored in the token.
                principal.SetTokenId(identifier);

                context.Logger.LogTrace(SR.GetResourceString(SR.ID7018), identifier);
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating a device code using IdentityModel.
        /// </summary>
        public class GenerateIdentityModelDeviceCode : IOpenIddictServerHandler<ProcessSignInContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireDeviceCodeIncluded>()
                    .UseSingletonHandler<GenerateIdentityModelDeviceCode>()
                    .SetOrder(CreateDeviceCodeEntry.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If a device code was already attached by another handler, don't overwrite it.
                if (!string.IsNullOrEmpty(context.Response.DeviceCode))
                {
                    return default;
                }

                // Clone the principal and exclude the claim mapped to standard JWT claims.
                var principal = context.DeviceCodePrincipal?.Clone(claim => claim.Type switch
                {
                    Claims.Private.CreationDate   => false,
                    Claims.Private.ExpirationDate => false,
                    Claims.Private.TokenType      => false,

                    _ => true
                });

                if (principal == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1021));
                }

                var descriptor = new SecurityTokenDescriptor
                {
                    AdditionalHeaderClaims = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        [JwtHeaderParameterNames.Typ] = JsonWebTokenTypes.Private.DeviceCode
                    },
                    Expires = context.DeviceCodePrincipal.GetExpirationDate()?.UtcDateTime,
                    IssuedAt = context.DeviceCodePrincipal.GetCreationDate()?.UtcDateTime,
                    Issuer = context.Issuer?.AbsoluteUri,
                    SigningCredentials = context.Options.SigningCredentials.First(),
                    Subject = (ClaimsIdentity) principal.Identity
                };

                // Attach claims destinations to the JWT claims collection.
                var destinations = principal.GetDestinations();
                if (destinations.Count != 0)
                {
                    descriptor.Claims = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        [Claims.Private.ClaimDestinationsMap] = destinations
                    };
                }

                // Sign and encrypt the device code.
                var token = context.Options.JsonWebTokenHandler.CreateToken(descriptor);

                token = context.Options.JsonWebTokenHandler.EncryptToken(token,
                    encryptingCredentials: context.Options.EncryptionCredentials.First(),
                    additionalHeaderClaims: descriptor.AdditionalHeaderClaims);

                context.Response.DeviceCode = token;

                context.Logger.LogTrace(SR.GetResourceString(SR.ID7019), principal.GetClaim(Claims.JwtId), token, principal.Claims);

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of creating a reference device code entry.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ConvertReferenceDeviceCode : IOpenIddictServerHandler<ProcessSignInContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public ConvertReferenceDeviceCode() => throw new InvalidOperationException(SR.GetResourceString(SR.ID1015));

            public ConvertReferenceDeviceCode([NotNull] IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    // Note: device codes are always reference tokens.
                    .AddFilter<RequireDeviceCodeIncluded>()
                    .UseScopedHandler<ConvertReferenceDeviceCode>()
                    .SetOrder(GenerateIdentityModelDeviceCode.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (string.IsNullOrEmpty(context.Response.DeviceCode))
                {
                    return;
                }

                if (context.EndpointType == OpenIddictServerEndpointType.Verification)
                {
                    return;
                }

                var principal = context.DeviceCodePrincipal;
                if (principal == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1019));
                }

                var identifier = principal.GetTokenId();
                if (string.IsNullOrEmpty(identifier))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1008));
                }

                var token = await _tokenManager.FindByIdAsync(identifier);
                if (token == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1020));
                }

                // Generate a new crypto-secure random identifier that will be substituted to the token.
                var data = new byte[256 / 8];
#if SUPPORTS_STATIC_RANDOM_NUMBER_GENERATOR_METHODS
                RandomNumberGenerator.Fill(data);
#else
                using var generator = RandomNumberGenerator.Create();
                generator.GetBytes(data);
#endif
                var descriptor = new OpenIddictTokenDescriptor();
                await _tokenManager.PopulateAsync(descriptor, token);

                // Attach the generated token to the token entry, persist the change
                // and replace the returned token by the reference identifier.
                descriptor.Payload = context.Response.DeviceCode;
                descriptor.Principal = principal;
                descriptor.ReferenceId = Base64UrlEncoder.Encode(data);

                await _tokenManager.UpdateAsync(token, descriptor);

                context.Response.DeviceCode = descriptor.ReferenceId;

                context.Logger.LogTrace(SR.GetResourceString(SR.ID7020), identifier, descriptor.ReferenceId);
            }
        }

        /// <summary>
        /// Contains the logic responsible of updating the existing reference device code entry.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class UpdateReferenceDeviceCodeEntry : IOpenIddictServerHandler<ProcessSignInContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public UpdateReferenceDeviceCodeEntry() => throw new InvalidOperationException(SR.GetResourceString(SR.ID1015));

            public UpdateReferenceDeviceCodeEntry([NotNull] IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .AddFilter<RequireDeviceCodeIncluded>()
                    .UseScopedHandler<UpdateReferenceDeviceCodeEntry>()
                    .SetOrder(ConvertReferenceDeviceCode.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (string.IsNullOrEmpty(context.Response.DeviceCode))
                {
                    return;
                }

                if (context.EndpointType != OpenIddictServerEndpointType.Verification)
                {
                    return;
                }

                var principal = context.DeviceCodePrincipal;
                if (principal == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1019));
                }

                // Extract the token identifier from the authentication principal.
                var identifier = context.Principal.GetClaim(Claims.Private.DeviceCodeId);
                if (string.IsNullOrEmpty(identifier))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1007));
                }

                var token = await _tokenManager.FindByIdAsync(identifier);
                if (token == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1264));
                }

                // Replace the device code details by the payload derived from the new device code principal,
                // that includes all the user claims populated by the application after authenticating the user.
                var descriptor = new OpenIddictTokenDescriptor();
                await _tokenManager.PopulateAsync(descriptor, token);

                // Note: the lifetime is deliberately extended to give more time to the client to redeem the code.
                descriptor.ExpirationDate = principal.GetExpirationDate();
                descriptor.Payload = context.Response.DeviceCode;
                descriptor.Principal = principal;
                descriptor.Status = Statuses.Valid;
                descriptor.Subject = principal.GetClaim(Claims.Subject);

                await _tokenManager.UpdateAsync(token, descriptor);

                // Don't return the prepared device code directly from the verification endpoint.
                context.Response.DeviceCode = null;

                context.Logger.LogTrace(SR.GetResourceString(SR.ID7021), await _tokenManager.GetIdAsync(token));
            }
        }

        /// <summary>
        /// Contains the logic responsible of creating a refresh token entry.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class CreateRefreshTokenEntry : IOpenIddictServerHandler<ProcessSignInContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;
            private readonly IOpenIddictTokenManager _tokenManager;

            public CreateRefreshTokenEntry() => throw new InvalidOperationException(SR.GetResourceString(SR.ID1015));

            public CreateRefreshTokenEntry(
                [NotNull] IOpenIddictApplicationManager applicationManager,
                [NotNull] IOpenIddictTokenManager tokenManager)
            {
                _applicationManager = applicationManager;
                _tokenManager = tokenManager;
            }

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .AddFilter<RequireRefreshTokenIncluded>()
                    .UseScopedHandler<CreateRefreshTokenEntry>()
                    .SetOrder(UpdateReferenceDeviceCodeEntry.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var principal = context.RefreshTokenPrincipal;
                if (principal == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1019));
                }

                var descriptor = new OpenIddictTokenDescriptor
                {
                    AuthorizationId = principal.GetAuthorizationId(),
                    CreationDate = principal.GetCreationDate(),
                    ExpirationDate = principal.GetExpirationDate(),
                    Principal = principal,
                    Status = Statuses.Valid,
                    Subject = principal.GetClaim(Claims.Subject),
                    Type = TokenTypeHints.RefreshToken
                };

                // If the client application is known, associate it with the token.
                if (!string.IsNullOrEmpty(context.Request.ClientId))
                {
                    var application = await _applicationManager.FindByClientIdAsync(context.Request.ClientId);
                    if (application == null)
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID1016));
                    }

                    descriptor.ApplicationId = await _applicationManager.GetIdAsync(application);
                }

                var token = await _tokenManager.CreateAsync(descriptor);
                if (token == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1018));
                }

                var identifier = await _tokenManager.GetIdAsync(token);

                // Attach the token identifier to the principal so that it can be stored in the token.
                principal.SetTokenId(identifier);

                context.Logger.LogTrace(SR.GetResourceString(SR.ID7022), identifier);
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating a refresh token using IdentityModel.
        /// </summary>
        public class GenerateIdentityModelRefreshToken : IOpenIddictServerHandler<ProcessSignInContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireRefreshTokenIncluded>()
                    .UseSingletonHandler<GenerateIdentityModelRefreshToken>()
                    .SetOrder(CreateRefreshTokenEntry.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If a refresh token was already attached by another handler, don't overwrite it.
                if (!string.IsNullOrEmpty(context.Response.RefreshToken))
                {
                    return default;
                }

                // Clone the principal and exclude the claim mapped to standard JWT claims.
                var principal = context.RefreshTokenPrincipal?.Clone(claim => claim.Type switch
                {
                    Claims.Private.CreationDate   => false,
                    Claims.Private.ExpirationDate => false,
                    Claims.Private.TokenType      => false,

                    _ => true
                });

                if (principal == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1021));
                }

                var descriptor = new SecurityTokenDescriptor
                {
                    AdditionalHeaderClaims = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        [JwtHeaderParameterNames.Typ] = JsonWebTokenTypes.Private.RefreshToken
                    },
                    Expires = context.RefreshTokenPrincipal.GetExpirationDate()?.UtcDateTime,
                    IssuedAt = context.RefreshTokenPrincipal.GetCreationDate()?.UtcDateTime,
                    Issuer = context.Issuer?.AbsoluteUri,
                    SigningCredentials = context.Options.SigningCredentials.First(),
                    Subject = (ClaimsIdentity) principal.Identity
                };

                // Attach claims destinations to the JWT claims collection.
                var destinations = principal.GetDestinations();
                if (destinations.Count != 0)
                {
                    descriptor.Claims = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        [Claims.Private.ClaimDestinationsMap] = destinations
                    };
                }

                // Sign and encrypt the refresh token.
                var token = context.Options.JsonWebTokenHandler.CreateToken(descriptor);

                token = context.Options.JsonWebTokenHandler.EncryptToken(token,
                    encryptingCredentials: context.Options.EncryptionCredentials.First(),
                    additionalHeaderClaims: descriptor.AdditionalHeaderClaims);

                context.Response.RefreshToken = token;

                context.Logger.LogTrace(SR.GetResourceString(SR.ID7023), principal.GetClaim(Claims.JwtId), token, principal.Claims);

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of converting the refresh token to a reference token.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ConvertReferenceRefreshToken : IOpenIddictServerHandler<ProcessSignInContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public ConvertReferenceRefreshToken() => throw new InvalidOperationException(SR.GetResourceString(SR.ID1015));

            public ConvertReferenceRefreshToken([NotNull] IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .AddFilter<RequireReferenceRefreshTokensEnabled>()
                    .AddFilter<RequireRefreshTokenIncluded>()
                    .UseScopedHandler<ConvertReferenceRefreshToken>()
                    .SetOrder(GenerateIdentityModelRefreshToken.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (string.IsNullOrEmpty(context.Response.RefreshToken))
                {
                    return;
                }

                var principal = context.RefreshTokenPrincipal;
                if (principal == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1019));
                }

                var identifier = principal.GetTokenId();
                if (string.IsNullOrEmpty(identifier))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1008));
                }

                var token = await _tokenManager.FindByIdAsync(identifier);
                if (token == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1020));
                }

                // Generate a new crypto-secure random identifier that will be substituted to the token.
                var data = new byte[256 / 8];
#if SUPPORTS_STATIC_RANDOM_NUMBER_GENERATOR_METHODS
                RandomNumberGenerator.Fill(data);
#else
                using var generator = RandomNumberGenerator.Create();
                generator.GetBytes(data);
#endif
                var descriptor = new OpenIddictTokenDescriptor();
                await _tokenManager.PopulateAsync(descriptor, token);

                // Attach the generated token to the token entry, persist the change
                // and replace the returned token by the reference identifier.
                descriptor.Payload = context.Response.RefreshToken;
                descriptor.Principal = principal;
                descriptor.ReferenceId = Base64UrlEncoder.Encode(data);

                await _tokenManager.UpdateAsync(token, descriptor);

                context.Response.RefreshToken = descriptor.ReferenceId;

                context.Logger.LogTrace(SR.GetResourceString(SR.ID7024), identifier, descriptor.ReferenceId);
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating and attaching the device code identifier to the user code principal.
        /// </summary>
        public class AttachDeviceCodeIdentifier : IOpenIddictServerHandler<ProcessSignInContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireDeviceCodeIncluded>()
                    .AddFilter<RequireUserCodeIncluded>()
                    .UseSingletonHandler<AttachDeviceCodeIdentifier>()
                    .SetOrder(ConvertReferenceRefreshToken.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var principal = context.UserCodePrincipal;
                if (principal == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1019));
                }

                var identifier = context.DeviceCodePrincipal.GetTokenId();
                if (!string.IsNullOrEmpty(identifier))
                {
                    principal.SetClaim(Claims.Private.DeviceCodeId, identifier);
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of creating a user code entry.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class CreateUserCodeEntry : IOpenIddictServerHandler<ProcessSignInContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;
            private readonly IOpenIddictTokenManager _tokenManager;

            public CreateUserCodeEntry() => throw new InvalidOperationException(SR.GetResourceString(SR.ID1015));

            public CreateUserCodeEntry(
                [NotNull] IOpenIddictApplicationManager applicationManager,
                [NotNull] IOpenIddictTokenManager tokenManager)
            {
                _applicationManager = applicationManager;
                _tokenManager = tokenManager;
            }

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .AddFilter<RequireUserCodeIncluded>()
                    .UseScopedHandler<CreateUserCodeEntry>()
                    .SetOrder(AttachDeviceCodeIdentifier.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var principal = context.UserCodePrincipal;
                if (principal == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1019));
                }

                var descriptor = new OpenIddictTokenDescriptor
                {
                    AuthorizationId = principal.GetAuthorizationId(),
                    CreationDate = principal.GetCreationDate(),
                    ExpirationDate = principal.GetExpirationDate(),
                    Principal = principal,
                    Status = Statuses.Valid,
                    Subject = null, // User codes are not bound to a user until authorization is granted.
                    Type = TokenTypeHints.UserCode
                };

                // If the client application is known, associate it with the token.
                if (!string.IsNullOrEmpty(context.Request.ClientId))
                {
                    var application = await _applicationManager.FindByClientIdAsync(context.Request.ClientId);
                    if (application == null)
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID1016));
                    }

                    descriptor.ApplicationId = await _applicationManager.GetIdAsync(application);
                }

                var token = await _tokenManager.CreateAsync(descriptor);
                if (token == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1018));
                }

                var identifier = await _tokenManager.GetIdAsync(token);

                // Attach the token identifier to the principal so that it can be stored in the token.
                principal.SetTokenId(identifier);

                context.Logger.LogTrace(SR.GetResourceString(SR.ID7025), identifier);
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating a user code using IdentityModel.
        /// </summary>
        public class GenerateIdentityModelUserCode : IOpenIddictServerHandler<ProcessSignInContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireUserCodeIncluded>()
                    .UseSingletonHandler<GenerateIdentityModelUserCode>()
                    .SetOrder(CreateUserCodeEntry.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If a user code was already attached by another handler, don't overwrite it.
                if (!string.IsNullOrEmpty(context.Response.UserCode))
                {
                    return default;
                }

                // Clone the principal and exclude the claim mapped to standard JWT claims.
                var principal = context.UserCodePrincipal?.Clone(claim => claim.Type switch
                {
                    Claims.Private.CreationDate   => false,
                    Claims.Private.ExpirationDate => false,
                    Claims.Private.TokenType      => false,

                    _ => true
                });

                if (principal == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1021));
                }

                var descriptor = new SecurityTokenDescriptor
                {
                    AdditionalHeaderClaims = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        [JwtHeaderParameterNames.Typ] = JsonWebTokenTypes.Private.UserCode
                    },
                    Expires = context.UserCodePrincipal.GetExpirationDate()?.UtcDateTime,
                    IssuedAt = context.UserCodePrincipal.GetCreationDate()?.UtcDateTime,
                    Issuer = context.Issuer?.AbsoluteUri,
                    SigningCredentials = context.Options.SigningCredentials.First(),
                    Subject = (ClaimsIdentity) principal.Identity
                };

                // Sign and encrypt the user code.
                var token = context.Options.JsonWebTokenHandler.CreateToken(descriptor);

                token = context.Options.JsonWebTokenHandler.EncryptToken(token,
                    encryptingCredentials: context.Options.EncryptionCredentials.First(),
                    additionalHeaderClaims: descriptor.AdditionalHeaderClaims);

                context.Response.UserCode = token;

                context.Logger.LogTrace(SR.GetResourceString(SR.ID7026), principal.GetClaim(Claims.JwtId), token, principal.Claims);

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of converting the user code to a reference token.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ConvertReferenceUserCode : IOpenIddictServerHandler<ProcessSignInContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public ConvertReferenceUserCode() => throw new InvalidOperationException(SR.GetResourceString(SR.ID1015));

            public ConvertReferenceUserCode([NotNull] IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    // Note: user codes are always reference tokens.
                    .AddFilter<RequireUserCodeIncluded>()
                    .UseScopedHandler<ConvertReferenceUserCode>()
                    .SetOrder(GenerateIdentityModelUserCode.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (string.IsNullOrEmpty(context.Response.UserCode))
                {
                    return;
                }

                var principal = context.UserCodePrincipal;
                if (principal == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1019));
                }

                var identifier = principal.GetTokenId();
                if (string.IsNullOrEmpty(identifier))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1008));
                }

                var token = await _tokenManager.FindByIdAsync(identifier);
                if (token == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1020));
                }

                // Note: unlike other reference tokens, user codes are meant to be used by humans,
                // who may have to enter it in a web form. To ensure it remains easy enough to type
                // even by users with non-Latin keyboards, user codes generated by OpenIddict are
                // only compound of 12 digits, generated using a crypto-secure random number generator.
                // In this case, the resulting user code is estimated to have at most ~40 bits of entropy.

                var data = new byte[12];
#if SUPPORTS_STATIC_RANDOM_NUMBER_GENERATOR_METHODS
                RandomNumberGenerator.Fill(data);
#else
                using var generator = RandomNumberGenerator.Create();
                generator.GetBytes(data);
#endif
                var builder = new StringBuilder(data.Length);

                for (var index = 0; index < data.Length; index += 4)
                {
                    builder.AppendFormat(CultureInfo.InvariantCulture, "{0:D4}", BitConverter.ToUInt32(data, index) % 10000);
                }

                var descriptor = new OpenIddictTokenDescriptor();
                await _tokenManager.PopulateAsync(descriptor, token);

                // Attach the generated token to the token entry, persist the change
                // and replace the returned token by the reference identifier.
                descriptor.Payload = context.Response.UserCode;
                descriptor.Principal = principal;
                descriptor.ReferenceId = builder.ToString();

                await _tokenManager.UpdateAsync(token, descriptor);

                context.Response.UserCode = descriptor.ReferenceId;

                context.Logger.LogTrace(SR.GetResourceString(SR.ID7027), identifier, descriptor.ReferenceId);
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating and attaching the hashes of
        /// the access token and authorization code to the identity token principal.
        /// </summary>
        public class AttachTokenDigests : IOpenIddictServerHandler<ProcessSignInContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireIdentityTokenIncluded>()
                    .UseSingletonHandler<AttachTokenDigests>()
                    .SetOrder(ConvertReferenceUserCode.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (string.IsNullOrEmpty(context.Response.AccessToken) &&
                    string.IsNullOrEmpty(context.Response.Code))
                {
                    return default;
                }

                var credentials = context.Options.SigningCredentials.FirstOrDefault(
                    credentials => credentials.Key is AsymmetricSecurityKey);
                if (credentials == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1265));
                }

                using var hash = GetHashAlgorithm(credentials);
                if (hash == null || hash is KeyedHashAlgorithm)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1266));
                }

                if (!string.IsNullOrEmpty(context.Response.AccessToken))
                {
                    var digest = hash.ComputeHash(Encoding.ASCII.GetBytes(context.Response.AccessToken));

                    // Note: only the left-most half of the hash is used.
                    // See http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
                    context.IdentityTokenPrincipal.SetClaim(Claims.AccessTokenHash, Base64UrlEncoder.Encode(digest, 0, digest.Length / 2));
                }

                if (!string.IsNullOrEmpty(context.Response.Code))
                {
                    var digest = hash.ComputeHash(Encoding.ASCII.GetBytes(context.Response.Code));

                    // Note: only the left-most half of the hash is used.
                    // See http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken
                    context.IdentityTokenPrincipal.SetClaim(Claims.CodeHash, Base64UrlEncoder.Encode(digest, 0, digest.Length / 2));
                }

                return default;

                static HashAlgorithm GetHashAlgorithm(SigningCredentials credentials)
                {
                    HashAlgorithm hash = null;

                    if (!string.IsNullOrEmpty(credentials.Digest))
                    {
                        hash = CryptoConfig.CreateFromName(credentials.Digest) as HashAlgorithm;
                    }

                    if (hash == null)
                    {
                        var algorithm = credentials.Digest switch
                        {
                            SecurityAlgorithms.Sha256 => HashAlgorithmName.SHA256,
                            SecurityAlgorithms.Sha384 => HashAlgorithmName.SHA384,
                            SecurityAlgorithms.Sha512 => HashAlgorithmName.SHA512,
                            SecurityAlgorithms.Sha256Digest => HashAlgorithmName.SHA256,
                            SecurityAlgorithms.Sha384Digest => HashAlgorithmName.SHA384,
                            SecurityAlgorithms.Sha512Digest => HashAlgorithmName.SHA512,

                            _ => credentials.Algorithm switch
                            {
#if SUPPORTS_ECDSA
                                SecurityAlgorithms.EcdsaSha256 => HashAlgorithmName.SHA256,
                                SecurityAlgorithms.EcdsaSha384 => HashAlgorithmName.SHA384,
                                SecurityAlgorithms.EcdsaSha512 => HashAlgorithmName.SHA512,
                                SecurityAlgorithms.EcdsaSha256Signature => HashAlgorithmName.SHA256,
                                SecurityAlgorithms.EcdsaSha384Signature => HashAlgorithmName.SHA384,
                                SecurityAlgorithms.EcdsaSha512Signature => HashAlgorithmName.SHA512,
#endif
                                SecurityAlgorithms.HmacSha256 => HashAlgorithmName.SHA256,
                                SecurityAlgorithms.HmacSha384 => HashAlgorithmName.SHA384,
                                SecurityAlgorithms.HmacSha512 => HashAlgorithmName.SHA512,
                                SecurityAlgorithms.HmacSha256Signature => HashAlgorithmName.SHA256,
                                SecurityAlgorithms.HmacSha384Signature => HashAlgorithmName.SHA384,
                                SecurityAlgorithms.HmacSha512Signature => HashAlgorithmName.SHA512,

                                SecurityAlgorithms.RsaSha256 => HashAlgorithmName.SHA256,
                                SecurityAlgorithms.RsaSha384 => HashAlgorithmName.SHA384,
                                SecurityAlgorithms.RsaSha512 => HashAlgorithmName.SHA512,
                                SecurityAlgorithms.RsaSha256Signature => HashAlgorithmName.SHA256,
                                SecurityAlgorithms.RsaSha384Signature => HashAlgorithmName.SHA384,
                                SecurityAlgorithms.RsaSha512Signature => HashAlgorithmName.SHA512,

                                SecurityAlgorithms.RsaSsaPssSha256 => HashAlgorithmName.SHA256,
                                SecurityAlgorithms.RsaSsaPssSha384 => HashAlgorithmName.SHA384,
                                SecurityAlgorithms.RsaSsaPssSha512 => HashAlgorithmName.SHA512,
                                SecurityAlgorithms.RsaSsaPssSha256Signature => HashAlgorithmName.SHA256,
                                SecurityAlgorithms.RsaSsaPssSha384Signature => HashAlgorithmName.SHA384,
                                SecurityAlgorithms.RsaSsaPssSha512Signature => HashAlgorithmName.SHA512,

                                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID1266))
                            }
                        };

                        hash = CryptoConfig.CreateFromName(algorithm.Name) as HashAlgorithm;
                    }

                    return hash;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of creating an identity token entry.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class CreateIdentityTokenEntry : IOpenIddictServerHandler<ProcessSignInContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;
            private readonly IOpenIddictTokenManager _tokenManager;

            public CreateIdentityTokenEntry() => throw new InvalidOperationException(SR.GetResourceString(SR.ID1015));

            public CreateIdentityTokenEntry(
                [NotNull] IOpenIddictApplicationManager applicationManager,
                [NotNull] IOpenIddictTokenManager tokenManager)
            {
                _applicationManager = applicationManager;
                _tokenManager = tokenManager;
            }

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .AddFilter<RequireIdentityTokenIncluded>()
                    .UseScopedHandler<CreateIdentityTokenEntry>()
                    .SetOrder(AttachTokenDigests.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var principal = context.IdentityTokenPrincipal;
                if (principal == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1019));
                }

                var descriptor = new OpenIddictTokenDescriptor
                {
                    AuthorizationId = principal.GetAuthorizationId(),
                    CreationDate = principal.GetCreationDate(),
                    ExpirationDate = principal.GetExpirationDate(),
                    Principal = principal,
                    Status = Statuses.Valid,
                    Subject = principal.GetClaim(Claims.Subject),
                    Type = TokenTypeHints.IdToken
                };

                // If the client application is known, associate it with the token.
                if (!string.IsNullOrEmpty(context.Request.ClientId))
                {
                    var application = await _applicationManager.FindByClientIdAsync(context.Request.ClientId);
                    if (application == null)
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID1016));
                    }

                    descriptor.ApplicationId = await _applicationManager.GetIdAsync(application);
                }

                var token = await _tokenManager.CreateAsync(descriptor);
                if (token == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1018));
                }

                var identifier = await _tokenManager.GetIdAsync(token);

                // Attach the token identifier to the principal so that it can be stored in the token.
                principal.SetTokenId(identifier);

                context.Logger.LogTrace(SR.GetResourceString(SR.ID7028), identifier);
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating an identity token using IdentityModel.
        /// </summary>
        public class GenerateIdentityModelIdentityToken : IOpenIddictServerHandler<ProcessSignInContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireIdentityTokenIncluded>()
                    .UseSingletonHandler<GenerateIdentityModelIdentityToken>()
                    .SetOrder(CreateIdentityTokenEntry.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If an identity token was already attached by another handler, don't overwrite it.
                if (!string.IsNullOrEmpty(context.Response.IdToken))
                {
                    return default;
                }

                // Clone the principal and exclude the claim mapped to standard JWT claims.
                var principal = context.IdentityTokenPrincipal?.Clone(claim => claim.Type switch
                {
                    Claims.Private.Audience       => false,
                    Claims.Private.CreationDate   => false,
                    Claims.Private.ExpirationDate => false,
                    Claims.Private.TokenType      => false,

                    _ => true
                });

                if (principal == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1021));
                }

                var claims = new Dictionary<string, object>(StringComparer.Ordinal);

                // Set the public audience claims using the private audience claims from the principal.
                // Note: when there's a single audience, represent it as a unique string claim.
                var audiences = context.IdentityTokenPrincipal.GetAudiences();
                if (audiences.Any())
                {
                    claims.Add(Claims.Audience, audiences.Length switch
                    {
                        1 => audiences.ElementAt(0),
                        _ => audiences
                    });
                }

                var descriptor = new SecurityTokenDescriptor
                {
                    AdditionalHeaderClaims = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        [JwtHeaderParameterNames.Typ] = JsonWebTokenTypes.IdentityToken
                    },
                    Claims = claims,
                    Expires = context.IdentityTokenPrincipal.GetExpirationDate()?.UtcDateTime,
                    IssuedAt = context.IdentityTokenPrincipal.GetCreationDate()?.UtcDateTime,
                    Issuer = context.Issuer?.AbsoluteUri,
                    // Note: unlike other tokens, identity tokens can only be signed using an asymmetric key
                    // as they are meant to be validated by clients using the public keys exposed by the server.
                    SigningCredentials = context.Options.SigningCredentials.First(credentials =>
                        credentials.Key is AsymmetricSecurityKey),
                    Subject = (ClaimsIdentity) principal.Identity
                };

                // Sign and attach the identity token.
                var token = context.Options.JsonWebTokenHandler.CreateToken(descriptor);

                context.Response.IdToken = token;

                context.Logger.LogTrace(SR.GetResourceString(SR.ID7029), principal.GetClaim(Claims.JwtId), token, principal.Claims);

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of beautifying the user code returned to the client.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class BeautifyUserCode : IOpenIddictServerHandler<ProcessSignInContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    // Technically, this handler doesn't require that the degraded mode be disabled
                    // but the default CreateReferenceUserCodeEntry that creates the user code
                    // reference identifiers only works when the degraded mode is disabled.
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireUserCodeIncluded>()
                    .UseSingletonHandler<BeautifyUserCode>()
                    .SetOrder(GenerateIdentityModelIdentityToken.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // To make user codes easier to read and type by humans, a dash is automatically
                // appended before each new block of 4 integers. These dashes are expected to be
                // stripped from the user codes when receiving them at the verification endpoint.

                var builder = new StringBuilder(context.Response.UserCode);
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

                context.Response.UserCode = builder.ToString();

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of attaching additional access token properties to the sign-in response.
        /// </summary>
        public class AttachAccessTokenProperties : IOpenIddictServerHandler<ProcessSignInContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireAccessTokenIncluded>()
                    .UseSingletonHandler<AttachAccessTokenProperties>()
                    .SetOrder(BeautifyUserCode.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                context.Response.TokenType = TokenTypes.Bearer;

                // If an expiration date was set on the access token principal, return it to the client application.
                var date = context.AccessTokenPrincipal.GetExpirationDate();
                if (date.HasValue && date.Value > DateTimeOffset.UtcNow)
                {
                    context.Response.ExpiresIn = (long) ((date.Value - DateTimeOffset.UtcNow).TotalSeconds + .5);
                }

                // If the granted access token scopes differ from the requested scopes, return the granted scopes
                // list as a parameter to inform the client application of the fact the scopes set will be reduced.
                var scopes = new HashSet<string>(context.AccessTokenPrincipal.GetScopes(), StringComparer.Ordinal);
                if ((context.EndpointType == OpenIddictServerEndpointType.Token && context.Request.IsAuthorizationCodeGrantType()) ||
                    !scopes.SetEquals(context.Request.GetScopes()))
                {
                    context.Response.Scope = string.Join(" ", scopes);
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of attaching additional device code properties to the sign-in response.
        /// </summary>
        public class AttachDeviceCodeProperties : IOpenIddictServerHandler<ProcessSignInContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireDeviceCodeIncluded>()
                    .UseSingletonHandler<AttachDeviceCodeProperties>()
                    .SetOrder(AttachAccessTokenProperties.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var address = GetEndpointAbsoluteUri(context.Issuer, context.Options.VerificationEndpointUris.FirstOrDefault());
                if (address != null)
                {
                    var builder = new UriBuilder(address)
                    {
                        Query = string.Concat(Parameters.UserCode, "=", context.Response.UserCode)
                    };

                    context.Response[Parameters.VerificationUri] = address.AbsoluteUri;
                    context.Response[Parameters.VerificationUriComplete] = builder.Uri.AbsoluteUri;
                }

                // If an expiration date was set on the device code principal, return it to the client application.
                var date = context.DeviceCodePrincipal.GetExpirationDate();
                if (date.HasValue && date.Value > DateTimeOffset.UtcNow)
                {
                    context.Response.ExpiresIn = (long) ((date.Value - DateTimeOffset.UtcNow).TotalSeconds + .5);
                }

                return default;

                static Uri GetEndpointAbsoluteUri(Uri issuer, Uri endpoint)
                {
                    // If the endpoint is disabled (i.e a null address is specified), return null.
                    if (endpoint == null)
                    {
                        return null;
                    }

                    // If the endpoint address is already an absolute URL, return it as-is.
                    if (endpoint.IsAbsoluteUri)
                    {
                        return endpoint;
                    }

                    // At this stage, throw an exception if the issuer cannot be retrieved.
                    if (issuer == null || !issuer.IsAbsoluteUri)
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID1022));
                    }

                    // Ensure the issuer ends with a trailing slash, as it is necessary
                    // for Uri's constructor to correctly compute correct absolute URLs.
                    if (!issuer.OriginalString.EndsWith("/"))
                    {
                        issuer = new Uri(issuer.OriginalString + "/", UriKind.Absolute);
                    }

                    // Ensure the endpoint does not start with a leading slash, as it is necessary
                    // for Uri's constructor to correctly compute correct absolute URLs.
                    if (endpoint.OriginalString.StartsWith("/"))
                    {
                        endpoint = new Uri(endpoint.OriginalString.Substring(1, endpoint.OriginalString.Length - 1), UriKind.Relative);
                    }

                    return new Uri(issuer, endpoint);
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of ensuring that the sign-out demand
        /// is compatible with the type of the endpoint that handled the request.
        /// </summary>
        public class ValidateSignOutDemand : IOpenIddictServerHandler<ProcessSignOutContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignOutContext>()
                    .UseSingletonHandler<ValidateSignOutDemand>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessSignOutContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (context.EndpointType != OpenIddictServerEndpointType.Logout)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1023));
                }

                return default;
            }
        }
    }
}
