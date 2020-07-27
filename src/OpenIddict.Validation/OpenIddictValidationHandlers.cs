/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Validation.OpenIddictValidationEvents;
using static OpenIddict.Validation.OpenIddictValidationHandlerFilters;
using Properties = OpenIddict.Validation.OpenIddictValidationConstants.Properties;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.Validation
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static partial class OpenIddictValidationHandlers
    {
        public static ImmutableArray<OpenIddictValidationHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Authentication processing:
             */
            ValidateToken.Descriptor,
            ValidateReferenceTokenIdentifier.Descriptor,
            ValidateIdentityModelToken.Descriptor,
            IntrospectToken.Descriptor,
            NormalizeScopeClaims.Descriptor,
            MapInternalClaims.Descriptor,
            RestoreReferenceTokenProperties.Descriptor,
            ValidatePrincipal.Descriptor,
            ValidateExpirationDate.Descriptor,
            ValidateAudience.Descriptor,
            ValidateTokenEntry.Descriptor,
            ValidateAuthorizationEntry.Descriptor,

            /*
             * Challenge processing:
             */
            AttachDefaultChallengeError.Descriptor)

            .AddRange(Discovery.DefaultHandlers)
            .AddRange(Introspection.DefaultHandlers);

        /// <summary>
        /// Contains the logic responsible of ensuring a token was correctly resolved from the context.
        /// </summary>
        public class ValidateToken : IOpenIddictValidationHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .UseSingletonHandler<ValidateToken>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessAuthenticationContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Note: unlike the equivalent event in the server stack, authentication can be triggered for
                // arbitrary requests (typically, API endpoints that are not owned by the validation stack).
                // As such, the token is not directly resolved from the request, that may be null at this stage.
                // Instead, the token is expected to be populated by one or multiple handlers provided by the host.
                //
                // Note: this event can also be triggered by the validation service to validate an arbitrary token.

                if (string.IsNullOrEmpty(context.Token))
                {
                    context.Reject(
                        error: Errors.MissingToken,
                        description: context.Localizer[SR.ID3000]);

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of validating reference token identifiers.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ValidateReferenceTokenIdentifier : IOpenIddictValidationHandler<ProcessAuthenticationContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public ValidateReferenceTokenIdentifier() => throw new InvalidOperationException(SR.GetResourceString(SR.ID1138));

            public ValidateReferenceTokenIdentifier(IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireLocalValidation>()
                    .AddFilter<RequireTokenEntryValidationEnabled>()
                    .UseScopedHandler<ValidateReferenceTokenIdentifier>()
                    .SetOrder(ValidateToken.Descriptor.Order + 1_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessAuthenticationContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Reference tokens are base64url-encoded payloads of exactly 256 bits (generated using a
                // crypto-secure RNG). If the token length differs, the token cannot be a reference token.
                if (string.IsNullOrEmpty(context.Token) || context.Token.Length != 43)
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
                        error: Errors.InvalidToken,
                        description: context.Localizer[SR.ID3027]);

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
        public class ValidateIdentityModelToken : IOpenIddictValidationHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireLocalValidation>()
                    .UseSingletonHandler<ValidateIdentityModelToken>()
                    .SetOrder(ValidateReferenceTokenIdentifier.Descriptor.Order + 1_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessAuthenticationContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If a principal was already attached, don't overwrite it.
                if (context.Principal != null)
                {
                    return;
                }

                // If the token cannot be read, don't return an error to allow another handler to validate it.
                if (!context.Options.JsonWebTokenHandler.CanReadToken(context.Token))
                {
                    return;
                }

                var configuration = await context.Options.ConfigurationManager.GetConfigurationAsync(default) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1139));

                // Clone the token validation parameters and set the issuer using the value found in the
                // OpenID Connect server configuration (that can be static or retrieved using discovery).
                var parameters = context.Options.TokenValidationParameters.Clone();
                parameters.ValidIssuer ??= configuration.Issuer ?? context.Issuer?.AbsoluteUri;
                parameters.ValidateIssuer = !string.IsNullOrEmpty(parameters.ValidIssuer);

                // Combine the signing keys registered statically in the token validation parameters
                // with the signing keys resolved from the OpenID Connect server configuration.
                parameters.IssuerSigningKeys =
                    parameters.IssuerSigningKeys?.Concat(configuration.SigningKeys) ?? configuration.SigningKeys;

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

                    _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID1002))
                };

                var result = context.Options.JsonWebTokenHandler.ValidateToken(context.Token, parameters);
                if (!result.IsValid)
                {
                    // If validation failed because of an unrecognized key identifier, inform the configuration manager
                    // that the configuration MAY have be refreshed by sending a new discovery request to the server.
                    if (result.Exception is SecurityTokenSignatureKeyNotFoundException)
                    {
                        context.Options.ConfigurationManager.RequestRefresh();
                    }

                    context.Logger.LogTrace(result.Exception, SR.GetResourceString(SR.ID7000), context.Token);

                    context.Reject(
                        error: Errors.InvalidToken,
                        description: result.Exception switch
                        {
                            SecurityTokenInvalidIssuerException        _ => context.Localizer[SR.ID3088],
                            SecurityTokenInvalidTypeException          _ => context.Localizer[SR.ID3089],
                            SecurityTokenSignatureKeyNotFoundException _ => context.Localizer[SR.ID3090],
                            SecurityTokenInvalidSignatureException     _ => context.Localizer[SR.ID3091],

                            _ => context.Localizer[SR.ID3027]
                        });

                    return;
                }

                // Attach the principal extracted from the token to the parent event context.
                context.Principal = new ClaimsPrincipal(result.ClaimsIdentity);

                // Store the token type (resolved from "typ" or "token_usage") as a special private claim.
                context.Principal.SetTokenType(result.TokenType switch
                {
                    var type when string.IsNullOrEmpty(type) => throw new InvalidOperationException(SR.GetResourceString(SR.ID1024)),

                    JsonWebTokenTypes.AccessToken                                          => TokenTypeHints.AccessToken,
                    JsonWebTokenTypes.Prefixes.Application + JsonWebTokenTypes.AccessToken => TokenTypeHints.AccessToken,

                    _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID1002))
                });

                context.Logger.LogTrace(SR.GetResourceString(SR.ID7001), context.Token, context.Principal.Claims);
            }
        }

        /// <summary>
        /// Contains the logic responsible of validating the tokens using OAuth 2.0 introspection.
        /// </summary>
        public class IntrospectToken : IOpenIddictValidationHandler<ProcessAuthenticationContext>
        {
            private readonly OpenIddictValidationService _service;

            public IntrospectToken(OpenIddictValidationService service)
                => _service = service;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireIntrospectionValidation>()
                    .UseSingletonHandler<IntrospectToken>()
                    .SetOrder(ValidateIdentityModelToken.Descriptor.Order + 1_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessAuthenticationContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If a principal was already attached, don't overwrite it.
                if (context.Principal != null)
                {
                    return;
                }

                Debug.Assert(!string.IsNullOrEmpty(context.Token), SR.GetResourceString(SR.ID5010));

                var configuration = await context.Options.ConfigurationManager.GetConfigurationAsync(default) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1139));

                if (string.IsNullOrEmpty(configuration.IntrospectionEndpoint) ||
                    !Uri.TryCreate(configuration.IntrospectionEndpoint, UriKind.Absolute, out Uri? address) ||
                    !address.IsWellFormedOriginalString())
                {
                    context.Reject(
                        error: Errors.ServerError,
                        description: context.Localizer[SR.ID3092]);

                    return;
                }

                try
                {
                    var principal = await _service.IntrospectTokenAsync(address, context.Token, context.TokenType) ??
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID1140));

                    // Note: tokens that are considered valid at this point are assumed to be of the given type,
                    // as the introspection handlers ensure the introspected token type matches the expected
                    // type when a "token_usage" claim was returned as part of the introspection response.
                    // If no token type can be inferred, the token is assumed to be an access token.
                    context.Principal = principal.SetTokenType(context.TokenType ?? TokenTypeHints.AccessToken);

                    context.Logger.LogTrace(SR.GetResourceString(SR.ID7154), context.Token, context.Principal.Claims);
                }

                catch (Exception exception)
                {
                    context.Logger.LogDebug(exception, SR.GetResourceString(SR.ID7155));

                    context.Reject(
                        error: Errors.InvalidToken,
                        description: context.Localizer[SR.ID3027]);

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of normalizing the scope claims stored in the tokens.
        /// </summary>
        public class NormalizeScopeClaims : IOpenIddictValidationHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .UseSingletonHandler<NormalizeScopeClaims>()
                    .SetOrder(IntrospectToken.Descriptor.Order + 1_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessAuthenticationContext context)
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
        public class MapInternalClaims : IOpenIddictValidationHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .UseSingletonHandler<MapInternalClaims>()
                    .SetOrder(NormalizeScopeClaims.Descriptor.Order + 1_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessAuthenticationContext context)
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
        public class RestoreReferenceTokenProperties : IOpenIddictValidationHandler<ProcessAuthenticationContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public RestoreReferenceTokenProperties() => throw new InvalidOperationException(SR.GetResourceString(SR.ID1138));

            public RestoreReferenceTokenProperties(IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireLocalValidation>()
                    .AddFilter<RequireTokenEntryValidationEnabled>()
                    .UseScopedHandler<RestoreReferenceTokenProperties>()
                    .SetOrder(MapInternalClaims.Descriptor.Order + 1_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessAuthenticationContext context)
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
        public class ValidatePrincipal : IOpenIddictValidationHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .UseSingletonHandler<ValidatePrincipal>()
                    .SetOrder(RestoreReferenceTokenProperties.Descriptor.Order + 1_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessAuthenticationContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (context.Principal == null)
                {
                    context.Reject(
                        error: Errors.InvalidToken,
                        description: context.Localizer[SR.ID3027]);

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
        /// Contains the logic responsible of rejecting authentication demands containing expired access tokens.
        /// </summary>
        public class ValidateExpirationDate : IOpenIddictValidationHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .UseSingletonHandler<ValidateExpirationDate>()
                    .SetOrder(ValidatePrincipal.Descriptor.Order + 1_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessAuthenticationContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(context.Principal != null, SR.GetResourceString(SR.ID5006));

                var date = context.Principal.GetExpirationDate();
                if (date.HasValue && date.Value < DateTimeOffset.UtcNow)
                {
                    context.Logger.LogError(SR.GetResourceString(SR.ID7156));

                    context.Reject(
                        error: Errors.InvalidToken,
                        description: context.Localizer[SR.ID3019]);

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of rejecting authentication demands containing
        /// access tokens that were issued to be used by another audience/resource server.
        /// </summary>
        public class ValidateAudience : IOpenIddictValidationHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .UseSingletonHandler<ValidateAudience>()
                    .SetOrder(ValidateExpirationDate.Descriptor.Order + 1_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessAuthenticationContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(context.Principal != null, SR.GetResourceString(SR.ID5006));

                // If no explicit audience has been configured,
                // skip the default audience validation.
                if (context.Options.Audiences.Count == 0)
                {
                    return default;
                }

                // If the access token doesn't have any audience attached, return an error.
                var audiences = context.Principal.GetAudiences();
                if (audiences.IsDefaultOrEmpty)
                {
                    context.Logger.LogError(SR.GetResourceString(SR.ID7157));

                    context.Reject(
                        error: Errors.InvalidToken,
                        description: context.Localizer[SR.ID3093]);

                    return default;
                }

                // If the access token doesn't include any registered audience, return an error.
                if (!audiences.Intersect(context.Options.Audiences, StringComparer.Ordinal).Any())
                {
                    context.Logger.LogError(SR.GetResourceString(SR.ID7158));

                    context.Reject(
                        error: Errors.InvalidToken,
                        description: context.Localizer[SR.ID3094]);

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of authentication demands a token whose
        /// associated token entry is no longer valid (e.g was revoked).
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ValidateTokenEntry : IOpenIddictValidationHandler<ProcessAuthenticationContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public ValidateTokenEntry() => throw new InvalidOperationException(SR.GetResourceString(SR.ID1138));

            public ValidateTokenEntry(IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireLocalValidation>()
                    .AddFilter<RequireTokenEntryValidationEnabled>()
                    .UseScopedHandler<ValidateTokenEntry>()
                    .SetOrder(ValidateAudience.Descriptor.Order + 1_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessAuthenticationContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(context.Principal != null, SR.GetResourceString(SR.ID5006));

                var identifier = context.Principal.GetTokenId();
                if (string.IsNullOrEmpty(identifier))
                {
                    return;
                }

                var token = await _tokenManager.FindByIdAsync(identifier);
                if (token == null || !await _tokenManager.HasStatusAsync(token, Statuses.Valid))
                {
                    context.Logger.LogError(SR.GetResourceString(SR.ID7005), identifier);

                    context.Reject(
                        error: Errors.InvalidToken,
                        description: context.Localizer[SR.ID3019]);

                    return;
                }

                // Restore the creation/expiration dates/identifiers from the token entry metadata.
                context.Principal.SetCreationDate(await _tokenManager.GetCreationDateAsync(token))
                                 .SetExpirationDate(await _tokenManager.GetExpirationDateAsync(token))
                                 .SetAuthorizationId(await _tokenManager.GetAuthorizationIdAsync(token))
                                 .SetTokenId(await _tokenManager.GetIdAsync(token))
                                 .SetTokenType(await _tokenManager.GetTypeAsync(token));
            }
        }

        /// <summary>
        /// Contains the logic responsible of authentication demands a token whose
        /// associated authorization entry is no longer valid (e.g was revoked).
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ValidateAuthorizationEntry : IOpenIddictValidationHandler<ProcessAuthenticationContext>
        {
            private readonly IOpenIddictAuthorizationManager _authorizationManager;

            public ValidateAuthorizationEntry() => throw new InvalidOperationException(SR.GetResourceString(SR.ID1141));

            public ValidateAuthorizationEntry(IOpenIddictAuthorizationManager authorizationManager)
                => _authorizationManager = authorizationManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireLocalValidation>()
                    .AddFilter<RequireAuthorizationEntryValidationEnabled>()
                    .UseScopedHandler<ValidateAuthorizationEntry>()
                    .SetOrder(ValidateTokenEntry.Descriptor.Order + 1_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessAuthenticationContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(context.Principal != null, SR.GetResourceString(SR.ID5006));

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
                        error: Errors.InvalidToken,
                        description: context.Localizer[SR.ID3023]);

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of ensuring that the challenge response contains an appropriate error.
        /// </summary>
        public class AttachDefaultChallengeError : IOpenIddictValidationHandler<ProcessChallengeContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                    .UseSingletonHandler<AttachDefaultChallengeError>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessChallengeContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If an error was explicitly set by the application, don't override it.
                if (!string.IsNullOrEmpty(context.Response.Error) ||
                    !string.IsNullOrEmpty(context.Response.ErrorDescription) ||
                    !string.IsNullOrEmpty(context.Response.ErrorUri))
                {
                    return default;
                }

                // Try to retrieve the authentication context from the validation transaction and use
                // the error details returned during the authentication processing, if available.
                // If no error is attached to the authentication context, this likely means that
                // the request was rejected very early without even checking the access token or was
                // rejected due to a lack of permission. In this case, return an insufficient_access error
                // to inform the client that the user is not allowed to perform the requested action.

                var notification = context.Transaction.GetProperty<ProcessAuthenticationContext>(
                    typeof(ProcessAuthenticationContext).FullName!);

                if (!string.IsNullOrEmpty(notification?.Error))
                {
                    context.Response.Error = notification.Error;
                    context.Response.ErrorDescription = notification.ErrorDescription;
                    context.Response.ErrorUri = notification.ErrorUri;
                }

                else
                {
                    context.Response.Error = Errors.InsufficientAccess;
                    context.Response.ErrorDescription = context.Localizer[SR.ID3095];
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of extracting potential errors from the response.
        /// </summary>
        public class HandleErrorResponse<TContext> : IOpenIddictValidationHandler<TContext> where TContext : BaseValidatingContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<TContext>()
                    .UseSingletonHandler<HandleErrorResponse<TContext>>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(TContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (!string.IsNullOrEmpty(context.Transaction.Response?.Error))
                {
                    context.Reject(
                        error: context.Transaction.Response.Error,
                        description: context.Transaction.Response.ErrorDescription,
                        uri: context.Transaction.Response.ErrorUri);

                    return default;
                }

                return default;
            }
        }
    }
}
