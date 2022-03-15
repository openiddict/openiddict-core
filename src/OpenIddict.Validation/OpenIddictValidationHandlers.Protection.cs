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
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Validation;

public static partial class OpenIddictValidationHandlers
{
    public static class Protection
    {
        public static ImmutableArray<OpenIddictValidationHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Token validation:
             */
            ResolveTokenValidationParameters.Descriptor,
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
            ValidateAuthorizationEntry.Descriptor);

        /// <summary>
        /// Contains the logic responsible of resolving the validation parameters used to validate tokens.
        /// </summary>
        public class ResolveTokenValidationParameters : IOpenIddictValidationHandler<ValidateTokenContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .AddFilter<RequireLocalValidation>()
                    .UseSingletonHandler<ResolveTokenValidationParameters>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateTokenContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var configuration = await context.Options.ConfigurationManager.GetConfigurationAsync(default) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0140));

                // Ensure the issuer resolved from the configuration matches the expected value.
                if (context.Options.Issuer is not null && configuration.Issuer != context.Options.Issuer)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0307));
                }

                // Clone the token validation parameters and set the issuer using the value found in the
                // OpenID Connect server configuration (that can be static or retrieved using discovery).
                var parameters = context.Options.TokenValidationParameters.Clone();

                parameters.ValidIssuers ??= configuration.Issuer switch
                {
                    null => null,

                    // If the issuer URI doesn't contain any path/query/fragment, allow both http://www.fabrikam.com
                    // and http://www.fabrikam.com/ (the recommended URI representation) to be considered valid.
                    // See https://datatracker.ietf.org/doc/html/rfc3986#section-6.2.3 for more information.
                    { AbsolutePath: "/", Query.Length: 0, Fragment.Length: 0 } issuer => new[]
                    {
                        issuer.AbsoluteUri, // Uri.AbsoluteUri is normalized and always contains a trailing slash.
                        issuer.AbsoluteUri.Substring(0, issuer.AbsoluteUri.Length - 1)
                    },

                    Uri issuer => new[] { issuer.AbsoluteUri }
                };

                parameters.ValidateIssuer = parameters.ValidIssuers is not null;

                // Combine the signing keys registered statically in the token validation parameters
                // with the signing keys resolved from the OpenID Connect server configuration.
                parameters.IssuerSigningKeys =
                    parameters.IssuerSigningKeys?.Concat(configuration.SigningKeys) ?? configuration.SigningKeys;

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

                        _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0003))
                    })
                };

                context.SecurityTokenHandler = context.Options.JsonWebTokenHandler;
                context.TokenValidationParameters = parameters;
            }
        }

        /// <summary>
        /// Contains the logic responsible of validating reference token identifiers.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ValidateReferenceTokenIdentifier : IOpenIddictValidationHandler<ValidateTokenContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public ValidateReferenceTokenIdentifier() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0139));

            public ValidateReferenceTokenIdentifier(IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .AddFilter<RequireLocalValidation>()
                    .AddFilter<RequireTokenEntryValidationEnabled>()
                    .UseScopedHandler<ValidateReferenceTokenIdentifier>()
                    .SetOrder(ResolveTokenValidationParameters.Descriptor.Order + 1_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateTokenContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Reference tokens are base64url-encoded payloads of exactly 256 bits (generated using a
                // crypto-secure RNG). If the token length differs, the token cannot be a reference token.
                if (context.Token.Length != 43)
                {
                    return;
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
                context.Token = payload;
                context.TokenId = await _tokenManager.GetIdAsync(token);
            }
        }

        /// <summary>
        /// Contains the logic responsible of validating tokens generated using IdentityModel.
        /// </summary>
        public class ValidateIdentityModelToken : IOpenIddictValidationHandler<ValidateTokenContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .AddFilter<RequireLocalValidation>()
                    .UseSingletonHandler<ValidateIdentityModelToken>()
                    .SetOrder(ValidateReferenceTokenIdentifier.Descriptor.Order + 1_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
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
                    // If validation failed because of an unrecognized key identifier, inform the configuration manager
                    // that the configuration MAY have be refreshed by sending a new discovery request to the server.
                    if (result.Exception is SecurityTokenSignatureKeyNotFoundException)
                    {
                        context.Options.ConfigurationManager.RequestRefresh();
                    }

                    context.Logger.LogTrace(result.Exception, SR.GetResourceString(SR.ID6000), context.Token);

                    context.Reject(
                        error: Errors.InvalidToken,
                        description: result.Exception switch
                        {
                            SecurityTokenInvalidIssuerException        => SR.GetResourceString(SR.ID2088),
                            SecurityTokenInvalidTypeException          => SR.GetResourceString(SR.ID2089),
                            SecurityTokenSignatureKeyNotFoundException => SR.GetResourceString(SR.ID2090),
                            SecurityTokenInvalidSignatureException     => SR.GetResourceString(SR.ID2091),

                            _ => SR.GetResourceString(SR.ID2004)
                        },
                        uri: result.Exception switch
                        {
                            SecurityTokenInvalidIssuerException        => SR.FormatID8000(SR.ID2088),
                            SecurityTokenInvalidTypeException          => SR.FormatID8000(SR.ID2089),
                            SecurityTokenSignatureKeyNotFoundException => SR.FormatID8000(SR.ID2090),
                            SecurityTokenInvalidSignatureException     => SR.FormatID8000(SR.ID2091),

                            _ => SR.FormatID8000(SR.ID2004)
                        });

                    return;
                }

                // Attach the principal extracted from the token to the parent event context and store
                // the token type (resolved from "typ" or "token_usage") as a special private claim.
                context.Principal = new ClaimsPrincipal(result.ClaimsIdentity).SetTokenType(result.TokenType switch
                {
                    null or { Length: 0 } => throw new InvalidOperationException(SR.GetResourceString(SR.ID0025)),

                    // Both at+jwt and application/at+jwt are supported for access tokens.
                    JsonWebTokenTypes.AccessToken or JsonWebTokenTypes.Prefixes.Application + JsonWebTokenTypes.AccessToken
                        => TokenTypeHints.AccessToken,

                    _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0003))
                });

                context.Logger.LogTrace(SR.GetResourceString(SR.ID6001), context.Token, context.Principal.Claims);
            }
        }

        /// <summary>
        /// Contains the logic responsible of validating the tokens using OAuth 2.0 introspection.
        /// </summary>
        public class IntrospectToken : IOpenIddictValidationHandler<ValidateTokenContext>
        {
            private readonly OpenIddictValidationService _service;

            public IntrospectToken(OpenIddictValidationService service)
                => _service = service;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .AddFilter<RequireIntrospectionValidation>()
                    .UseSingletonHandler<IntrospectToken>()
                    .SetOrder(ValidateIdentityModelToken.Descriptor.Order + 1_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
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

                Debug.Assert(!string.IsNullOrEmpty(context.Token), SR.GetResourceString(SR.ID4010));

                var configuration = await context.Options.ConfigurationManager.GetConfigurationAsync(default) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0140));

                // Ensure the issuer resolved from the configuration matches the expected value.
                if (context.Options.Issuer is not null && configuration.Issuer != context.Options.Issuer)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0307));
                }

                // Ensure the introspection endpoint is present and is a valid absolute URL.
                if (configuration.IntrospectionEndpoint is not { IsAbsoluteUri: true } ||
                   !configuration.IntrospectionEndpoint.IsWellFormedOriginalString())
                {
                    throw new InvalidOperationException(SR.FormatID0301(Metadata.IntrospectionEndpoint));
                }

                ClaimsPrincipal principal;

                try
                {
                    principal = await _service.IntrospectTokenAsync(configuration.IntrospectionEndpoint, context.Token, context.ValidTokenTypes.Count switch
                    {
                        // Infer the token type hint sent to the authorization server to help speed up
                        // the token resolution lookup. If multiple types are accepted, no hint is sent.
                        1 => context.ValidTokenTypes.ElementAt(0),
                        _ => null
                    }) ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0141));
                }

                catch (Exception exception)
                {
                    context.Logger.LogDebug(exception, SR.GetResourceString(SR.ID6155));

                    context.Reject(
                        error: Errors.InvalidToken,
                        description: SR.GetResourceString(SR.ID2004),
                        uri: SR.FormatID8000(SR.ID2004));

                    return;
                }

                // OpenIddict-based authorization servers always return the actual token type using
                // the special "token_usage" claim, that helps resource servers determine whether the
                // introspected token is one of the expected types and prevents token substitution attacks.
                //
                // If a "token_usage" claim can be extracted from the principal, use it to determine
                // whether the token details returned by the authorization server correspond to a
                // token whose type is considered acceptable based on the valid types collection.
                //
                // If the valid types collection is empty, all types of tokens are considered valid.
                var usage = principal.GetClaim(Claims.TokenUsage);
                if (!string.IsNullOrEmpty(usage) && context.ValidTokenTypes.Count > 0 &&
                    !context.ValidTokenTypes.Contains(usage))
                {
                    context.Reject(
                        error: Errors.InvalidToken,
                        description: SR.GetResourceString(SR.ID2110),
                        uri: SR.FormatID8000(SR.ID2110));

                    return;
                }

                // Note: at this point, the "token_usage" claim value is guaranteed to correspond
                // to a known value as it is checked when validating the introspection response.
                //
                // If no value could be resolved, the token is assumed to be an access token.
                context.Principal = principal.SetTokenType(usage ?? TokenTypeHints.AccessToken);

                context.Logger.LogTrace(SR.GetResourceString(SR.ID6154), context.Token, context.Principal.Claims);
            }
        }

        /// <summary>
        /// Contains the logic responsible of normalizing the scope claims stored in the tokens.
        /// </summary>
        public class NormalizeScopeClaims : IOpenIddictValidationHandler<ValidateTokenContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .UseSingletonHandler<NormalizeScopeClaims>()
                    .SetOrder(IntrospectToken.Descriptor.Order + 1_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
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
        public class MapInternalClaims : IOpenIddictValidationHandler<ValidateTokenContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .UseSingletonHandler<MapInternalClaims>()
                    .SetOrder(NormalizeScopeClaims.Descriptor.Order + 1_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
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
        /// Contains the logic responsible of restoring the properties associated with a reference token entry.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class RestoreReferenceTokenProperties : IOpenIddictValidationHandler<ValidateTokenContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public RestoreReferenceTokenProperties() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0139));

            public RestoreReferenceTokenProperties(IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .AddFilter<RequireLocalValidation>()
                    .AddFilter<RequireTokenEntryValidationEnabled>()
                    .UseScopedHandler<RestoreReferenceTokenProperties>()
                    .SetOrder(MapInternalClaims.Descriptor.Order + 1_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
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

                var token = await _tokenManager.FindByIdAsync(context.TokenId);
                if (token is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0021));
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
        /// Contains the logic responsible of rejecting authentication demands for which no valid principal was resolved.
        /// </summary>
        public class ValidatePrincipal : IOpenIddictValidationHandler<ValidateTokenContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .UseSingletonHandler<ValidatePrincipal>()
                    .SetOrder(RestoreReferenceTokenProperties.Descriptor.Order + 1_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
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
        /// Contains the logic responsible of rejecting authentication demands containing expired access tokens.
        /// </summary>
        public class ValidateExpirationDate : IOpenIddictValidationHandler<ValidateTokenContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .UseSingletonHandler<ValidateExpirationDate>()
                    .SetOrder(ValidatePrincipal.Descriptor.Order + 1_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
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
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6156));

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
        /// Contains the logic responsible of rejecting authentication demands containing
        /// access tokens that were issued to be used by another audience/resource server.
        /// </summary>
        public class ValidateAudience : IOpenIddictValidationHandler<ValidateTokenContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .UseSingletonHandler<ValidateAudience>()
                    .SetOrder(ValidateExpirationDate.Descriptor.Order + 1_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateTokenContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

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
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6157));

                    context.Reject(
                        error: Errors.InvalidToken,
                        description: SR.GetResourceString(SR.ID2093),
                        uri: SR.FormatID8000(SR.ID2093));

                    return default;
                }

                // If the access token doesn't include any registered audience, return an error.
                if (!audiences.Intersect(context.Options.Audiences, StringComparer.Ordinal).Any())
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6158));

                    context.Reject(
                        error: Errors.InvalidToken,
                        description: SR.GetResourceString(SR.ID2094),
                        uri: SR.FormatID8000(SR.ID2094));

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
        public class ValidateTokenEntry : IOpenIddictValidationHandler<ValidateTokenContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public ValidateTokenEntry() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0139));

            public ValidateTokenEntry(IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .AddFilter<RequireLocalValidation>()
                    .AddFilter<RequireTokenEntryValidationEnabled>()
                    .UseScopedHandler<ValidateTokenEntry>()
                    .SetOrder(ValidateAudience.Descriptor.Order + 1_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateTokenContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

                var identifier = context.Principal.GetTokenId();
                if (string.IsNullOrEmpty(identifier))
                {
                    return;
                }

                var token = await _tokenManager.FindByIdAsync(identifier);
                if (token is null || !await _tokenManager.HasStatusAsync(token, Statuses.Valid))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6005), identifier);

                    context.Reject(
                        error: Errors.InvalidToken,
                        description: SR.GetResourceString(SR.ID2019),
                        uri: SR.FormatID8000(SR.ID2019));

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
        public class ValidateAuthorizationEntry : IOpenIddictValidationHandler<ValidateTokenContext>
        {
            private readonly IOpenIddictAuthorizationManager _authorizationManager;

            public ValidateAuthorizationEntry() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0142));

            public ValidateAuthorizationEntry(IOpenIddictAuthorizationManager authorizationManager)
                => _authorizationManager = authorizationManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .AddFilter<RequireLocalValidation>()
                    .AddFilter<RequireAuthorizationEntryValidationEnabled>()
                    .UseScopedHandler<ValidateAuthorizationEntry>()
                    .SetOrder(ValidateTokenEntry.Descriptor.Order + 1_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
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
                        description: SR.GetResourceString(SR.ID2023),
                        uri: SR.FormatID8000(SR.ID2023));

                    return;
                }
            }
        }
    }
}
