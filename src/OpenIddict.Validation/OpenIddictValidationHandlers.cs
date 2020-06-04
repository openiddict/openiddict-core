/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Validation.OpenIddictValidationEvents;
using static OpenIddict.Validation.OpenIddictValidationHandlerFilters;
using Properties = OpenIddict.Validation.OpenIddictValidationConstants.Properties;

namespace OpenIddict.Validation
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static partial class OpenIddictValidationHandlers
    {
        public static ImmutableArray<OpenIddictValidationHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Authentication processing:
             */
            ValidateAccessTokenParameter.Descriptor,
            ValidateReferenceTokenIdentifier.Descriptor,
            ValidateIdentityModelToken.Descriptor,
            IntrospectToken.Descriptor,
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
        /// Contains the logic responsible of validating the access token resolved from the current request.
        /// </summary>
        public class ValidateAccessTokenParameter : IOpenIddictValidationHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .UseSingletonHandler<ValidateAccessTokenParameter>()
                    .SetOrder(int.MinValue + 100_000)
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

                if (string.IsNullOrEmpty(context.Request.AccessToken))
                {
                    context.Reject(
                        error: Errors.MissingToken,
                        description: "The access token is missing.");

                    return default;
                }

                context.Token = context.Request.AccessToken;
                context.TokenType = TokenTypeHints.AccessToken;

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

            public ValidateReferenceTokenIdentifier() => throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling token entry validation.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .ToString());

            public ValidateReferenceTokenIdentifier([NotNull] IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireLocalValidation>()
                    .AddFilter<RequireTokenEntryValidationEnabled>()
                    .UseScopedHandler<ValidateReferenceTokenIdentifier>()
                    .SetOrder(ValidateAccessTokenParameter.Descriptor.Order + 1_000)
                    .Build();

            public async ValueTask HandleAsync([NotNull] ProcessAuthenticationContext context)
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
                        description: "The specified token is not valid.");

                    return;
                }

                var payload = await _tokenManager.GetPayloadAsync(token);
                if (string.IsNullOrEmpty(payload))
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .AppendLine("The payload associated with a reference token cannot be retrieved.")
                        .Append("This may indicate that the token entry was corrupted.")
                        .ToString());
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
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async ValueTask HandleAsync([NotNull] ProcessAuthenticationContext context)
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

                // If the token cannot be validated, don't return an error to allow another handler to validate it.
                if (!context.Options.JsonWebTokenHandler.CanReadToken(context.Token))
                {
                    return;
                }

                var configuration = await context.Options.ConfigurationManager.GetConfigurationAsync(default) ??
                    throw new InvalidOperationException("An unknown error occurred while retrieving the server configuration.");

                // Clone the token validation parameters and set the issuer and the signing keys using the
                // OpenID Connect server configuration (that can be static or retrieved using discovery).
                var parameters = context.Options.TokenValidationParameters.Clone();
                parameters.ValidIssuer = configuration.Issuer ?? context.Issuer?.AbsoluteUri;
                parameters.IssuerSigningKeys = configuration.SigningKeys;

                // If a specific token type is expected, override the default valid types to reject
                // security tokens whose actual token type doesn't match the expected token type.
                if (!string.IsNullOrEmpty(context.TokenType))
                {
                    parameters.ValidTypes = new[]
                    {
                        context.TokenType switch
                        {
                            TokenTypeHints.AccessToken => JsonWebTokenTypes.AccessToken,

                            _ => throw new InvalidOperationException("The token type is not supported.")
                        }
                    };
                }

                // Populate the token decryption keys from the encryption credentials set in the options.
                parameters.TokenDecryptionKeys =
                    from credentials in context.Options.EncryptionCredentials
                    select credentials.Key;

                // If the token cannot be validated, don't return an error to allow another handle to validate it.
                var result = context.Options.JsonWebTokenHandler.ValidateToken(context.Token, parameters);
                if (!result.IsValid)
                {
                    // If validation failed because of an unrecognized key identifier, inform the configuration manager
                    // that the configuration MAY have be refreshed by sending a new discovery request to the server.
                    if (result.Exception is SecurityTokenSignatureKeyNotFoundException)
                    {
                        context.Options.ConfigurationManager.RequestRefresh();
                    }

                    context.Logger.LogTrace(result.Exception, "An error occurred while validating the token '{Token}'.", context.Token);

                    return;
                }

                // Attach the principal extracted from the token to the parent event context.
                context.Principal = new ClaimsPrincipal(result.ClaimsIdentity);

                // Store the token type (resolved from "typ" or "token_usage") as a special private claim.
                context.Principal.SetTokenType(result.TokenType switch
                {
                    JsonWebTokenTypes.AccessToken => TokenTypeHints.AccessToken,

                    _ => throw new InvalidOperationException("The token type is not supported.")
                });

                context.Logger.LogTrace("The self-contained JWT token '{Token}' was successfully validated and the following " +
                                        "claims could be extracted: {Claims}.", context.Token, context.Principal.Claims);
            }
        }

        /// <summary>
        /// Contains the logic responsible of validating the tokens using OAuth 2.0 introspection.
        /// </summary>
        public class IntrospectToken : IOpenIddictValidationHandler<ProcessAuthenticationContext>
        {
            private readonly OpenIddictValidationService _service;

            public IntrospectToken([NotNull] OpenIddictValidationService service)
                => _service = service;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireIntrospectionValidation>()
                    .UseSingletonHandler<IntrospectToken>()
                    .SetOrder(ValidateIdentityModelToken.Descriptor.Order + 1_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async ValueTask HandleAsync([NotNull] ProcessAuthenticationContext context)
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

                var configuration = await context.Options.ConfigurationManager.GetConfigurationAsync(default) ??
                    throw new InvalidOperationException("An unknown error occurred while retrieving the server configuration.");

                if (string.IsNullOrEmpty(configuration.IntrospectionEndpoint) ||
                    !Uri.TryCreate(configuration.IntrospectionEndpoint, UriKind.Absolute, out Uri address) ||
                    !address.IsWellFormedOriginalString())
                {
                    context.Reject(
                        error: Errors.ServerError,
                        description: "This resource server is currently unavailable. Try again later.");

                    return;
                }

                try
                {
                    var principal = await _service.IntrospectTokenAsync(address, context.Token, TokenTypeHints.AccessToken) ??
                        throw new InvalidOperationException("An unknown error occurred while introspecting the access token.");

                    // Note: tokens that are considered valid at this point are assumed to be access tokens,
                    // as the introspection handlers ensure the introspected token type matches the expected
                    // type when a "token_usage" claim was returned as part of the introspection response.
                    context.Principal = principal.SetTokenType(TokenTypeHints.AccessToken);

                    context.Logger.LogTrace("The token '{Token}' was successfully introspected and the following claims " +
                                            "could be extracted: {Claims}.", context.Token, context.Principal.Claims);
                }

                catch (Exception exception)
                {
                    context.Logger.LogDebug(exception, "An error occurred while introspecting the access token.");

                    // If an error occurred while introspecting the token, allow other handlers to validate it.
                }
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
                    .SetOrder(IntrospectToken.Descriptor.Order + 1_000)
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
                //
                // Note: in previous OpenIddict versions, scopes were represented as a JSON array
                // and deserialized as multiple claims. In OpenIddict 3.0, the public "scope" claim
                // is formatted as a unique space-separated string containing all the granted scopes.
                // To ensure access tokens generated by previous versions are still correctly handled,
                // both formats (unique space-separated string or multiple scope claims) must be supported.
                // Visit https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-04 for more information.
                if (!context.Principal.HasScope())
                {
                    var scopes = context.Principal.GetClaims(Claims.Scope);
                    if (scopes.Length == 1)
                    {
                        scopes = scopes[0].Split(Separators.Space, StringSplitOptions.RemoveEmptyEntries).ToImmutableArray();
                    }

                    if (scopes.Any())
                    {
                        context.Principal.SetScopes(scopes);
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

            public RestoreReferenceTokenProperties() => throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling token entry validation.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .ToString());

            public RestoreReferenceTokenProperties([NotNull] IOpenIddictTokenManager tokenManager)
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

                if (!context.Transaction.Properties.TryGetValue(Properties.ReferenceTokenIdentifier, out var identifier))
                {
                    return;
                }

                var token = await _tokenManager.FindByIdAsync((string) identifier);
                if (token == null)
                {
                    throw new InvalidOperationException("The token entry cannot be found in the database.");
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
                        error: Errors.InvalidToken,
                        description: "The specified token is not valid.");

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
                        throw new InvalidOperationException(new StringBuilder()
                            .AppendLine("The deserialized principal doesn't contain the mandatory 'oi_tkn_typ' claim.")
                            .Append("When implementing custom token deserialization, a 'oi_tkn_typ' claim containing ")
                            .Append("the type of the token being processed must be added to the security principal.")
                            .ToString());
                    }

                    if (!string.Equals(type, context.TokenType, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidOperationException(new StringBuilder()
                            .AppendFormat("The type of token associated with the deserialized principal ({0}) ", type)
                            .AppendFormat("doesn't match the expected token type ({0}).", context.TokenType)
                            .ToString());
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

                var date = context.Principal.GetExpirationDate();
                if (date.HasValue && date.Value < DateTimeOffset.UtcNow)
                {
                    context.Logger.LogError("The authentication demand was rejected because the token was expired.");

                    context.Reject(
                        error: Errors.InvalidToken,
                        description: "The specified access token is no longer valid.");

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
                    context.Logger.LogError("The authentication demand was rejected because the token had no audience attached.");

                    context.Reject(
                        error: Errors.InvalidToken,
                        description: "The specified access token doesn't contain any audience.");

                    return default;
                }

                // If the access token doesn't include any registered audience, return an error.
                if (!audiences.Intersect(context.Options.Audiences, StringComparer.Ordinal).Any())
                {
                    context.Logger.LogError("The authentication demand was rejected because the token had no valid audience.");

                    context.Reject(
                        error: Errors.InvalidToken,
                        description: "The specified access token cannot be used with this resource server.");

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

            public ValidateTokenEntry() => throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling token entry validation.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .ToString());

            public ValidateTokenEntry([NotNull] IOpenIddictTokenManager tokenManager)
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
                    .Build();

            public async ValueTask HandleAsync([NotNull] ProcessAuthenticationContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var identifier = context.Principal.GetTokenId();
                if (string.IsNullOrEmpty(identifier))
                {
                    return;
                }

                var token = await _tokenManager.FindByIdAsync(identifier);
                if (token == null || !await _tokenManager.HasStatusAsync(token, Statuses.Valid))
                {
                    context.Logger.LogError("The token '{Identifier}' was no longer valid.", identifier);

                    context.Reject(
                        error: Errors.InvalidToken,
                        description: "The token is no longer valid.");

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

            public ValidateAuthorizationEntry() => throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling authorization entry validation.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .ToString());

            public ValidateAuthorizationEntry([NotNull] IOpenIddictAuthorizationManager authorizationManager)
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
                    context.Logger.LogError("The authorization '{Identifier}' was no longer valid.", identifier);

                    context.Reject(
                        error: Errors.InvalidToken,
                        description: "The authorization associated with the token is no longer valid.");

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
                    typeof(ProcessAuthenticationContext).FullName);

                if (!string.IsNullOrEmpty(notification?.Error))
                {
                    context.Response.Error = notification.Error;
                    context.Response.ErrorDescription = notification.ErrorDescription;
                    context.Response.ErrorUri = notification.ErrorUri;
                }

                else
                {
                    context.Response.Error = Errors.InsufficientAccess;
                    context.Response.ErrorDescription = "The user represented by the token is not allowed to perform the requested action.";
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
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] TContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (!string.IsNullOrEmpty(context.Response.Error))
                {
                    context.Reject(
                        error: context.Response.Error,
                        description: context.Response.ErrorDescription,
                        uri: context.Response.ErrorUri);

                    return default;
                }

                return default;
            }
        }
    }
}
