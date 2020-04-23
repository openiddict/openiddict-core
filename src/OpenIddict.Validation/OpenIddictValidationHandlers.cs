/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.ComponentModel;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
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
            AttachDefaultChallengeError.Descriptor);

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
                    context.Logger.LogError("The request was rejected because the access token was missing.");

                    context.Reject(
                        error: Errors.MissingToken,
                        description: "The access token is missing.");

                    return default;
                }

                context.Token = context.Request.AccessToken;

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
                .AppendLine("The core services must be registered when enabling reference tokens support.")
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
                    .AddFilter<RequireTokenValidationEnabled>()
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

                var type = await _tokenManager.GetTypeAsync(token);
                if (!string.Equals(type, TokenTypeHints.AccessToken, StringComparison.OrdinalIgnoreCase))
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

                // If the token cannot be validated, don't return an error to allow another handle to validate it.
                if (!context.Options.JsonWebTokenHandler.CanReadToken(context.Token))
                {
                    return default;
                }

                // If no issuer signing key was attached, don't return an error to allow another handle to validate it.
                var parameters = context.TokenValidationParameters;
                if (parameters?.IssuerSigningKeys == null)
                {
                    return default;
                }

                // Clone the token validation parameters before mutating them.
                parameters = parameters.Clone();
                parameters.TokenDecryptionKeys = context.Options.EncryptionCredentials.Select(credentials => credentials.Key);
                parameters.ValidIssuer = context.Issuer?.AbsoluteUri;

                // If the token cannot be validated, don't return an error to allow another handle to validate it.
                var result = context.Options.JsonWebTokenHandler.ValidateToken(context.Token, parameters);
                if (!result.IsValid)
                {
                    context.Logger.LogTrace(result.Exception, "An error occurred while validating the token '{Token}'.", context.Token);

                    return default;
                }

                // Note: tokens that are considered valid at this point are guaranteed to be access tokens,
                // as a "typ" header validation is performed by the JWT handler, based on the valid values
                // set in the token validation parameters (by default, only "at+jwt" is considered valid).
                context.Principal = new ClaimsPrincipal(result.ClaimsIdentity).SetTokenType(TokenTypeHints.AccessToken);

                context.Logger.LogTrace("The self-contained JWT token '{Token}' was successfully validated and the following " +
                                        "claims could be extracted: {Claims}.", context.Token, context.Principal.Claims);

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
                    .SetOrder(ValidateIdentityModelToken.Descriptor.Order + 1_000)
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

                // Map the standardized "azp" and "scope" claims to their "oi_" equivalent so that
                // the ClaimsPrincipal extensions exposed by OpenIddict return consistent results.
                if (!context.Principal.HasPresenter())
                {
                    context.Principal.SetPresenters(context.Principal.GetClaims(Claims.AuthorizedParty));
                }

                // Note: in previous OpenIddict versions, scopes were represented as a JSON array
                // and deserialized as multiple claims. In OpenIddict 3.0, the public "scope" claim
                // is formatted as a unique space-separated string containing all the granted scopes.
                // To ensure access tokens generated by previous versions are still correctly handled,
                // both formats (unique space-separated string or multiple scope claims) must be supported.
                // Visit https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-03 for more information.
                if (!context.Principal.HasScope())
                {
                    var scopes = context.Principal.GetClaims(Claims.Scope);
                    if (scopes.Length == 1)
                    {
                        scopes = scopes[0].Split(Separators.Space, StringSplitOptions.RemoveEmptyEntries).ToImmutableArray();
                    }

                    context.Principal.SetScopes(scopes);
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
                .AppendLine("The core services must be registered when enabling reference tokens support.")
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
                    .AddFilter<RequireTokenValidationEnabled>()
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
                    .SetInternalAuthorizationId(await _tokenManager.GetAuthorizationIdAsync(token))
                    .SetInternalTokenId(await _tokenManager.GetIdAsync(token))
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
                    .SetOrder(ValidateIdentityModelToken.Descriptor.Order + 1_000)
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
                var type = context.Principal.GetTokenType();
                if (string.IsNullOrEmpty(type))
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .AppendLine("The deserialized principal doesn't contain the mandatory 'oi_tkn_typ' claim.")
                        .Append("When implementing custom token deserialization, a 'oi_tkn_typ' claim containing ")
                        .Append("the type of the token being processed must be added to the security principal.")
                        .ToString());
                }

                if (!string.Equals(type, TokenTypeHints.AccessToken, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .AppendFormat("The type of token associated with the deserialized principal ({0})", type)
                        .AppendFormat("doesn't match the expected token type ({0}).", TokenTypeHints.AccessToken)
                        .ToString());
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
                    context.Logger.LogError("The request was rejected because the access token was expired.");

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
                    context.Logger.LogError("The request was rejected because the access token had no audience attached.");

                    context.Reject(
                        error: Errors.InvalidToken,
                        description: "The specified access token doesn't contain any audience.");

                    return default;
                }

                // If the access token doesn't include any registered audience, return an error.
                if (!audiences.Intersect(context.Options.Audiences, StringComparer.Ordinal).Any())
                {
                    context.Logger.LogError("The request was rejected because the access token had no valid audience.");

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
                .AppendLine("The core services must be registered when enabling reference tokens support.")
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
                    .AddFilter<RequireTokenValidationEnabled>()
                    .UseScopedHandler<ValidateTokenEntry>()
                    .SetOrder(ValidateAudience.Descriptor.Order + 1_000)
                    .Build();

            public async ValueTask HandleAsync([NotNull] ProcessAuthenticationContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var identifier = context.Principal.GetInternalTokenId();
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
                                 .SetInternalAuthorizationId(await _tokenManager.GetAuthorizationIdAsync(token))
                                 .SetInternalTokenId(await _tokenManager.GetIdAsync(token))
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
                .AppendLine("The core services must be registered when enabling reference tokens support.")
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
                    .AddFilter<RequireAuthorizationValidationEnabled>()
                    .UseScopedHandler<ValidateAuthorizationEntry>()
                    .SetOrder(ValidateTokenEntry.Descriptor.Order + 1_000)
                    .Build();

            public async ValueTask HandleAsync([NotNull] ProcessAuthenticationContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var identifier = context.Principal.GetInternalAuthorizationId();
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

                context.Response.Realm = context.Options.Realm;

                return default;
            }
        }
    }
}
