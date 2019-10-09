/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
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
            ValidateReferenceToken.Descriptor,
            ValidateSelfContainedToken.Descriptor,
            ValidatePrincipal.Descriptor,
            ValidateExpirationDate.Descriptor,
            ValidateAudience.Descriptor,
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
                        error: Errors.InvalidToken,
                        description: "The access token is missing.");

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of rejecting authentication demands that use an invalid reference token.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ValidateReferenceToken : IOpenIddictValidationHandler<ProcessAuthenticationContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public ValidateReferenceToken() => throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling reference tokens support.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .ToString());

            public ValidateReferenceToken([NotNull] IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireReferenceTokensEnabled>()
                    .UseScopedHandler<ValidateReferenceToken>()
                    .SetOrder(ValidateAccessTokenParameter.Descriptor.Order + 1_000)
                    .Build();

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

                // If the reference token cannot be found, return a generic error.
                var token = await _tokenManager.FindByReferenceIdAsync(context.Request.AccessToken);
                if (token == null || !string.Equals(await _tokenManager.GetTypeAsync(token),
                    TokenUsages.AccessToken, StringComparison.OrdinalIgnoreCase))
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

                // If the token cannot be validated, don't return an error to allow another handle to validate it.
                if (!context.Options.JsonWebTokenHandler.CanReadToken(payload))
                {
                    return;
                }

                // If no issuer signing key was attached, don't return an error to allow another handle to validate it.
                var parameters = context.TokenValidationParameters;
                if (parameters?.IssuerSigningKeys == null)
                {
                    return;
                }

                // Clone the token validation parameters before mutating them to ensure the
                // shared token validation parameters registered as options are not modified.
                parameters = parameters.Clone();
                parameters.PropertyBag = new Dictionary<string, object> { [Claims.Private.TokenUsage] = TokenUsages.AccessToken };
                parameters.TokenDecryptionKeys = context.Options.EncryptionCredentials.Select(credentials => credentials.Key);
                parameters.ValidIssuer = context.Issuer?.AbsoluteUri;

                // If the token cannot be validated, don't return an error to allow another handle to validate it.
                var result = await context.Options.JsonWebTokenHandler.ValidateTokenStringAsync(payload, parameters);
                if (result.ClaimsIdentity == null)
                {
                    context.Logger.LogTrace(result.Exception, "An error occurred while validating the token '{Token}'.", payload);

                    return;
                }

                // Attach the principal extracted from the authorization code to the parent event context
                // and restore the creation/expiration dates/identifiers from the token entry metadata.
                context.Principal = new ClaimsPrincipal(result.ClaimsIdentity)
                    .SetCreationDate(await _tokenManager.GetCreationDateAsync(token))
                    .SetExpirationDate(await _tokenManager.GetExpirationDateAsync(token))
                    .SetInternalAuthorizationId(await _tokenManager.GetAuthorizationIdAsync(token))
                    .SetInternalTokenId(await _tokenManager.GetIdAsync(token))
                    .SetClaim(Claims.Private.TokenUsage, await _tokenManager.GetTypeAsync(token));

                context.Logger.LogTrace("The reference JWT token '{Token}' was successfully validated and the following " +
                                        "claims could be extracted: {Claims}.", payload, context.Principal.Claims);
            }
        }

        /// <summary>
        /// Contains the logic responsible of rejecting authentication demands that specify an invalid self-contained token.
        /// </summary>
        public class ValidateSelfContainedToken : IOpenIddictValidationHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .UseSingletonHandler<ValidateSelfContainedToken>()
                    .SetOrder(ValidateReferenceToken.Descriptor.Order + 1_000)
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

                // If the token cannot be validated, don't return an error to allow another handle to validate it.
                if (!context.Options.JsonWebTokenHandler.CanReadToken(context.Request.AccessToken))
                {
                    return;
                }

                // If no issuer signing key was attached, don't return an error to allow another handle to validate it.
                var parameters = context.TokenValidationParameters;
                if (parameters?.IssuerSigningKeys == null)
                {
                    return;
                }

                // Clone the token validation parameters before mutating them.
                parameters = parameters.Clone();
                parameters.PropertyBag = new Dictionary<string, object> { [Claims.Private.TokenUsage] = TokenUsages.AccessToken };
                parameters.TokenDecryptionKeys = context.Options.EncryptionCredentials.Select(credentials => credentials.Key);
                parameters.ValidIssuer = context.Issuer?.AbsoluteUri;

                // If the token cannot be validated, don't return an error to allow another handle to validate it.
                var result = await context.Options.JsonWebTokenHandler.ValidateTokenStringAsync(context.Request.AccessToken, parameters);
                if (result.ClaimsIdentity == null)
                {
                    context.Logger.LogTrace(result.Exception, "An error occurred while validating the token '{Token}'.", context.Request.AccessToken);

                    return;
                }

                // Attach the principal extracted from the token to the parent event context.
                context.Principal = new ClaimsPrincipal(result.ClaimsIdentity);

                context.Logger.LogTrace("The self-contained JWT token '{Token}' was successfully validated and the following " +
                                        "claims could be extracted: {Claims}.", context.Request.AccessToken, context.Principal.Claims);
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
                    .SetOrder(ValidateReferenceToken.Descriptor.Order + 1_000)
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
                if (!context.Principal.HasAudience())
                {
                    context.Logger.LogError("The request was rejected because the access token had no audience attached.");

                    context.Reject(
                        error: Errors.InvalidToken,
                        description: "The specified access token doesn't contain any audience.");

                    return default;
                }

                // If the access token doesn't include any registered audience, return an error.
                if (context.Principal.GetAudiences().Intersect(context.Options.Audiences).IsEmpty)
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
                    .SetOrder(ValidateAudience.Descriptor.Order + 1_000)
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
                if (authorization == null || !await _authorizationManager.IsValidAsync(authorization))
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

                if (string.IsNullOrEmpty(context.Response.Error))
                {
                    context.Response.Error = Errors.InvalidToken;
                }

                if (string.IsNullOrEmpty(context.Response.ErrorDescription))
                {
                    context.Response.ErrorDescription = "The access token is not valid.";
                }

                return default;
            }
        }
    }
}
