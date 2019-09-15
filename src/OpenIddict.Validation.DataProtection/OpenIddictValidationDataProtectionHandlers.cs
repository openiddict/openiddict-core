/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.ComponentModel;
using System.IO;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Validation.DataProtection.OpenIddictValidationDataProtectionConstants;
using static OpenIddict.Validation.OpenIddictValidationEvents;
using static OpenIddict.Validation.OpenIddictValidationHandlerFilters;
using static OpenIddict.Validation.OpenIddictValidationHandlers;

namespace OpenIddict.Validation.DataProtection
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static partial class OpenIddictValidationDataProtectionHandlers
    {
        public static ImmutableArray<OpenIddictValidationHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Authentication processing:
             */
            ValidateReferenceDataProtectionToken.Descriptor,
            ValidateSelfContainedDataProtectionToken.Descriptor);

        /// <summary>
        /// Contains the logic responsible of rejecting authentication
        /// demands that use an invalid reference Data Protection token.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ValidateReferenceDataProtectionToken : IOpenIddictValidationHandler<ProcessAuthenticationContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;
            private readonly IOptionsMonitor<OpenIddictValidationDataProtectionOptions> _options;

            public ValidateReferenceDataProtectionToken() => throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                .Append("the degraded mode with 'services.AddOpenIddict().AddValidation().EnableDegradedMode()'.")
                .ToString());

            public ValidateReferenceDataProtectionToken(
                [NotNull] IOpenIddictTokenManager tokenManager,
                [NotNull] IOptionsMonitor<OpenIddictValidationDataProtectionOptions> options)
            {
                _tokenManager = tokenManager;
                _options = options;
            }

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireReferenceTokensEnabled>()
                    .UseScopedHandler<ValidateReferenceDataProtectionToken>()
                    .SetOrder(ValidateReferenceToken.Descriptor.Order + 500)
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

                // If the token cannot be validated, don't return an error to allow another handle to validate it.
                var identifier = context.Request.AccessToken;
                if (string.IsNullOrEmpty(identifier))
                {
                    return;
                }

                var token = await _tokenManager.FindByReferenceIdAsync(identifier);
                if (token == null || !string.Equals(await _tokenManager.GetTypeAsync(token),
                    TokenUsages.AccessToken, StringComparison.OrdinalIgnoreCase))
                {
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

                // Create a Data Protection protector using the provider registered in the options.
                var protector = _options.CurrentValue.DataProtectionProvider.CreateProtector(
                    Purposes.Handlers.Server,
                    Purposes.Formats.AccessToken,
                    Purposes.Features.ReferenceTokens,
                    Purposes.Schemes.Server);

                ClaimsPrincipal principal = null;

                try
                {
                    using var buffer = new MemoryStream(protector.Unprotect(Base64UrlEncoder.DecodeBytes(payload)));
                    using var reader = new BinaryReader(buffer);

                    principal = _options.CurrentValue.Formatter.ReadToken(reader);
                }

                catch (Exception exception)
                {
                    context.Logger.LogTrace(exception, "An exception occured while deserializing a token.");
                }

                // If the token cannot be validated, don't return an error to allow another handle to validate it.
                if (principal == null)
                {
                    return;
                }

                // Attach the principal extracted from the authorization code to the parent event context
                // and restore the creation/expiration dates/identifiers from the token entry metadata.
                context.Principal = principal
                    .SetCreationDate(await _tokenManager.GetCreationDateAsync(token))
                    .SetExpirationDate(await _tokenManager.GetExpirationDateAsync(token))
                    .SetInternalAuthorizationId(await _tokenManager.GetAuthorizationIdAsync(token))
                    .SetInternalTokenId(await _tokenManager.GetIdAsync(token))
                    .SetClaim(Claims.Private.TokenUsage, await _tokenManager.GetTypeAsync(token));
            }
        }

        /// <summary>
        /// Contains the logic responsible of rejecting authentication demands
        /// that specify an invalid self-contained Data Protection token.
        /// </summary>
        public class ValidateSelfContainedDataProtectionToken : IOpenIddictValidationHandler<ProcessAuthenticationContext>
        {
            private readonly IOptionsMonitor<OpenIddictValidationDataProtectionOptions> _options;

            public ValidateSelfContainedDataProtectionToken([NotNull] IOptionsMonitor<OpenIddictValidationDataProtectionOptions> options)
                => _options = options;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireReferenceTokensDisabled>()
                    .UseSingletonHandler<ValidateSelfContainedDataProtectionToken>()
                    .SetOrder(ValidateSelfContainedToken.Descriptor.Order + 500)
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
                var token = context.Request.AccessToken;
                if (string.IsNullOrEmpty(token))
                {
                    return default;
                }

                // Create a Data Protection protector using the provider registered in the options.
                var protector = _options.CurrentValue.DataProtectionProvider.CreateProtector(
                    Purposes.Handlers.Server,
                    Purposes.Formats.AccessToken,
                    Purposes.Schemes.Server);

                ClaimsPrincipal principal = null;

                try
                {
                    using var buffer = new MemoryStream(protector.Unprotect(Base64UrlEncoder.DecodeBytes(token)));
                    using var reader = new BinaryReader(buffer);

                    principal = _options.CurrentValue.Formatter.ReadToken(reader);
                }

                catch (Exception exception)
                {
                    context.Logger.LogTrace(exception, "An exception occured while deserializing a token.");
                }

                // If the token cannot be validated, don't return an error to allow another handle to validate it.
                if (principal == null)
                {
                    return default;
                }

                // Note: since the data format relies on a data protector using different "purposes" strings
                // per token type, the token processed at this stage is guaranteed to be of the expected type.
                context.Principal = principal.SetClaim(Claims.Private.TokenUsage, TokenUsages.AccessToken);

                return default;
            }
        }
    }
}
