/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.ComponentModel;
using System.IO;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Validation.DataProtection.OpenIddictValidationDataProtectionConstants.Purposes;
using static OpenIddict.Validation.OpenIddictValidationEvents;
using static OpenIddict.Validation.OpenIddictValidationHandlers;
using Properties = OpenIddict.Validation.OpenIddictValidationConstants.Properties;
using Schemes = OpenIddict.Validation.DataProtection.OpenIddictValidationDataProtectionConstants.Purposes.Schemes;

namespace OpenIddict.Validation.DataProtection
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static partial class OpenIddictValidationDataProtectionHandlers
    {
        public static ImmutableArray<OpenIddictValidationHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Authentication processing:
             */
            ValidateDataProtectionToken.Descriptor);

        /// <summary>
        /// Contains the logic responsible of validating tokens generated using Data Protection.
        /// </summary>
        public class ValidateDataProtectionToken : IOpenIddictValidationHandler<ProcessAuthenticationContext>
        {
            private readonly IOptionsMonitor<OpenIddictValidationDataProtectionOptions> _options;

            public ValidateDataProtectionToken([NotNull] IOptionsMonitor<OpenIddictValidationDataProtectionOptions> options)
                => _options = options;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .UseSingletonHandler<ValidateDataProtectionToken>()
                    .SetOrder(ValidateIdentityModelToken.Descriptor.Order + 500)
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

                // Note: ASP.NET Core Data Protection tokens always start with "CfDJ8", that corresponds
                // to the base64 representation of the magic "09 F0 C9 F0" header identifying DP payloads.
                // As an optimization, always ignore tokens that don't start with the "CfDJ8" string.
                if (string.IsNullOrEmpty(context.Token) || !context.Token.StartsWith("CfDJ8", StringComparison.Ordinal))
                {
                    return default;
                }

                // Create a Data Protection protector using the provider registered in the options.
                var protector = _options.CurrentValue.DataProtectionProvider.CreateProtector(context.TokenType switch
                {
                    null => throw new InvalidOperationException("Generic token validation is not supported by the validation handler."),

                    TokenTypeHints.AccessToken when context.Transaction.Properties.ContainsKey(Properties.ReferenceTokenIdentifier)
                        => new[] { Handlers.Server, Formats.AccessToken, Features.ReferenceTokens, Schemes.Server },

                    TokenTypeHints.AccessToken => new[] { Handlers.Server, Formats.AccessToken, Schemes.Server },

                    _ => throw new InvalidOperationException("The specified token type is not supported.")
                });

                try
                {
                    using var buffer = new MemoryStream(protector.Unprotect(Base64UrlEncoder.DecodeBytes(context.Token)));
                    using var reader = new BinaryReader(buffer);

                    // Note: since the data format relies on a data protector using different "purposes" strings
                    // per token type, the token processed at this stage is guaranteed to be of the expected type.
                    context.Principal = _options.CurrentValue.Formatter.ReadToken(reader)?.SetTokenType(context.TokenType);
                }

                catch (Exception exception)
                {
                    context.Logger.LogTrace(exception, "An exception occured while deserializing the token '{Token}'.", context.Token);
                }

                // If the token cannot be validated, don't return an error to allow another handle to validate it.
                if (context.Principal == null)
                {
                    return default;
                }

                context.Logger.LogTrace("The DP token '{Token}' was successfully validated and the following claims " +
                                        "could be extracted: {Claims}.", context.Token, context.Principal.Claims);

                return default;
            }
        }
    }
}
