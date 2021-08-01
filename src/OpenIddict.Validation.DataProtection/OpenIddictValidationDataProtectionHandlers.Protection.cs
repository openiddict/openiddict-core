/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.IO;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Validation.DataProtection.OpenIddictValidationDataProtectionConstants.Purposes;
using static OpenIddict.Validation.OpenIddictValidationEvents;
using static OpenIddict.Validation.OpenIddictValidationHandlerFilters;
using static OpenIddict.Validation.OpenIddictValidationHandlers.Protection;
using Schemes = OpenIddict.Validation.DataProtection.OpenIddictValidationDataProtectionConstants.Purposes.Schemes;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.Validation.DataProtection
{
    public static partial class OpenIddictValidationDataProtectionHandlers
    {
        public static class Protection
        {
            public static ImmutableArray<OpenIddictValidationHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
                /*
                 * Token validation:
                 */
                ValidateDataProtectionToken.Descriptor);

            /// <summary>
            /// Contains the logic responsible of validating tokens generated using Data Protection.
            /// </summary>
            public class ValidateDataProtectionToken : IOpenIddictValidationHandler<ValidateTokenContext>
            {
                private readonly IOptionsMonitor<OpenIddictValidationDataProtectionOptions> _options;

                public ValidateDataProtectionToken(IOptionsMonitor<OpenIddictValidationDataProtectionOptions> options)
                    => _options = options;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                    = OpenIddictValidationHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                        .AddFilter<RequireLocalValidation>()
                        .UseSingletonHandler<ValidateDataProtectionToken>()
                        .SetOrder(ValidateIdentityModelToken.Descriptor.Order + 500)
                        .SetType(OpenIddictValidationHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public ValueTask HandleAsync(ValidateTokenContext context)
                {
                    // If a principal was already attached, don't overwrite it.
                    if (context.Principal is not null)
                    {
                        return default;
                    }

                    // Note: ASP.NET Core Data Protection tokens always start with "CfDJ8", that corresponds
                    // to the base64 representation of the magic "09 F0 C9 F0" header identifying DP payloads.
                    if (!context.Token.StartsWith("CfDJ8", StringComparison.Ordinal))
                    {
                        return default;
                    }

                    // Note: unlike the equivalent handler in the server stack, the logic used here is
                    // simpler as only access tokens are currently supported by the validation stack.
                    var principal = context.ValidTokenTypes.Count is 0 || context.ValidTokenTypes.Contains(TokenTypeHints.AccessToken) ?
                        ValidateToken(context.Token, TokenTypeHints.AccessToken) :
                        null;

                    if (principal is null)
                    {
                        context.Reject(
                            error: Errors.InvalidToken,
                            description: SR.GetResourceString(SR.ID2004),
                            uri: SR.FormatID8000(SR.ID2004));

                        return default;
                    }

                    context.Principal = principal;

                    context.Logger.LogTrace(SR.GetResourceString(SR.ID6152), context.Token, context.Principal.Claims);

                    return default;

                    ClaimsPrincipal? ValidateToken(string token, string type)
                    {
                        // Create a Data Protection protector using the provider registered in the options.
                        var protector = _options.CurrentValue.DataProtectionProvider.CreateProtector(type switch
                        {
                            // Note: reference tokens are encrypted using a different "purpose" string than non-reference tokens.
                            TokenTypeHints.AccessToken when !string.IsNullOrEmpty(context.TokenId)
                                => new[] { Handlers.Server, Formats.AccessToken, Features.ReferenceTokens, Schemes.Server },
                            TokenTypeHints.AccessToken => new[] { Handlers.Server, Formats.AccessToken, Schemes.Server },

                            _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0003))
                        });

                        try
                        {
                            using var buffer = new MemoryStream(protector.Unprotect(Base64UrlEncoder.DecodeBytes(token)));
                            using var reader = new BinaryReader(buffer);

                            // Note: since the data format relies on a data protector using different "purposes" strings
                            // per token type, the token processed at this stage is guaranteed to be of the expected type.
                            return _options.CurrentValue.Formatter.ReadToken(reader)?.SetTokenType(type);
                        }

                        catch (Exception exception)
                        {
                            context.Logger.LogTrace(exception, SR.GetResourceString(SR.ID6153), token);

                            return null;
                        }
                    }
                }
            }
        }
    }
}
