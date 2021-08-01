/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.DataProtection.OpenIddictServerDataProtectionConstants.Purposes;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers.Protection;
using Schemes = OpenIddict.Server.DataProtection.OpenIddictServerDataProtectionConstants.Purposes.Schemes;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.Server.DataProtection
{
    public static partial class OpenIddictServerDataProtectionHandlers
    {
        public static class Protection
        {
            public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
                /*
                 * Token validation:
                 */
                ValidateDataProtectionToken.Descriptor,

                /*
                 * Token validation:
                 */
                GenerateDataProtectionToken.Descriptor);

            /// <summary>
            /// Contains the logic responsible of validating tokens generated using Data Protection.
            /// </summary>
            public class ValidateDataProtectionToken : IOpenIddictServerHandler<ValidateTokenContext>
            {
                private readonly IOptionsMonitor<OpenIddictServerDataProtectionOptions> _options;

                public ValidateDataProtectionToken(IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
                    => _options = options;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                        .UseSingletonHandler<ValidateDataProtectionToken>()
                        .SetOrder(ValidateIdentityModelToken.Descriptor.Order + 500)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
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

                    // Tokens generated using ASP.NET Core Data Protection are encrypted by symmetric keys
                    // that are derived from both a master key resolved from the key ring and a specific value
                    // known as "purpose" that helps ensure that Data Protection payloads can't be decrypted
                    // without the correct "purpose" value, which is different for all types of tokens.
                    //
                    // While offering extensive protection at the cryptographic level, this prevents decrypting
                    // unknown tokens without re-executing the entire decryption routine for each type of token
                    // considered valid. To speed up this process when supporting multiple types is required,
                    // the Data Protection integration relies on the "token_type_hint" parameter specified
                    // by the client when it is available (e.g with introspection or revocation requests).

                    var principal = context.ValidTokenTypes.Count switch
                    {
                        // If no valid token type was set, all supported token types are allowed.
                        //
                        // Note: if a "token_type_hint" was specified by the client, use it to optimize
                        // the token decryption lookup but fall back to other types of tokens
                        // if the token can't be decrypted using the specified token type hint.
                        //
                        // In this case, common types (e.g access/refresh tokens) are checked first.
                        0 => context.TokenTypeHint switch
                        {
                            TokenTypeHints.AuthorizationCode =>
                                ValidateToken(context.Token, TokenTypeHints.AuthorizationCode) ??
                                ValidateToken(context.Token, TokenTypeHints.AccessToken)       ??
                                ValidateToken(context.Token, TokenTypeHints.RefreshToken)      ??
                                ValidateToken(context.Token, TokenTypeHints.DeviceCode)        ??
                                ValidateToken(context.Token, TokenTypeHints.UserCode),

                            TokenTypeHints.DeviceCode =>
                                ValidateToken(context.Token, TokenTypeHints.DeviceCode)        ??
                                ValidateToken(context.Token, TokenTypeHints.AccessToken)       ??
                                ValidateToken(context.Token, TokenTypeHints.RefreshToken)      ??
                                ValidateToken(context.Token, TokenTypeHints.AuthorizationCode) ??
                                ValidateToken(context.Token, TokenTypeHints.UserCode),

                            TokenTypeHints.RefreshToken =>
                                ValidateToken(context.Token, TokenTypeHints.RefreshToken)      ??
                                ValidateToken(context.Token, TokenTypeHints.AccessToken)       ??
                                ValidateToken(context.Token, TokenTypeHints.AuthorizationCode) ??
                                ValidateToken(context.Token, TokenTypeHints.DeviceCode)        ??
                                ValidateToken(context.Token, TokenTypeHints.UserCode),

                            TokenTypeHints.UserCode =>
                                ValidateToken(context.Token, TokenTypeHints.UserCode)          ??
                                ValidateToken(context.Token, TokenTypeHints.AccessToken)       ??
                                ValidateToken(context.Token, TokenTypeHints.RefreshToken)      ??
                                ValidateToken(context.Token, TokenTypeHints.AuthorizationCode) ??
                                ValidateToken(context.Token, TokenTypeHints.DeviceCode),

                            _ =>
                                ValidateToken(context.Token, TokenTypeHints.AccessToken)       ??
                                ValidateToken(context.Token, TokenTypeHints.RefreshToken)      ??
                                ValidateToken(context.Token, TokenTypeHints.AuthorizationCode) ??
                                ValidateToken(context.Token, TokenTypeHints.DeviceCode)        ??
                                ValidateToken(context.Token, TokenTypeHints.UserCode),
                        },

                        // If a single valid token type was set, ignore the specified token type hint.
                        1 => context.ValidTokenTypes.ElementAt(0) switch
                        {
                            TokenTypeHints.AccessToken       => ValidateToken(context.Token, TokenTypeHints.AccessToken),
                            TokenTypeHints.RefreshToken      => ValidateToken(context.Token, TokenTypeHints.RefreshToken),
                            TokenTypeHints.AuthorizationCode => ValidateToken(context.Token, TokenTypeHints.AuthorizationCode),
                            TokenTypeHints.DeviceCode        => ValidateToken(context.Token, TokenTypeHints.DeviceCode),
                            TokenTypeHints.UserCode          => ValidateToken(context.Token, TokenTypeHints.UserCode),

                            _ => null // The token type is not supported by the Data Protection integration (e.g identity tokens).
                        },

                        // If multiple valid types were set, use the specified token type hint
                        // and select the first non-null token that can be successfully decrypted.
                        _ => context.ValidTokenTypes.OrderBy(type => type switch
                        {
                            // If the token type hint corresponds to one of the valid types, test it first.
                            string value when value == context.TokenTypeHint => 0,

                            TokenTypeHints.AccessToken       => 1,
                            TokenTypeHints.RefreshToken      => 2,
                            TokenTypeHints.AuthorizationCode => 3,
                            TokenTypeHints.DeviceCode        => 4,
                            TokenTypeHints.UserCode          => 5,

                            _ => int.MaxValue
                        })
                        .Select(type => type switch
                        {
                            TokenTypeHints.AccessToken       => ValidateToken(context.Token, TokenTypeHints.AccessToken),
                            TokenTypeHints.RefreshToken      => ValidateToken(context.Token, TokenTypeHints.RefreshToken),
                            TokenTypeHints.AuthorizationCode => ValidateToken(context.Token, TokenTypeHints.AuthorizationCode),
                            TokenTypeHints.DeviceCode        => ValidateToken(context.Token, TokenTypeHints.DeviceCode),
                            TokenTypeHints.UserCode          => ValidateToken(context.Token, TokenTypeHints.UserCode),

                            _ => null // The token type is not supported by the Data Protection integration (e.g identity tokens).
                        })
                        .Where(static principal => principal is not null)
                        .FirstOrDefault()
                    };

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

                            TokenTypeHints.AuthorizationCode when !string.IsNullOrEmpty(context.TokenId)
                                => new[] { Handlers.Server, Formats.AuthorizationCode, Features.ReferenceTokens, Schemes.Server },
                            TokenTypeHints.AuthorizationCode => new[] { Handlers.Server, Formats.AuthorizationCode, Schemes.Server },

                            TokenTypeHints.DeviceCode when !string.IsNullOrEmpty(context.TokenId)
                                => new[] { Handlers.Server, Formats.DeviceCode, Features.ReferenceTokens, Schemes.Server },
                            TokenTypeHints.DeviceCode => new[] { Handlers.Server, Formats.DeviceCode, Schemes.Server },

                            TokenTypeHints.RefreshToken when !string.IsNullOrEmpty(context.TokenId)
                                => new[] { Handlers.Server, Formats.RefreshToken, Features.ReferenceTokens, Schemes.Server },
                            TokenTypeHints.RefreshToken => new[] { Handlers.Server, Formats.RefreshToken, Schemes.Server },

                            TokenTypeHints.UserCode when !string.IsNullOrEmpty(context.TokenId)
                                => new[] { Handlers.Server, Formats.UserCode, Features.ReferenceTokens, Schemes.Server },
                            TokenTypeHints.UserCode => new[] { Handlers.Server, Formats.UserCode, Schemes.Server },

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

            /// <summary>
            /// Contains the logic responsible of generating a token using Data Protection.
            /// </summary>
            public class GenerateDataProtectionToken : IOpenIddictServerHandler<GenerateTokenContext>
            {
                private readonly IOptionsMonitor<OpenIddictServerDataProtectionOptions> _options;

                public GenerateDataProtectionToken(IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
                    => _options = options;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<GenerateTokenContext>()
                        .UseSingletonHandler<GenerateDataProtectionToken>()
                        .SetOrder(GenerateIdentityModelToken.Descriptor.Order - 500)
                        .SetType(OpenIddictServerHandlerType.BuiltIn)
                        .Build();

                /// <inheritdoc/>
                public ValueTask HandleAsync(GenerateTokenContext context)
                {
                    if (context is null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // If an access token was already attached by another handler, don't overwrite it.
                    if (!string.IsNullOrEmpty(context.Token))
                    {
                        return default;
                    }

                    if (context.TokenType switch
                    {
                        TokenTypeHints.AccessToken       => _options.CurrentValue.PreferDefaultAccessTokenFormat,
                        TokenTypeHints.AuthorizationCode => _options.CurrentValue.PreferDefaultAuthorizationCodeFormat,
                        TokenTypeHints.DeviceCode        => _options.CurrentValue.PreferDefaultDeviceCodeFormat,
                        TokenTypeHints.RefreshToken      => _options.CurrentValue.PreferDefaultRefreshTokenFormat,
                        TokenTypeHints.UserCode          => _options.CurrentValue.PreferDefaultUserCodeFormat,

                        _ => true // The token type is not supported by the Data Protection integration (e.g identity tokens).
                    })
                    {
                        return default;
                    }

                    // Create a Data Protection protector using the provider registered in the options.
                    var protector = _options.CurrentValue.DataProtectionProvider.CreateProtector(context.TokenType switch
                    {
                        // Note: reference tokens are encrypted using a different "purpose" string than non-reference tokens.
                        TokenTypeHints.AccessToken when context.Options.UseReferenceAccessTokens
                            => new[] { Handlers.Server, Formats.AccessToken, Features.ReferenceTokens, Schemes.Server },
                        TokenTypeHints.AccessToken => new[] { Handlers.Server, Formats.AccessToken, Schemes.Server },

                        TokenTypeHints.AuthorizationCode when !context.Options.DisableTokenStorage
                            => new[] { Handlers.Server, Formats.AuthorizationCode, Features.ReferenceTokens, Schemes.Server },
                        TokenTypeHints.AuthorizationCode => new[] { Handlers.Server, Formats.AuthorizationCode, Schemes.Server },

                        TokenTypeHints.DeviceCode when !context.Options.DisableTokenStorage
                            => new[] { Handlers.Server, Formats.DeviceCode, Features.ReferenceTokens, Schemes.Server },
                        TokenTypeHints.DeviceCode => new[] { Handlers.Server, Formats.DeviceCode, Schemes.Server },

                        TokenTypeHints.RefreshToken when context.Options.UseReferenceRefreshTokens
                            => new[] { Handlers.Server, Formats.RefreshToken, Features.ReferenceTokens, Schemes.Server },
                        TokenTypeHints.RefreshToken => new[] { Handlers.Server, Formats.RefreshToken, Schemes.Server },

                        TokenTypeHints.UserCode when !context.Options.DisableTokenStorage
                            => new[] { Handlers.Server, Formats.UserCode, Features.ReferenceTokens, Schemes.Server },
                        TokenTypeHints.UserCode => new[] { Handlers.Server, Formats.UserCode, Schemes.Server },

                        _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0003))
                    });

                    using var buffer = new MemoryStream();
                    using var writer = new BinaryWriter(buffer);

                    _options.CurrentValue.Formatter.WriteToken(writer, context.Principal);

                    context.Token = Base64UrlEncoder.Encode(protector.Protect(buffer.ToArray()));

                    context.Logger.LogTrace(SR.GetResourceString(SR.ID6013), context.TokenType,
                        context.Token, context.Principal.Claims);

                    return default;
                }
            }
        }
    }
}
