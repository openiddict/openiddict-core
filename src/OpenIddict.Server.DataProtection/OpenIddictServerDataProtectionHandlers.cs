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
using System.Threading.Tasks;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.DataProtection.OpenIddictServerDataProtectionConstants.Purposes;
using static OpenIddict.Server.DataProtection.OpenIddictServerDataProtectionHandlerFilters;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlerFilters;
using static OpenIddict.Server.OpenIddictServerHandlers;
using Properties = OpenIddict.Server.OpenIddictServerConstants.Properties;
using Schemes = OpenIddict.Server.DataProtection.OpenIddictServerDataProtectionConstants.Purposes.Schemes;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.Server.DataProtection
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static partial class OpenIddictServerDataProtectionHandlers
    {
        public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Authentication processing:
             */
            ValidateDataProtectionToken.Descriptor,

            /*
             * Sign-in processing:
             */
            GenerateDataProtectionAccessToken.Descriptor,
            GenerateDataProtectionAuthorizationCode.Descriptor,
            GenerateDataProtectionDeviceCode.Descriptor,
            GenerateDataProtectionRefreshToken.Descriptor,
            GenerateDataProtectionUserCode.Descriptor);

        /// <summary>
        /// Contains the logic responsible of validating tokens generated using Data Protection.
        /// </summary>
        public class ValidateDataProtectionToken : IOpenIddictServerHandler<ProcessAuthenticationContext>
        {
            private readonly IOptionsMonitor<OpenIddictServerDataProtectionOptions> _options;

            public ValidateDataProtectionToken(IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
                => _options = options;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .UseSingletonHandler<ValidateDataProtectionToken>()
                    .SetOrder(ValidateIdentityModelToken.Descriptor.Order + 500)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessAuthenticationContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If a principal was already attached, don't overwrite it.
                if (context.Principal is not null)
                {
                    return default;
                }

                // Note: ASP.NET Core Data Protection tokens always start with "CfDJ8", that corresponds
                // to the base64 representation of the magic "09 F0 C9 F0" header identifying DP payloads.
                if (string.IsNullOrEmpty(context.Token) || !context.Token.StartsWith("CfDJ8", StringComparison.Ordinal))
                {
                    return default;
                }

                var principal = !string.IsNullOrEmpty(context.TokenType) ?
                    ValidateToken(context.Token, context.TokenType) :
                    ValidateToken(context.Token, TokenTypeHints.AccessToken)       ??
                    ValidateToken(context.Token, TokenTypeHints.RefreshToken)      ??
                    ValidateToken(context.Token, TokenTypeHints.AuthorizationCode) ??
                    ValidateToken(context.Token, TokenTypeHints.DeviceCode)        ??
                    ValidateToken(context.Token, TokenTypeHints.UserCode);

                if (principal is null)
                {
                    context.Reject(
                        error: context.EndpointType switch
                        {
                            OpenIddictServerEndpointType.Token => Errors.InvalidGrant,
                            _                                  => Errors.InvalidToken
                        },
                        description: SR.GetResourceString(SR.ID2004));

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
                        TokenTypeHints.AccessToken when context.Transaction.Properties.ContainsKey(Properties.ReferenceTokenIdentifier)
                            => new[] { Handlers.Server, Formats.AccessToken, Features.ReferenceTokens, Schemes.Server       },

                        TokenTypeHints.AuthorizationCode when context.Transaction.Properties.ContainsKey(Properties.ReferenceTokenIdentifier)
                            => new[] { Handlers.Server, Formats.AuthorizationCode, Features.ReferenceTokens, Schemes.Server },

                        TokenTypeHints.DeviceCode when context.Transaction.Properties.ContainsKey(Properties.ReferenceTokenIdentifier)
                            => new[] { Handlers.Server, Formats.DeviceCode, Features.ReferenceTokens, Schemes.Server        },

                        TokenTypeHints.RefreshToken when context.Transaction.Properties.ContainsKey(Properties.ReferenceTokenIdentifier)
                            => new[] { Handlers.Server, Formats.RefreshToken, Features.ReferenceTokens, Schemes.Server      },

                        TokenTypeHints.UserCode when context.Transaction.Properties.ContainsKey(Properties.ReferenceTokenIdentifier)
                            => new[] { Handlers.Server, Formats.UserCode, Features.ReferenceTokens, Schemes.Server          },

                        TokenTypeHints.AccessToken       => new[] { Handlers.Server, Formats.AccessToken,       Schemes.Server },
                        TokenTypeHints.AuthorizationCode => new[] { Handlers.Server, Formats.AuthorizationCode, Schemes.Server },
                        TokenTypeHints.DeviceCode        => new[] { Handlers.Server, Formats.DeviceCode,        Schemes.Server },
                        TokenTypeHints.RefreshToken      => new[] { Handlers.Server, Formats.RefreshToken,      Schemes.Server },
                        TokenTypeHints.UserCode          => new[] { Handlers.Server, Formats.UserCode,          Schemes.Server },

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
        /// Contains the logic responsible of generating an access token using Data Protection.
        /// </summary>
        public class GenerateDataProtectionAccessToken : IOpenIddictServerHandler<ProcessSignInContext>
        {
            private readonly IOptionsMonitor<OpenIddictServerDataProtectionOptions> _options;

            public GenerateDataProtectionAccessToken(IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
                => _options = options;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireAccessTokenGenerated>()
                    .AddFilter<RequireDataProtectionAccessTokenFormatEnabled>()
                    .UseSingletonHandler<GenerateDataProtectionAccessToken>()
                    .SetOrder(GenerateIdentityModelAccessToken.Descriptor.Order - 500)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessSignInContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If an access token was already attached by another handler, don't overwrite it.
                if (!string.IsNullOrEmpty(context.Response.AccessToken))
                {
                    return default;
                }

                if (context.AccessTokenPrincipal is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0022));
                }

                // Create a Data Protection protector using the provider registered in the options.
                var protector = context.Options.UseReferenceAccessTokens ?
                    _options.CurrentValue.DataProtectionProvider.CreateProtector(
                        Handlers.Server, Formats.AccessToken, Features.ReferenceTokens, Schemes.Server) :
                    _options.CurrentValue.DataProtectionProvider.CreateProtector(
                        Handlers.Server, Formats.AccessToken, Schemes.Server);

                using var buffer = new MemoryStream();
                using var writer = new BinaryWriter(buffer);

                _options.CurrentValue.Formatter.WriteToken(writer, context.AccessTokenPrincipal);

                context.AccessToken = Base64UrlEncoder.Encode(protector.Protect(buffer.ToArray()));

                context.Logger.LogTrace(SR.GetResourceString(SR.ID6013),
                    context.AccessTokenPrincipal.GetClaim(Claims.JwtId),
                    context.AccessToken, context.AccessTokenPrincipal.Claims);

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating an authorization code using Data Protection.
        /// </summary>
        public class GenerateDataProtectionAuthorizationCode : IOpenIddictServerHandler<ProcessSignInContext>
        {
            private readonly IOptionsMonitor<OpenIddictServerDataProtectionOptions> _options;

            public GenerateDataProtectionAuthorizationCode(IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
                => _options = options;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireAuthorizationCodeGenerated>()
                    .AddFilter<RequireDataProtectionAuthorizationCodeFormatEnabled>()
                    .UseSingletonHandler<GenerateDataProtectionAuthorizationCode>()
                    .SetOrder(GenerateIdentityModelAuthorizationCode.Descriptor.Order - 500)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessSignInContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If an authorization code was already attached by another handler, don't overwrite it.
                if (!string.IsNullOrEmpty(context.Response.Code))
                {
                    return default;
                }

                if (context.AuthorizationCodePrincipal is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0022));
                }

                // Create a Data Protection protector using the provider registered in the options.
                var protector = !context.Options.DisableTokenStorage ?
                    _options.CurrentValue.DataProtectionProvider.CreateProtector(
                        Handlers.Server, Formats.AuthorizationCode, Features.ReferenceTokens, Schemes.Server) :
                    _options.CurrentValue.DataProtectionProvider.CreateProtector(
                        Handlers.Server, Formats.AuthorizationCode, Schemes.Server);

                using var buffer = new MemoryStream();
                using var writer = new BinaryWriter(buffer);

                _options.CurrentValue.Formatter.WriteToken(writer, context.AuthorizationCodePrincipal);

                context.AuthorizationCode = Base64UrlEncoder.Encode(protector.Protect(buffer.ToArray()));

                context.Logger.LogTrace(SR.GetResourceString(SR.ID6016),
                    context.AuthorizationCodePrincipal.GetClaim(Claims.JwtId),
                    context.AuthorizationCode, context.AuthorizationCodePrincipal.Claims);

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating a device code using Data Protection.
        /// </summary>
        public class GenerateDataProtectionDeviceCode : IOpenIddictServerHandler<ProcessSignInContext>
        {
            private readonly IOptionsMonitor<OpenIddictServerDataProtectionOptions> _options;

            public GenerateDataProtectionDeviceCode(IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
                => _options = options;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireDeviceCodeGenerated>()
                    .AddFilter<RequireDataProtectionDeviceCodeFormatEnabled>()
                    .UseSingletonHandler<GenerateDataProtectionDeviceCode>()
                    .SetOrder(GenerateIdentityModelDeviceCode.Descriptor.Order - 500)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessSignInContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If a device code was already attached by another handler, don't overwrite it.
                if (!string.IsNullOrEmpty(context.Response.DeviceCode))
                {
                    return default;
                }

                if (context.DeviceCodePrincipal is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0022));
                }

                // Create a Data Protection protector using the provider registered in the options.
                var protector = !context.Options.DisableTokenStorage ?
                    _options.CurrentValue.DataProtectionProvider.CreateProtector(
                        Handlers.Server, Formats.DeviceCode, Features.ReferenceTokens, Schemes.Server) :
                    _options.CurrentValue.DataProtectionProvider.CreateProtector(
                        Handlers.Server, Formats.DeviceCode, Schemes.Server);

                using var buffer = new MemoryStream();
                using var writer = new BinaryWriter(buffer);

                _options.CurrentValue.Formatter.WriteToken(writer, context.DeviceCodePrincipal);

                context.DeviceCode = Base64UrlEncoder.Encode(protector.Protect(buffer.ToArray()));

                context.Logger.LogTrace(SR.GetResourceString(SR.ID6019),
                    context.DeviceCodePrincipal.GetClaim(Claims.JwtId),
                    context.DeviceCode, context.DeviceCodePrincipal.Claims);

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating a refresh token using Data Protection.
        /// </summary>
        public class GenerateDataProtectionRefreshToken : IOpenIddictServerHandler<ProcessSignInContext>
        {
            private readonly IOptionsMonitor<OpenIddictServerDataProtectionOptions> _options;

            public GenerateDataProtectionRefreshToken(IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
                => _options = options;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireRefreshTokenGenerated>()
                    .AddFilter<RequireDataProtectionRefreshTokenFormatEnabled>()
                    .UseSingletonHandler<GenerateDataProtectionRefreshToken>()
                    .SetOrder(GenerateIdentityModelRefreshToken.Descriptor.Order - 500)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessSignInContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If a refresh token was already attached by another handler, don't overwrite it.
                if (!string.IsNullOrEmpty(context.Response.RefreshToken))
                {
                    return default;
                }

                if (context.RefreshTokenPrincipal is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0022));
                }

                // Create a Data Protection protector using the provider registered in the options.
                var protector = context.Options.UseReferenceRefreshTokens ?
                    _options.CurrentValue.DataProtectionProvider.CreateProtector(
                        Handlers.Server, Formats.RefreshToken, Features.ReferenceTokens, Schemes.Server) :
                    _options.CurrentValue.DataProtectionProvider.CreateProtector(
                        Handlers.Server, Formats.RefreshToken, Schemes.Server);

                using var buffer = new MemoryStream();
                using var writer = new BinaryWriter(buffer);

                _options.CurrentValue.Formatter.WriteToken(writer, context.RefreshTokenPrincipal);

                context.RefreshToken = Base64UrlEncoder.Encode(protector.Protect(buffer.ToArray()));

                context.Logger.LogTrace(SR.GetResourceString(SR.ID6023),
                    context.RefreshTokenPrincipal.GetClaim(Claims.JwtId),
                    context.RefreshToken, context.RefreshTokenPrincipal.Claims);

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating a user code using Data Protection.
        /// </summary>
        public class GenerateDataProtectionUserCode : IOpenIddictServerHandler<ProcessSignInContext>
        {
            private readonly IOptionsMonitor<OpenIddictServerDataProtectionOptions> _options;

            public GenerateDataProtectionUserCode(IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
                => _options = options;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireUserCodeGenerated>()
                    .AddFilter<RequireDataProtectionUserCodeFormatEnabled>()
                    .UseSingletonHandler<GenerateDataProtectionUserCode>()
                    .SetOrder(GenerateIdentityModelUserCode.Descriptor.Order - 500)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessSignInContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If a user code was already attached by another handler, don't overwrite it.
                if (!string.IsNullOrEmpty(context.Response.UserCode))
                {
                    return default;
                }

                if (context.UserCodePrincipal is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0022));
                }

                // Create a Data Protection protector using the provider registered in the options.
                var protector = !context.Options.DisableTokenStorage ?
                    _options.CurrentValue.DataProtectionProvider.CreateProtector(
                        Handlers.Server, Formats.UserCode, Features.ReferenceTokens, Schemes.Server) :
                    _options.CurrentValue.DataProtectionProvider.CreateProtector(
                        Handlers.Server, Formats.UserCode, Schemes.Server);

                using var buffer = new MemoryStream();
                using var writer = new BinaryWriter(buffer);

                _options.CurrentValue.Formatter.WriteToken(writer, context.UserCodePrincipal);

                context.UserCode = Base64UrlEncoder.Encode(protector.Protect(buffer.ToArray()));

                context.Logger.LogTrace(SR.GetResourceString(SR.ID6026),
                    context.UserCodePrincipal.GetClaim(Claims.JwtId),
                    context.UserCode, context.UserCodePrincipal.Claims);

                return default;
            }
        }
    }
}
