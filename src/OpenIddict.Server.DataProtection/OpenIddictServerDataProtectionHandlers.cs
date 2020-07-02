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
using JetBrains.Annotations;
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

            public ValidateDataProtectionToken([NotNull] IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
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

                if (principal == null)
                {
                    context.Reject(
                        error: context.EndpointType switch
                        {
                            OpenIddictServerEndpointType.Token => Errors.InvalidGrant,
                            _                                  => Errors.InvalidToken
                        },
                        description: "The specified token is not valid.");

                    return default;
                }

                context.Principal = principal;

                context.Logger.LogTrace("The DP token '{Token}' was successfully validated and the following claims " +
                                        "could be extracted: {Claims}.", context.Token, context.Principal.Claims);

                return default;

                ClaimsPrincipal ValidateToken(string token, string type)
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

                        _ => throw new InvalidOperationException("The specified token type is not supported.")
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
                        context.Logger.LogTrace(exception, "An exception occured while deserializing the token '{Token}'.", token);

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

            public GenerateDataProtectionAccessToken([NotNull] IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
                => _options = options;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireAccessTokenIncluded>()
                    .AddFilter<RequireDataProtectionAccessTokenFormatEnabled>()
                    .UseSingletonHandler<GenerateDataProtectionAccessToken>()
                    .SetOrder(GenerateIdentityModelAccessToken.Descriptor.Order - 500)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If an access token was already attached by another handler, don't overwrite it.
                if (!string.IsNullOrEmpty(context.Response.AccessToken))
                {
                    return default;
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

                context.Response.AccessToken = Base64UrlEncoder.Encode(protector.Protect(buffer.ToArray()));

                context.Logger.LogTrace("The access token '{Identifier}' was successfully created: {Payload}. " +
                                        "The principal used to create the token contained the following claims: {Claims}.",
                                        context.AccessTokenPrincipal.GetClaim(Claims.JwtId),
                                        context.Response.AccessToken, context.AccessTokenPrincipal.Claims);

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating an authorization code using Data Protection.
        /// </summary>
        public class GenerateDataProtectionAuthorizationCode : IOpenIddictServerHandler<ProcessSignInContext>
        {
            private readonly IOptionsMonitor<OpenIddictServerDataProtectionOptions> _options;

            public GenerateDataProtectionAuthorizationCode([NotNull] IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
                => _options = options;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireAuthorizationCodeIncluded>()
                    .AddFilter<RequireDataProtectionAuthorizationCodeFormatEnabled>()
                    .UseSingletonHandler<GenerateDataProtectionAuthorizationCode>()
                    .SetOrder(GenerateIdentityModelAuthorizationCode.Descriptor.Order - 500)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If an authorization code was already attached by another handler, don't overwrite it.
                if (!string.IsNullOrEmpty(context.Response.Code))
                {
                    return default;
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

                context.Response.Code = Base64UrlEncoder.Encode(protector.Protect(buffer.ToArray()));

                context.Logger.LogTrace("The authorization code '{Identifier}' was successfully created: {Payload}. " +
                                        "The principal used to create the token contained the following claims: {Claims}.",
                                        context.AuthorizationCodePrincipal.GetClaim(Claims.JwtId),
                                        context.Response.Code, context.AuthorizationCodePrincipal.Claims);

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating a device code using Data Protection.
        /// </summary>
        public class GenerateDataProtectionDeviceCode : IOpenIddictServerHandler<ProcessSignInContext>
        {
            private readonly IOptionsMonitor<OpenIddictServerDataProtectionOptions> _options;

            public GenerateDataProtectionDeviceCode([NotNull] IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
                => _options = options;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireDeviceCodeIncluded>()
                    .AddFilter<RequireDataProtectionDeviceCodeFormatEnabled>()
                    .UseSingletonHandler<GenerateDataProtectionDeviceCode>()
                    .SetOrder(GenerateIdentityModelDeviceCode.Descriptor.Order - 500)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If a device code was already attached by another handler, don't overwrite it.
                if (!string.IsNullOrEmpty(context.Response.DeviceCode))
                {
                    return default;
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

                context.Response.DeviceCode = Base64UrlEncoder.Encode(protector.Protect(buffer.ToArray()));

                context.Logger.LogTrace("The device code '{Identifier}' was successfully created: {Payload}. " +
                                        "The principal used to create the token contained the following claims: {Claims}.",
                                        context.DeviceCodePrincipal.GetClaim(Claims.JwtId),
                                        context.Response.DeviceCode, context.DeviceCodePrincipal.Claims);

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating a refresh token using Data Protection.
        /// </summary>
        public class GenerateDataProtectionRefreshToken : IOpenIddictServerHandler<ProcessSignInContext>
        {
            private readonly IOptionsMonitor<OpenIddictServerDataProtectionOptions> _options;

            public GenerateDataProtectionRefreshToken([NotNull] IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
                => _options = options;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireRefreshTokenIncluded>()
                    .AddFilter<RequireDataProtectionRefreshTokenFormatEnabled>()
                    .UseSingletonHandler<GenerateDataProtectionRefreshToken>()
                    .SetOrder(GenerateIdentityModelRefreshToken.Descriptor.Order - 500)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If a refresh token was already attached by another handler, don't overwrite it.
                if (!string.IsNullOrEmpty(context.Response.RefreshToken))
                {
                    return default;
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

                context.Response.RefreshToken = Base64UrlEncoder.Encode(protector.Protect(buffer.ToArray()));

                context.Logger.LogTrace("The refresh token '{Identifier}' was successfully created: {Payload}. " +
                                        "The principal used to create the token contained the following claims: {Claims}.",
                                        context.RefreshTokenPrincipal.GetClaim(Claims.JwtId),
                                        context.Response.RefreshToken, context.RefreshTokenPrincipal.Claims);

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating a user code using Data Protection.
        /// </summary>
        public class GenerateDataProtectionUserCode : IOpenIddictServerHandler<ProcessSignInContext>
        {
            private readonly IOptionsMonitor<OpenIddictServerDataProtectionOptions> _options;

            public GenerateDataProtectionUserCode([NotNull] IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
                => _options = options;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireUserCodeIncluded>()
                    .AddFilter<RequireDataProtectionUserCodeFormatEnabled>()
                    .UseSingletonHandler<GenerateDataProtectionUserCode>()
                    .SetOrder(GenerateIdentityModelUserCode.Descriptor.Order - 500)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessSignInContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If a user code was already attached by another handler, don't overwrite it.
                if (!string.IsNullOrEmpty(context.Response.UserCode))
                {
                    return default;
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

                context.Response.UserCode = Base64UrlEncoder.Encode(protector.Protect(buffer.ToArray()));

                context.Logger.LogTrace("The user code '{Identifier}' was successfully created: {Payload}. " +
                                        "The principal used to create the token contained the following claims: {Claims}.",
                                        context.UserCodePrincipal.GetClaim(Claims.JwtId),
                                        context.Response.UserCode, context.UserCodePrincipal.Claims);

                return default;
            }
        }
    }
}
