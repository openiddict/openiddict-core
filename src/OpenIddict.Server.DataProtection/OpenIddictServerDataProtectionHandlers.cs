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
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.DataProtection.OpenIddictServerDataProtectionConstants;
using static OpenIddict.Server.DataProtection.OpenIddictServerDataProtectionHandlerFilters;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlerFilters;
using static OpenIddict.Server.OpenIddictServerHandlers;

namespace OpenIddict.Server.DataProtection
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static partial class OpenIddictServerDataProtectionHandlers
    {
        public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Authentication processing:
             */
            ValidateReferenceDataProtectionToken.Descriptor,
            ValidateSelfContainedDataProtectionToken.Descriptor,
            
            /*
             * Sign-in processing:
             */
            AttachReferenceDataProtectionAccessToken.Descriptor,
            AttachReferenceDataProtectionAuthorizationCode.Descriptor,
            AttachReferenceDataProtectionRefreshToken.Descriptor,

            AttachSelfContainedDataProtectionAccessToken.Descriptor,
            AttachSelfContainedDataProtectionAuthorizationCode.Descriptor,
            AttachSelfContainedDataProtectionRefreshToken.Descriptor);

        /// <summary>
        /// Contains the logic responsible of rejecting authentication
        /// demands that use an invalid reference Data Protection token.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ValidateReferenceDataProtectionToken : IOpenIddictServerHandler<ProcessAuthenticationContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;
            private readonly IOptionsMonitor<OpenIddictServerDataProtectionOptions> _options;

            public ValidateReferenceDataProtectionToken() => throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                .ToString());

            public ValidateReferenceDataProtectionToken(
                [NotNull] IOpenIddictTokenManager tokenManager,
                [NotNull] IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
            {
                _tokenManager = tokenManager;
                _options = options;
            }

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
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

                var identifier = context.EndpointType switch
                {
                    OpenIddictServerEndpointType.Introspection => context.Request.Token,
                    OpenIddictServerEndpointType.Revocation    => context.Request.Token,

                    OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType()
                        => context.Request.Code,
                    OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                        => context.Request.RefreshToken,

                    OpenIddictServerEndpointType.Userinfo => context.Request.AccessToken,

                    _ => null
                };

                // If the token cannot be validated, don't return an error to allow another handle to validate it.
                if (string.IsNullOrEmpty(identifier))
                {
                    return;
                }

                var token = await _tokenManager.FindByReferenceIdAsync(identifier);
                if (token == null || !await IsTokenTypeValidAsync(token))
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

                var principal = context.EndpointType switch
                {
                    OpenIddictServerEndpointType.Introspection => ValidateToken(payload, TokenUsages.AccessToken)  ??
                                                                  ValidateToken(payload, TokenUsages.RefreshToken) ??
                                                                  ValidateToken(payload, TokenUsages.AuthorizationCode),

                    OpenIddictServerEndpointType.Revocation => ValidateToken(payload, TokenUsages.AccessToken)  ??
                                                               ValidateToken(payload, TokenUsages.RefreshToken) ??
                                                               ValidateToken(payload, TokenUsages.AuthorizationCode),

                    OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType()
                        => ValidateToken(payload, TokenUsages.AuthorizationCode),

                    OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                        => ValidateToken(payload, TokenUsages.RefreshToken),

                    OpenIddictServerEndpointType.Userinfo => ValidateToken(payload, TokenUsages.AccessToken),

                    _ => null
                };

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

                context.Logger.LogTrace("The reference DP token '{Token}' was successfully validated and the following " +
                                        "claims could be extracted: {Claims}.", payload, context.Principal.Claims);

                ClaimsPrincipal ValidateToken(string token, string type)
                {
                    // Create a Data Protection protector using the provider registered in the options.
                    var protector = _options.CurrentValue.DataProtectionProvider.CreateProtector(
                        Purposes.Handlers.Server,
                        type switch
                        {
                            TokenUsages.AccessToken       => Purposes.Formats.AccessToken,
                            TokenUsages.AuthorizationCode => Purposes.Formats.AuthorizationCode,
                            TokenUsages.RefreshToken      => Purposes.Formats.RefreshToken,

                            _ => throw new InvalidOperationException("The specified token type is not supported.")
                        },
                        Purposes.Features.ReferenceTokens,
                        Purposes.Schemes.Server);

                    try
                    {
                        using var buffer = new MemoryStream(protector.Unprotect(Base64UrlEncoder.DecodeBytes(token)));
                        using var reader = new BinaryReader(buffer);

                        // Note: since the data format relies on a data protector using different "purposes" strings
                        // per token type, the token processed at this stage is guaranteed to be of the expected type.
                        return _options.CurrentValue.Formatter.ReadToken(reader)?.SetClaim(Claims.Private.TokenUsage, type);
                    }

                    catch (Exception exception)
                    {
                        context.Logger.LogTrace(exception, "An exception occured while deserializing the token '{Token}'.", token);

                        return null;
                    }
                }

                async ValueTask<bool> IsTokenTypeValidAsync(object token) => context.EndpointType switch
                {
                    // All types of tokens are accepted by the introspection and revocation endpoints.
                    OpenIddictServerEndpointType.Introspection => true,
                    OpenIddictServerEndpointType.Revocation    => true,

                    OpenIddictServerEndpointType.Token => await _tokenManager.GetTypeAsync(token) switch
                    {
                        TokenUsages.AuthorizationCode when context.Request.IsAuthorizationCodeGrantType() => true,
                        TokenUsages.RefreshToken      when context.Request.IsRefreshTokenGrantType()      => true,

                        _ => false
                    },

                    OpenIddictServerEndpointType.Userinfo => await _tokenManager.GetTypeAsync(token) switch
                    {
                        TokenUsages.AccessToken => true,

                        _ => false
                    },

                    _ => false
                };
            }
        }

        /// <summary>
        /// Contains the logic responsible of rejecting authentication demands
        /// that specify an invalid self-contained Data Protection token.
        /// </summary>
        public class ValidateSelfContainedDataProtectionToken : IOpenIddictServerHandler<ProcessAuthenticationContext>
        {
            private readonly IOptionsMonitor<OpenIddictServerDataProtectionOptions> _options;

            public ValidateSelfContainedDataProtectionToken([NotNull] IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
                => _options = options;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
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

                var token = context.EndpointType switch
                {
                    OpenIddictServerEndpointType.Introspection => context.Request.Token,
                    OpenIddictServerEndpointType.Revocation    => context.Request.Token,

                    // This handler doesn't handle reference tokens.
                    _ when context.Options.UseReferenceTokens  => null,

                    OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType()
                        => context.Request.Code,
                    OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                        => context.Request.RefreshToken,

                    OpenIddictServerEndpointType.Userinfo => context.Request.AccessToken,

                    _ => null
                };

                // If the token cannot be validated, don't return an error to allow another handle to validate it.
                if (string.IsNullOrEmpty(token))
                {
                    return default;
                }

                var principal = context.EndpointType switch
                {
                    OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType()
                        => ValidateToken(token, TokenUsages.AuthorizationCode),

                    OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                        => ValidateToken(token, TokenUsages.RefreshToken),

                    OpenIddictServerEndpointType.Introspection => ValidateToken(token, TokenUsages.AccessToken)  ??
                                                                  ValidateToken(token, TokenUsages.RefreshToken) ??
                                                                  ValidateToken(token, TokenUsages.AuthorizationCode),

                    OpenIddictServerEndpointType.Revocation => ValidateToken(token, TokenUsages.AccessToken)  ??
                                                               ValidateToken(token, TokenUsages.RefreshToken) ??
                                                               ValidateToken(token, TokenUsages.AuthorizationCode),

                    OpenIddictServerEndpointType.Userinfo => ValidateToken(token, TokenUsages.AccessToken),

                    _ => null
                };

                // If the token cannot be validated, don't return an error to allow another handle to validate it.
                if (principal == null)
                {
                    return default;
                }

                context.Principal = principal;

                context.Logger.LogTrace("The self-contained DP token '{Token}' was successfully validated and the following " +
                                        "claims could be extracted: {Claims}.", token, context.Principal.Claims);

                return default;

                ClaimsPrincipal ValidateToken(string token, string type)
                {
                    // Create a Data Protection protector using the provider registered in the options.
                    var protector = _options.CurrentValue.DataProtectionProvider.CreateProtector(
                        Purposes.Handlers.Server,
                        type switch
                        {
                            TokenUsages.AccessToken       => Purposes.Formats.AccessToken,
                            TokenUsages.AuthorizationCode => Purposes.Formats.AuthorizationCode,
                            TokenUsages.RefreshToken      => Purposes.Formats.RefreshToken,

                            _ => throw new InvalidOperationException("The specified token type is not supported.")
                        },
                        Purposes.Schemes.Server);

                    try
                    {
                        using var buffer = new MemoryStream(protector.Unprotect(Base64UrlEncoder.DecodeBytes(token)));
                        using var reader = new BinaryReader(buffer);

                        // Note: since the data format relies on a data protector using different "purposes" strings
                        // per token type, the token processed at this stage is guaranteed to be of the expected type.
                        return _options.CurrentValue.Formatter.ReadToken(reader)?.SetClaim(Claims.Private.TokenUsage, type);
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
        /// Contains the logic responsible of generating and attaching the
        /// reference Data Protection access token returned as part of the response.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class AttachReferenceDataProtectionAccessToken : IOpenIddictServerHandler<ProcessSigninContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;
            private readonly IOpenIddictTokenManager _tokenManager;
            private readonly IOptionsMonitor<OpenIddictServerDataProtectionOptions> _options;

            public AttachReferenceDataProtectionAccessToken() => throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                .ToString());

            public AttachReferenceDataProtectionAccessToken(
                [NotNull] IOpenIddictApplicationManager applicationManager,
                [NotNull] IOpenIddictTokenManager tokenManager,
                [NotNull] IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
            {
                _applicationManager = applicationManager;
                _tokenManager = tokenManager;
                _options = options;
            }

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .AddFilter<RequireAccessTokenIncluded>()
                    .AddFilter<RequireReferenceTokensEnabled>()
                    .AddFilter<RequirePreferDataProtectionFormatEnabled>()
                    .UseScopedHandler<AttachReferenceDataProtectionAccessToken>()
                    .SetOrder(AttachReferenceAccessToken.Descriptor.Order - 500)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async ValueTask HandleAsync([NotNull] ProcessSigninContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If an access token was already attached by another handler, don't overwrite it.
                if (!string.IsNullOrEmpty(context.Response.AccessToken))
                {
                    return;
                }

                // Create a Data Protection protector using the provider registered in the options.
                var protector = _options.CurrentValue.DataProtectionProvider.CreateProtector(
                    Purposes.Handlers.Server,
                    Purposes.Formats.AccessToken,
                    Purposes.Features.ReferenceTokens,
                    Purposes.Schemes.Server);

                using var buffer = new MemoryStream();
                using var writer = new BinaryWriter(buffer);

                _options.CurrentValue.Formatter.WriteToken(writer, context.AccessTokenPrincipal);

                // Generate a new crypto-secure random identifier that will be substituted to the token.
                var data = new byte[256 / 8];
#if SUPPORTS_STATIC_RANDOM_NUMBER_GENERATOR_METHODS
                RandomNumberGenerator.Fill(data);
#else
                using var generator = RandomNumberGenerator.Create();
                generator.GetBytes(data);
#endif
                var descriptor = new OpenIddictTokenDescriptor
                {
                    AuthorizationId = context.AccessTokenPrincipal.GetInternalAuthorizationId(),
                    CreationDate = context.AccessTokenPrincipal.GetCreationDate(),
                    ExpirationDate = context.AccessTokenPrincipal.GetExpirationDate(),
                    Payload = Base64UrlEncoder.Encode(protector.Protect(buffer.ToArray())),
                    Principal = context.AccessTokenPrincipal,
                    ReferenceId = Base64UrlEncoder.Encode(data),
                    Status = Statuses.Valid,
                    Subject = context.AccessTokenPrincipal.GetClaim(Claims.Subject),
                    Type = TokenUsages.AccessToken
                };

                // If the client application is known, associate it with the token.
                if (!string.IsNullOrEmpty(context.Request.ClientId))
                {
                    var application = await _applicationManager.FindByClientIdAsync(context.Request.ClientId);
                    if (application == null)
                    {
                        throw new InvalidOperationException("The application entry cannot be found in the database.");
                    }

                    descriptor.ApplicationId = await _applicationManager.GetIdAsync(application);
                }

                var token = await _tokenManager.CreateAsync(descriptor);

                context.Response.AccessToken = descriptor.ReferenceId;

                context.Logger.LogTrace("The reference access token '{Identifier}' was successfully created with the " +
                                        "reference identifier '{ReferenceId}' and the following DP payload: {Payload}. " +
                                        "The principal used to create the token contained the following claims: {Claims}.",
                                        await _tokenManager.GetIdAsync(token), descriptor.ReferenceId,
                                        descriptor.Payload, context.AccessTokenPrincipal.Claims);
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating and attaching the
        /// reference Data Protection authorization code returned as part of the response.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class AttachReferenceDataProtectionAuthorizationCode : IOpenIddictServerHandler<ProcessSigninContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;
            private readonly IOpenIddictTokenManager _tokenManager;
            private readonly IOptionsMonitor<OpenIddictServerDataProtectionOptions> _options;

            public AttachReferenceDataProtectionAuthorizationCode() => throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                .ToString());

            public AttachReferenceDataProtectionAuthorizationCode(
                [NotNull] IOpenIddictApplicationManager applicationManager,
                [NotNull] IOpenIddictTokenManager tokenManager,
                [NotNull] IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
            {
                _applicationManager = applicationManager;
                _tokenManager = tokenManager;
                _options = options;
            }

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .AddFilter<RequireAuthorizationCodeIncluded>()
                    .AddFilter<RequireReferenceTokensEnabled>()
                    .AddFilter<RequirePreferDataProtectionFormatEnabled>()
                    .UseScopedHandler<AttachReferenceDataProtectionAuthorizationCode>()
                    .SetOrder(AttachReferenceAuthorizationCode.Descriptor.Order - 500)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async ValueTask HandleAsync([NotNull] ProcessSigninContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If an authorization code was already attached by another handler, don't overwrite it.
                if (!string.IsNullOrEmpty(context.Response.Code))
                {
                    return;
                }

                // Create a Data Protection protector using the provider registered in the options.
                var protector = _options.CurrentValue.DataProtectionProvider.CreateProtector(
                    Purposes.Handlers.Server,
                    Purposes.Formats.AuthorizationCode,
                    Purposes.Features.ReferenceTokens,
                    Purposes.Schemes.Server);

                using var buffer = new MemoryStream();
                using var writer = new BinaryWriter(buffer);

                _options.CurrentValue.Formatter.WriteToken(writer, context.AuthorizationCodePrincipal);

                // Generate a new crypto-secure random identifier that will be substituted to the token.
                var data = new byte[256 / 8];
#if SUPPORTS_STATIC_RANDOM_NUMBER_GENERATOR_METHODS
                RandomNumberGenerator.Fill(data);
#else
                using var generator = RandomNumberGenerator.Create();
                generator.GetBytes(data);
#endif
                var descriptor = new OpenIddictTokenDescriptor
                {
                    AuthorizationId = context.AuthorizationCodePrincipal.GetInternalAuthorizationId(),
                    CreationDate = context.AuthorizationCodePrincipal.GetCreationDate(),
                    ExpirationDate = context.AuthorizationCodePrincipal.GetExpirationDate(),
                    Payload = Base64UrlEncoder.Encode(protector.Protect(buffer.ToArray())),
                    Principal = context.AuthorizationCodePrincipal,
                    ReferenceId = Base64UrlEncoder.Encode(data),
                    Status = Statuses.Valid,
                    Subject = context.AuthorizationCodePrincipal.GetClaim(Claims.Subject),
                    Type = TokenUsages.AuthorizationCode
                };

                // If the client application is known, associate it with the token.
                if (!string.IsNullOrEmpty(context.Request.ClientId))
                {
                    var application = await _applicationManager.FindByClientIdAsync(context.Request.ClientId);
                    if (application == null)
                    {
                        throw new InvalidOperationException("The application entry cannot be found in the database.");
                    }

                    descriptor.ApplicationId = await _applicationManager.GetIdAsync(application);
                }

                var token = await _tokenManager.CreateAsync(descriptor);

                context.Response.Code = descriptor.ReferenceId;

                context.Logger.LogTrace("The reference authorization code '{Identifier}' was successfully created with the " +
                                        "reference identifier '{ReferenceId}' and the following DP payload: {Payload}. " +
                                        "The principal used to create the token contained the following claims: {Claims}.",
                                        await _tokenManager.GetIdAsync(token), descriptor.ReferenceId,
                                        descriptor.Payload, context.AuthorizationCodePrincipal.Claims);
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating and attaching the
        /// reference Data Protection refresh token returned as part of the response.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class AttachReferenceDataProtectionRefreshToken : IOpenIddictServerHandler<ProcessSigninContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;
            private readonly IOpenIddictTokenManager _tokenManager;
            private readonly IOptionsMonitor<OpenIddictServerDataProtectionOptions> _options;

            public AttachReferenceDataProtectionRefreshToken() => throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                .ToString());

            public AttachReferenceDataProtectionRefreshToken(
                [NotNull] IOpenIddictApplicationManager applicationManager,
                [NotNull] IOpenIddictTokenManager tokenManager,
                [NotNull] IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
            {
                _applicationManager = applicationManager;
                _tokenManager = tokenManager;
                _options = options;
            }

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .AddFilter<RequireRefreshTokenIncluded>()
                    .AddFilter<RequireReferenceTokensEnabled>()
                    .AddFilter<RequirePreferDataProtectionFormatEnabled>()
                    .UseScopedHandler<AttachReferenceDataProtectionRefreshToken>()
                    .SetOrder(AttachReferenceRefreshToken.Descriptor.Order - 500)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async ValueTask HandleAsync([NotNull] ProcessSigninContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If a refresh token was already attached by another handler, don't overwrite it.
                if (!string.IsNullOrEmpty(context.Response.RefreshToken))
                {
                    return;
                }

                // Create a Data Protection protector using the provider registered in the options.
                var protector = _options.CurrentValue.DataProtectionProvider.CreateProtector(
                    Purposes.Handlers.Server,
                    Purposes.Formats.RefreshToken,
                    Purposes.Features.ReferenceTokens,
                    Purposes.Schemes.Server);

                using var buffer = new MemoryStream();
                using var writer = new BinaryWriter(buffer);

                _options.CurrentValue.Formatter.WriteToken(writer, context.RefreshTokenPrincipal);

                // Generate a new crypto-secure random identifier that will be substituted to the token.
                var data = new byte[256 / 8];
#if SUPPORTS_STATIC_RANDOM_NUMBER_GENERATOR_METHODS
                RandomNumberGenerator.Fill(data);
#else
                using var generator = RandomNumberGenerator.Create();
                generator.GetBytes(data);
#endif
                var descriptor = new OpenIddictTokenDescriptor
                {
                    AuthorizationId = context.RefreshTokenPrincipal.GetInternalAuthorizationId(),
                    CreationDate = context.RefreshTokenPrincipal.GetCreationDate(),
                    ExpirationDate = context.RefreshTokenPrincipal.GetExpirationDate(),
                    Payload = Base64UrlEncoder.Encode(protector.Protect(buffer.ToArray())),
                    Principal = context.RefreshTokenPrincipal,
                    ReferenceId = Base64UrlEncoder.Encode(data),
                    Status = Statuses.Valid,
                    Subject = context.RefreshTokenPrincipal.GetClaim(Claims.Subject),
                    Type = TokenUsages.RefreshToken
                };

                // If the client application is known, associate it with the token.
                if (!string.IsNullOrEmpty(context.Request.ClientId))
                {
                    var application = await _applicationManager.FindByClientIdAsync(context.Request.ClientId);
                    if (application == null)
                    {
                        throw new InvalidOperationException("The application entry cannot be found in the database.");
                    }

                    descriptor.ApplicationId = await _applicationManager.GetIdAsync(application);
                }

                var token = await _tokenManager.CreateAsync(descriptor);

                context.Response.RefreshToken = descriptor.ReferenceId;

                context.Logger.LogTrace("The reference refresh token '{Identifier}' was successfully created with the " +
                                        "reference identifier '{ReferenceId}' and the following DP payload: {Payload}. " +
                                        "The principal used to create the token contained the following claims: {Claims}.",
                                        await _tokenManager.GetIdAsync(token), descriptor.ReferenceId,
                                        descriptor.Payload, context.RefreshTokenPrincipal.Claims);
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating and attaching the self-contained
        /// Data Protection access token returned as part of the response.
        /// </summary>
        public class AttachSelfContainedDataProtectionAccessToken : IOpenIddictServerHandler<ProcessSigninContext>
        {
            private readonly IOptionsMonitor<OpenIddictServerDataProtectionOptions> _options;

            public AttachSelfContainedDataProtectionAccessToken([NotNull] IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
                => _options = options;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireReferenceTokensDisabled>()
                    .AddFilter<RequireAccessTokenIncluded>()
                    .AddFilter<RequirePreferDataProtectionFormatEnabled>()
                    .UseSingletonHandler<AttachSelfContainedDataProtectionAccessToken>()
                    .SetOrder(AttachSelfContainedAccessToken.Descriptor.Order - 500)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessSigninContext context)
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
                var protector = _options.CurrentValue.DataProtectionProvider.CreateProtector(
                    Purposes.Handlers.Server,
                    Purposes.Formats.AccessToken,
                    Purposes.Schemes.Server);

                using var buffer = new MemoryStream();
                using var writer = new BinaryWriter(buffer);

                _options.CurrentValue.Formatter.WriteToken(writer, context.AccessTokenPrincipal);

                context.Response.AccessToken = Base64UrlEncoder.Encode(protector.Protect(buffer.ToArray()));

                context.Logger.LogTrace("The access token '{Identifier}' was successfully created and the " +
                                        "following DP payload was attached to the OpenID Connect response: {Payload}. " +
                                        "The principal used to create the token contained the following claims: {Claims}.",
                                        context.AccessTokenPrincipal.GetClaim(Claims.JwtId),
                                        context.Response.AccessToken, context.AccessTokenPrincipal.Claims);

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating and attaching the self-contained
        /// Data Protection authorization code returned as part of the response.
        /// </summary>
        public class AttachSelfContainedDataProtectionAuthorizationCode : IOpenIddictServerHandler<ProcessSigninContext>
        {
            private readonly IOptionsMonitor<OpenIddictServerDataProtectionOptions> _options;

            public AttachSelfContainedDataProtectionAuthorizationCode([NotNull] IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
                => _options = options;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireReferenceTokensDisabled>()
                    .AddFilter<RequireAuthorizationCodeIncluded>()
                    .AddFilter<RequirePreferDataProtectionFormatEnabled>()
                    .UseSingletonHandler<AttachSelfContainedDataProtectionAuthorizationCode>()
                    .SetOrder(AttachSelfContainedAuthorizationCode.Descriptor.Order - 500)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessSigninContext context)
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
                var protector = _options.CurrentValue.DataProtectionProvider.CreateProtector(
                    Purposes.Handlers.Server,
                    Purposes.Formats.AuthorizationCode,
                    Purposes.Schemes.Server);

                using var buffer = new MemoryStream();
                using var writer = new BinaryWriter(buffer);

                _options.CurrentValue.Formatter.WriteToken(writer, context.AuthorizationCodePrincipal);

                context.Response.Code = Base64UrlEncoder.Encode(protector.Protect(buffer.ToArray()));

                context.Logger.LogTrace("The authorization code '{Identifier}' was successfully created and the " +
                                        "following JWT payload was attached to the OpenID Connect response: {Payload}. " +
                                        "The principal used to create the token contained the following claims: {Claims}.",
                                        context.AccessTokenPrincipal.GetClaim(Claims.JwtId),
                                        context.Response.Code, context.AuthorizationCodePrincipal.Claims);

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating and attaching the self-contained
        /// Data Protection refresh token returned as part of the response.
        /// </summary>
        public class AttachSelfContainedDataProtectionRefreshToken : IOpenIddictServerHandler<ProcessSigninContext>
        {
            private readonly IOptionsMonitor<OpenIddictServerDataProtectionOptions> _options;

            public AttachSelfContainedDataProtectionRefreshToken([NotNull] IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
                => _options = options;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireReferenceTokensDisabled>()
                    .AddFilter<RequireRefreshTokenIncluded>()
                    .AddFilter<RequirePreferDataProtectionFormatEnabled>()
                    .UseSingletonHandler<AttachSelfContainedDataProtectionRefreshToken>()
                    .SetOrder(AttachSelfContainedRefreshToken.Descriptor.Order - 500)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessSigninContext context)
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
                var protector = _options.CurrentValue.DataProtectionProvider.CreateProtector(
                    Purposes.Handlers.Server,
                    Purposes.Formats.RefreshToken,
                    Purposes.Schemes.Server);

                using var buffer = new MemoryStream();
                using var writer = new BinaryWriter(buffer);

                _options.CurrentValue.Formatter.WriteToken(writer, context.RefreshTokenPrincipal);

                context.Response.RefreshToken = Base64UrlEncoder.Encode(protector.Protect(buffer.ToArray()));

                context.Logger.LogTrace("The refresh token '{Identifier}' was successfully created and the " +
                                        "following JWT payload was attached to the OpenID Connect response: {Payload}. " +
                                        "The principal used to create the token contained the following claims: {Claims}.",
                                        context.AccessTokenPrincipal.GetClaim(Claims.JwtId),
                                        context.Response.RefreshToken, context.RefreshTokenPrincipal.Claims);

                return default;
            }
        }
    }
}
