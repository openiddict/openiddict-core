/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlerFilters;
using Properties = OpenIddict.Server.OpenIddictServerConstants.Properties;

namespace OpenIddict.Server
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static partial class OpenIddictServerHandlers
    {
        public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Authentication processing:
             */
            ValidateAuthenticationDemand.Descriptor,
            ValidateTokenParameter.Descriptor,
            NormalizeUserCode.Descriptor,
            ValidateReferenceTokenIdentifier.Descriptor,
            ValidateIdentityModelToken.Descriptor,
            RestoreReferenceTokenProperties.Descriptor,
            ValidatePrincipal.Descriptor,
            ValidateTokenEntry.Descriptor,
            ValidateAuthorizationEntry.Descriptor,
            ValidateExpirationDate.Descriptor,

            /*
             * Challenge processing:
             */
            ValidateChallengeDemand.Descriptor,
            AttachDefaultChallengeError.Descriptor,
            RejectDeviceCodeEntry.Descriptor,
            RejectUserCodeEntry.Descriptor,

            /*
            * Sign-in processing:
            */
            ValidateSigninDemand.Descriptor,
            RestoreInternalClaims.Descriptor,
            AttachDefaultScopes.Descriptor,
            AttachDefaultPresenters.Descriptor,
            InferResources.Descriptor,
            EvaluateReturnedTokens.Descriptor,
            AttachAuthorization.Descriptor,

            PrepareAccessTokenPrincipal.Descriptor,
            PrepareAuthorizationCodePrincipal.Descriptor,
            PrepareDeviceCodePrincipal.Descriptor,
            PrepareRefreshTokenPrincipal.Descriptor,
            PrepareIdentityTokenPrincipal.Descriptor,
            PrepareUserCodePrincipal.Descriptor,

            RedeemTokenEntry.Descriptor,
            RedeemDeviceCodeEntry.Descriptor,
            RedeemUserCodeEntry.Descriptor,
            RevokeExistingTokenEntries.Descriptor,
            ExtendRefreshTokenEntry.Descriptor,

            GenerateIdentityModelAccessToken.Descriptor,
            CreateReferenceAccessTokenEntry.Descriptor,

            GenerateIdentityModelAuthorizationCode.Descriptor,
            CreateReferenceAuthorizationCodeEntry.Descriptor,

            GenerateIdentityModelDeviceCode.Descriptor,
            CreateReferenceDeviceCodeEntry.Descriptor,
            UpdateReferenceDeviceCodeEntry.Descriptor,

            GenerateIdentityModelRefreshToken.Descriptor,
            CreateReferenceRefreshTokenEntry.Descriptor,

            AttachDeviceCodeIdentifier.Descriptor,
            GenerateIdentityModelUserCode.Descriptor,
            CreateReferenceUserCodeEntry.Descriptor,

            AttachTokenDigests.Descriptor,
            GenerateIdentityModelIdentityToken.Descriptor,

            BeautifyUserCode.Descriptor,
            AttachAccessTokenProperties.Descriptor,
            AttachDeviceCodeProperties.Descriptor)

            .AddRange(Authentication.DefaultHandlers)
            .AddRange(Device.DefaultHandlers)
            .AddRange(Discovery.DefaultHandlers)
            .AddRange(Exchange.DefaultHandlers)
            .AddRange(Introspection.DefaultHandlers)
            .AddRange(Revocation.DefaultHandlers)
            .AddRange(Session.DefaultHandlers)
            .AddRange(Userinfo.DefaultHandlers);

        /// <summary>
        /// Contains the logic responsible of rejecting authentication demands made from unsupported endpoints.
        /// </summary>
        public class ValidateAuthenticationDemand : IOpenIddictServerHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .UseSingletonHandler<ValidateAuthenticationDemand>()
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

                switch (context.EndpointType)
                {
                    case OpenIddictServerEndpointType.Authorization:
                    case OpenIddictServerEndpointType.Introspection:
                    case OpenIddictServerEndpointType.Logout:
                    case OpenIddictServerEndpointType.Revocation:
                    case OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType():
                    case OpenIddictServerEndpointType.Token when context.Request.IsDeviceCodeGrantType():
                    case OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType():
                    case OpenIddictServerEndpointType.Userinfo:
                    case OpenIddictServerEndpointType.Verification:
                        return default;

                    default: throw new InvalidOperationException("No identity cannot be extracted from this request.");
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of resolving the token from the incoming request.
        /// </summary>
        public class ValidateTokenParameter : IOpenIddictServerHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .UseSingletonHandler<ValidateTokenParameter>()
                    .SetOrder(ValidateAuthenticationDemand.Descriptor.Order + 1_000)
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

                var (token, type) = context.EndpointType switch
                {
                    OpenIddictServerEndpointType.Authorization => (context.Request.IdTokenHint, TokenUsages.IdToken),
                    OpenIddictServerEndpointType.Logout        => (context.Request.IdTokenHint, TokenUsages.IdToken),

                    // Generic tokens received by the introspection and revocation can be of any type.
                    // Additional token type filtering is made by the endpoint themselves, if needed.
                    OpenIddictServerEndpointType.Introspection => (context.Request.Token, null),
                    OpenIddictServerEndpointType.Revocation    => (context.Request.Token, null),

                    OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType()
                        => (context.Request.Code, TokenUsages.AuthorizationCode),
                    OpenIddictServerEndpointType.Token when context.Request.IsDeviceCodeGrantType()
                        => (context.Request.DeviceCode, TokenUsages.DeviceCode),
                    OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                        => (context.Request.RefreshToken, TokenUsages.RefreshToken),

                    OpenIddictServerEndpointType.Userinfo => (context.Request.AccessToken, TokenUsages.AccessToken),

                    OpenIddictServerEndpointType.Verification => (context.Request.UserCode, TokenUsages.UserCode),

                    _ => (null, null)
                };

                if (string.IsNullOrEmpty(token))
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: context.EndpointType switch
                        {
                            OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType()
                                => "The authorization code is missing.",
                            OpenIddictServerEndpointType.Token when context.Request.IsDeviceCodeGrantType()
                                => "The specified device code is missing.",
                            OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                                => "The specified refresh token is missing.",

                            _ => "The security token is missing."
                        });

                    return default;
                }

                context.Token = token;
                context.TokenType = type;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of normalizing user codes.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class NormalizeUserCode : IOpenIddictServerHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    // Technically, this handler doesn't require that the degraded mode be disabled
                    // but the default CreateReferenceUserCodeEntry that creates the user code
                    // reference identifiers only works when the degraded mode is disabled.
                    .AddFilter<RequireDegradedModeDisabled>()
                    .UseSingletonHandler<NormalizeUserCode>()
                    .SetOrder(ValidateTokenParameter.Descriptor.Order + 1_000)
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

                if (!string.Equals(context.TokenType, TokenUsages.UserCode, StringComparison.OrdinalIgnoreCase))
                {
                    return default;
                }

                // Note: unlike other tokens, user codes may be potentially entered manually by users in a web form.
                // To make that easier, user codes are generally "beautified" by adding intermediate dashes to
                // make them easier to read and type. Since these additional characters are not part of the original
                // user codes, non-digit characters are automatically filtered from the reference identifier.

                var builder = new StringBuilder(context.Token);
                for (var index = builder.Length - 1; index >= 0; index--)
                {
                    var character = builder[index];
                    if (character < '0' || character > '9')
                    {
                        builder.Remove(index, 1);
                    }
                }

                context.Token = builder.ToString();

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of validating reference token identifiers.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ValidateReferenceTokenIdentifier : IOpenIddictServerHandler<ProcessAuthenticationContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public ValidateReferenceTokenIdentifier() => throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                .ToString());

            public ValidateReferenceTokenIdentifier([NotNull] IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .UseScopedHandler<ValidateReferenceTokenIdentifier>()
                    .SetOrder(NormalizeUserCode.Descriptor.Order + 1_000)
                    .Build();

            public async ValueTask HandleAsync([NotNull] ProcessAuthenticationContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If the reference token cannot be found, don't return an error to allow another handle to validate it.
                var token = await _tokenManager.FindByReferenceIdAsync(context.Token);
                if (token == null)
                {
                    return;
                }

                // If the type associated with the token entry doesn't match the expected type, return an error.
                if (!string.IsNullOrEmpty(context.TokenType) &&
                    !string.Equals(context.TokenType, await _tokenManager.GetTypeAsync(token)))
                {
                    context.Reject(
                        error: context.EndpointType switch
                        {
                            OpenIddictServerEndpointType.Token => Errors.InvalidGrant,
                            _                                  => Errors.InvalidToken
                        },
                        description: context.EndpointType switch
                        {
                            OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType()
                                => "The specified authorization code is invalid.",
                            OpenIddictServerEndpointType.Token when context.Request.IsDeviceCodeGrantType()
                                => "The specified device code is invalid.",
                            OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                                => "The specified refresh token is invalid.",

                            _ => "The specified token is invalid."
                        });

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
        public class ValidateIdentityModelToken : IOpenIddictServerHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
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

                var parameters = context.Options.TokenValidationParameters.Clone();
                parameters.ValidIssuer = context.Issuer?.AbsoluteUri;
                parameters.IssuerSigningKeys = context.Options.SigningCredentials.Select(credentials => credentials.Key);
                parameters.TokenDecryptionKeys = context.Options.EncryptionCredentials.Select(credentials => credentials.Key);

                // If a specific token type is expected, override the default valid types to reject
                // security tokens whose "typ" header doesn't match the expected token type.
                if (!string.IsNullOrEmpty(context.TokenType))
                {
                    parameters.ValidTypes = new[]
                    {
                        context.TokenType switch
                        {
                            TokenUsages.AccessToken => JsonWebTokenTypes.AccessToken,
                            TokenUsages.IdToken     => JsonWebTokenTypes.IdentityToken,

                            TokenUsages.AuthorizationCode => JsonWebTokenTypes.Private.AuthorizationCode,
                            TokenUsages.DeviceCode        => JsonWebTokenTypes.Private.DeviceCode,
                            TokenUsages.RefreshToken      => JsonWebTokenTypes.Private.RefreshToken,
                            TokenUsages.UserCode          => JsonWebTokenTypes.Private.UserCode,

                            _ => throw new InvalidOperationException("The token type is not supported.")
                        }
                    };
                }

                // If the token cannot be validated, don't return an error to allow another handle to validate it.
                var result = context.Options.JsonWebTokenHandler.ValidateToken(context.Token, parameters);
                if (!result.IsValid)
                {
                    context.Logger.LogTrace(result.Exception, "An error occurred while validating the token '{Token}'.", context.Token);

                    return default;
                }

                // Get the JWT token. If the token is encrypted using JWE, retrieve the inner token.
                var token = (JsonWebToken) result.SecurityToken;
                if (token.InnerToken != null)
                {
                    token = token.InnerToken;
                }

                // Attach the principal extracted from the token to the parent event context.
                context.Principal = new ClaimsPrincipal(result.ClaimsIdentity);

                // Store the token type as a special private claim.
                context.Principal.SetClaim(Claims.Private.TokenUsage, token.Typ switch
                {
                    JsonWebTokenTypes.AccessToken   => TokenUsages.AccessToken,
                    JsonWebTokenTypes.IdentityToken => TokenUsages.IdToken,

                    JsonWebTokenTypes.Private.AuthorizationCode => TokenUsages.AuthorizationCode,
                    JsonWebTokenTypes.Private.DeviceCode        => TokenUsages.DeviceCode,
                    JsonWebTokenTypes.Private.RefreshToken      => TokenUsages.RefreshToken,
                    JsonWebTokenTypes.Private.UserCode          => TokenUsages.UserCode,

                    _ => throw new InvalidOperationException("The token type is not supported.")
                });

                // Restore the claim destinations from the special oi_cl_dstn claim (represented as a dictionary/JSON object).
                if (token.TryGetPayloadValue(Claims.Private.ClaimDestinations, out ImmutableDictionary<string, string[]> destinations))
                {
                    context.Principal.SetDestinations(destinations);
                }

                context.Logger.LogTrace("The token '{Token}' was successfully validated and the following claims " +
                                        "could be extracted: {Claims}.", context.Token, context.Principal.Claims);

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of restoring the properties associated with a reference token entry.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class RestoreReferenceTokenProperties : IOpenIddictServerHandler<ProcessAuthenticationContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public RestoreReferenceTokenProperties() => throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                .ToString());

            public RestoreReferenceTokenProperties([NotNull] IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .UseScopedHandler<RestoreReferenceTokenProperties>()
                    .SetOrder(ValidateIdentityModelToken.Descriptor.Order + 1_000)
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
                    .SetClaim(Claims.Private.TokenUsage, await _tokenManager.GetTypeAsync(token));
            }
        }

        /// <summary>
        /// Contains the logic responsible of rejecting authentication demands for which no valid principal was resolved.
        /// </summary>
        public class ValidatePrincipal : IOpenIddictServerHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
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
                        error: context.EndpointType switch
                        {
                            OpenIddictServerEndpointType.Token => Errors.InvalidGrant,
                            _                                  => Errors.InvalidToken
                        },
                        description: context.EndpointType switch
                        {
                            OpenIddictServerEndpointType.Authorization => "The specified identity token hint is invalid.",
                            OpenIddictServerEndpointType.Logout        => "The specified identity token hint is invalid.",

                            OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType()
                                => "The specified authorization code is invalid.",
                            OpenIddictServerEndpointType.Token when context.Request.IsDeviceCodeGrantType()
                                => "The specified device code is invalid.",
                            OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                                => "The specified refresh token is invalid.",

                            _ => "The specified token is invalid."
                        });


                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of rejecting authentication demands that
        /// use a token whose entry is no longer valid (e.g was revoked).
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ValidateTokenEntry : IOpenIddictServerHandler<ProcessAuthenticationContext>
        {
            private readonly IOpenIddictAuthorizationManager _authorizationManager;
            private readonly IOpenIddictTokenManager _tokenManager;

            public ValidateTokenEntry() => throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                .ToString());

            public ValidateTokenEntry(
                [NotNull] IOpenIddictAuthorizationManager authorizationManager,
                [NotNull] IOpenIddictTokenManager tokenManager)
            {
                _authorizationManager = authorizationManager;
                _tokenManager = tokenManager;
            }

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .UseScopedHandler<ValidateTokenEntry>()
                    .SetOrder(ValidatePrincipal.Descriptor.Order + 1_000)
                    .Build();

            public async ValueTask HandleAsync([NotNull] ProcessAuthenticationContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Extract the token identifier from the authentication principal.
                // If no token identifier can be found, this indicates that the token
                // has no backing database entry (e.g an access token or an identity token).
                var identifier = context.Principal.GetInternalTokenId();
                if (string.IsNullOrEmpty(identifier))
                {
                    return;
                }

                // If the token entry cannot be found, return a generic error.
                var token = await _tokenManager.FindByIdAsync(identifier);
                if (token == null)
                {
                    context.Reject(
                        error: context.EndpointType switch
                        {
                            OpenIddictServerEndpointType.Token => Errors.InvalidGrant,
                            _                                  => Errors.InvalidToken
                        },
                        description: context.EndpointType switch
                        {
                            OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType()
                                => "The specified authorization code is invalid.",
                            OpenIddictServerEndpointType.Token when context.Request.IsDeviceCodeGrantType()
                                => "The specified device code is invalid.",
                            OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                                => "The specified refresh token is invalid.",

                            _ => "The specified token is invalid."
                        });

                    return;
                }

                if (context.EndpointType == OpenIddictServerEndpointType.Token &&
                   (context.Request.IsAuthorizationCodeGrantType() ||
                    context.Request.IsDeviceCodeGrantType() ||
                    context.Request.IsRefreshTokenGrantType()))
                {
                    // If the authorization code/device code/refresh token is already marked as redeemed, this may indicate
                    // that it was compromised. In this case, revoke the authorization and all the associated tokens. 
                    // See https://tools.ietf.org/html/rfc6749#section-10.5 for more information.
                    if (await _tokenManager.HasStatusAsync(token, Statuses.Redeemed))
                    {
                        // First, mark the redeemed token submitted by the client as revoked.
                        await _tokenManager.TryRevokeAsync(token);

                        // Then, try to revoke the authorization and the associated token entries.
                        await TryRevokeAuthorizationChainAsync(context.Principal.GetInternalAuthorizationId());

                        context.Logger.LogError("The token '{Identifier}' has already been redeemed.", identifier);

                        context.Reject(
                            error: context.EndpointType switch
                            {
                                OpenIddictServerEndpointType.Token => Errors.InvalidGrant,
                                _                                  => Errors.InvalidToken
                            },
                            description: context.EndpointType switch
                            {
                                OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType()
                                    => "The specified authorization code has already been redeemed.",
                                OpenIddictServerEndpointType.Token when context.Request.IsDeviceCodeGrantType()
                                    => "The specified device code has already been redeemed.",
                                OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                                    => "The specified refresh token has already been redeemed.",

                                _ => "The specified token has already been redeemed."
                            });

                        return;
                    }

                    if (context.Request.IsDeviceCodeGrantType())
                    {
                        // If the device code is not marked as valid yet, return an authorization_pending error.
                        if (await _tokenManager.HasStatusAsync(token, Statuses.Inactive))
                        {
                            context.Logger.LogError("The token '{Identifier}' is not active yet.", identifier);

                            context.Reject(
                                error: Errors.AuthorizationPending,
                                description: "The authorization has not been granted yet by the end user.");

                            return;
                        }

                        // If the device code is marked as rejected, return an authorization_pending error.
                        if (await _tokenManager.HasStatusAsync(token, Statuses.Rejected))
                        {
                            context.Logger.LogError("The token '{Identifier}' was marked as rejected.", identifier);

                            context.Reject(
                                error: Errors.AccessDenied,
                                description: "The authorization demand has been rejected by the end user.");

                            return;
                        }
                    }
                }

                if (!await _tokenManager.HasStatusAsync(token, Statuses.Valid))
                {
                    context.Logger.LogError("The token '{Identifier}' was no longer valid.", identifier);

                    context.Reject(
                        error: context.EndpointType switch
                        {
                            OpenIddictServerEndpointType.Token => Errors.InvalidGrant,
                            _                                  => Errors.InvalidToken
                        },
                        description: context.EndpointType switch
                        {
                            OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType()
                                => "The specified authorization code is no longer valid.",
                            OpenIddictServerEndpointType.Token when context.Request.IsDeviceCodeGrantType()
                                => "The specified device code is no longer valid.",
                            OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                                => "The specified refresh token is no longer valid.",

                            _ => "The specified token is no longer valid."
                        });

                    return;
                }

                // Restore the creation/expiration dates/identifiers from the token entry metadata.
                context.Principal.SetCreationDate(await _tokenManager.GetCreationDateAsync(token))
                                 .SetExpirationDate(await _tokenManager.GetExpirationDateAsync(token))
                                 .SetInternalAuthorizationId(await _tokenManager.GetAuthorizationIdAsync(token))
                                 .SetInternalTokenId(await _tokenManager.GetIdAsync(token))
                                 .SetClaim(Claims.Private.TokenUsage, await _tokenManager.GetTypeAsync(token));

                async ValueTask TryRevokeAuthorizationChainAsync(string identifier)
                {
                    if (context.Options.DisableAuthorizationStorage || string.IsNullOrEmpty(identifier))
                    {
                        return;
                    }

                    // Then, try to revoke the authorization and the associated token entries.

                    var authorization = await _authorizationManager.FindByIdAsync(identifier);
                    if (authorization != null)
                    {
                        await _authorizationManager.TryRevokeAsync(authorization);
                    }

                    await foreach (var token in _tokenManager.FindByAuthorizationIdAsync(identifier))
                    {
                        // Don't change the status of the token used in the token request.
                        if (string.Equals(context.Principal.GetInternalTokenId(),
                            await _tokenManager.GetIdAsync(token), StringComparison.Ordinal))
                        {
                            continue;
                        }

                        await _tokenManager.TryRevokeAsync(token);
                    }
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of authentication demands a token whose
        /// associated authorization entry is no longer valid (e.g was revoked).
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ValidateAuthorizationEntry : IOpenIddictServerHandler<ProcessAuthenticationContext>
        {
            private readonly IOpenIddictAuthorizationManager _authorizationManager;

            public ValidateAuthorizationEntry() => throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                .ToString());

            public ValidateAuthorizationEntry([NotNull] IOpenIddictAuthorizationManager authorizationManager)
                => _authorizationManager = authorizationManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireAuthorizationStorageEnabled>()
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
                        error: context.EndpointType switch
                        {
                            OpenIddictServerEndpointType.Token => Errors.InvalidGrant,
                            _                                  => Errors.InvalidToken
                        },
                        description: context.EndpointType switch
                        {
                            OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType()
                                => "The authorization associated with the authorization code is no longer valid.",
                            OpenIddictServerEndpointType.Token when context.Request.IsDeviceCodeGrantType()
                                => "The authorization associated with the device code is no longer valid.",
                            OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                                => "The authorization associated with the refresh token is no longer valid.",

                            _ => "The authorization associated with the token is no longer valid."
                        });

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of rejecting authentication demands that use an expired token.
        /// </summary>
        public class ValidateExpirationDate : IOpenIddictServerHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .UseSingletonHandler<ValidateExpirationDate>()
                    .SetOrder(ValidateTokenEntry.Descriptor.Order + 1_000)
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

                // Don't validate the lifetime of id_tokens used as id_token_hints.
                switch (context.EndpointType)
                {
                    case OpenIddictServerEndpointType.Authorization:
                    case OpenIddictServerEndpointType.Logout:
                        return default;
                }

                var date = context.Principal.GetExpirationDate();
                if (date.HasValue && date.Value < DateTimeOffset.UtcNow)
                {
                    context.Reject(
                        error: context.EndpointType switch
                        {
                            OpenIddictServerEndpointType.Token => Errors.InvalidGrant,
                            _                                  => Errors.InvalidToken
                        },
                        description: context.EndpointType switch
                        {
                            OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType()
                                => "The specified authorization code is no longer valid.",
                            OpenIddictServerEndpointType.Token when context.Request.IsDeviceCodeGrantType()
                                => "The specified device code is no longer valid.",
                            OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                                => "The specified refresh token is no longer valid.",

                            _ => "The specified token is no longer valid."
                        });

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of rejecting challenge demands made from unsupported endpoints.
        /// </summary>
        public class ValidateChallengeDemand : IOpenIddictServerHandler<ProcessChallengeContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                    .UseSingletonHandler<ValidateChallengeDemand>()
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

                switch (context.EndpointType)
                {
                    case OpenIddictServerEndpointType.Authorization:
                    case OpenIddictServerEndpointType.Token:
                    case OpenIddictServerEndpointType.Userinfo:
                    case OpenIddictServerEndpointType.Verification:
                        return default;

                    default: throw new InvalidOperationException("No challenge can be triggered from this endpoint.");
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of ensuring that the challenge response contains an appropriate error.
        /// </summary>
        public class AttachDefaultChallengeError : IOpenIddictServerHandler<ProcessChallengeContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                    .UseSingletonHandler<AttachDefaultChallengeError>()
                    .SetOrder(ValidateChallengeDemand.Descriptor.Order + 1_000)
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
                    context.Response.Error = context.EndpointType switch
                    {
                        OpenIddictServerEndpointType.Authorization => Errors.AccessDenied,
                        OpenIddictServerEndpointType.Token         => Errors.InvalidGrant,
                        OpenIddictServerEndpointType.Userinfo      => Errors.InvalidToken,
                        OpenIddictServerEndpointType.Verification  => Errors.AccessDenied,

                        _ => throw new InvalidOperationException("An OpenID Connect response cannot be returned from this endpoint.")
                    };
                }

                if (string.IsNullOrEmpty(context.Response.ErrorDescription))
                {
                    context.Response.ErrorDescription = context.EndpointType switch
                    {
                        OpenIddictServerEndpointType.Authorization => "The authorization was denied by the resource owner.",
                        OpenIddictServerEndpointType.Token         => "The token request was rejected by the authorization server.",
                        OpenIddictServerEndpointType.Userinfo      => "The access token is not valid or cannot be used to retrieve user information.",
                        OpenIddictServerEndpointType.Verification  => "The authorization was denied by the resource owner.",

                        _ => throw new InvalidOperationException("An OpenID Connect response cannot be returned from this endpoint.")
                    };
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of rejecting the device code entry associated with the user code.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class RejectDeviceCodeEntry : IOpenIddictServerHandler<ProcessChallengeContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public RejectDeviceCodeEntry() => throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                .ToString());

            public RejectDeviceCodeEntry([NotNull] IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .UseScopedHandler<RejectDeviceCodeEntry>()
                    .SetOrder(AttachDefaultChallengeError.Descriptor.Order + 1_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async ValueTask HandleAsync([NotNull] ProcessChallengeContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (context.EndpointType != OpenIddictServerEndpointType.Verification)
                {
                    return;
                }

                var notification = context.Transaction.GetProperty<ProcessAuthenticationContext>(
                    typeof(ProcessAuthenticationContext).FullName) ??
                    throw new InvalidOperationException("The authentication context cannot be found.");

                // Extract the device code identifier from the authentication principal.
                var identifier = notification.Principal.GetClaim(Claims.Private.DeviceCodeId);
                if (string.IsNullOrEmpty(identifier))
                {
                    throw new InvalidOperationException("The device code identifier cannot be extracted from the principal.");
                }

                var token = await _tokenManager.FindByIdAsync(identifier);
                if (token != null)
                {
                    await _tokenManager.TryRejectAsync(token);
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of rejecting the user code entry, if applicable.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class RejectUserCodeEntry : IOpenIddictServerHandler<ProcessChallengeContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public RejectUserCodeEntry() => throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                .ToString());

            public RejectUserCodeEntry([NotNull] IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .UseScopedHandler<RejectUserCodeEntry>()
                    .SetOrder(RejectDeviceCodeEntry.Descriptor.Order + 1_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async ValueTask HandleAsync([NotNull] ProcessChallengeContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (context.EndpointType != OpenIddictServerEndpointType.Verification)
                {
                    return;
                }

                var notification = context.Transaction.GetProperty<ProcessAuthenticationContext>(
                    typeof(ProcessAuthenticationContext).FullName) ??
                    throw new InvalidOperationException("The authentication context cannot be found.");

                // Extract the device code identifier from the authentication principal.
                var identifier = notification.Principal.GetInternalTokenId();
                if (string.IsNullOrEmpty(identifier))
                {
                    throw new InvalidOperationException("The token identifier cannot be extracted from the principal.");
                }

                var token = await _tokenManager.FindByIdAsync(identifier);
                if (token != null)
                {
                    await _tokenManager.TryRejectAsync(token);
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of ensuring that the sign-in demand
        /// is compatible with the type of the endpoint that handled the request.
        /// </summary>
        public class ValidateSigninDemand : IOpenIddictServerHandler<ProcessSigninContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .UseSingletonHandler<ValidateSigninDemand>()
                    .SetOrder(int.MinValue + 100_000)
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

                switch (context.EndpointType)
                {
                    case OpenIddictServerEndpointType.Authorization:
                    case OpenIddictServerEndpointType.Device:
                    case OpenIddictServerEndpointType.Token:
                    case OpenIddictServerEndpointType.Verification:
                        break;

                    default: throw new InvalidOperationException("An OpenID Connect response cannot be returned from this endpoint.");
                }

                if (context.Principal.Identity == null)
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .AppendLine("The specified principal doesn't contain any claims-based identity.")
                        .Append("Make sure that both 'ClaimsPrincipal.Identity' is not null.")
                        .ToString());
                }

                // Note: sign-in operations triggered from the device endpoint can't be associated to specific users
                // as users' identity is not known until they reach the verification endpoint and validate the user code.
                // As such, the principal used in this case cannot contain an authenticated identity or a subject claim.
                if (context.EndpointType == OpenIddictServerEndpointType.Device)
                {
                    if (context.Principal.Identity.IsAuthenticated)
                    {
                        throw new InvalidOperationException(new StringBuilder()
                            .Append("The specified principal contains an authenticated identity, which is not valid ")
                            .AppendLine("when the sign-in operation is triggered from the device authorization endpoint.")
                            .Append("Make sure that 'ClaimsPrincipal.Identity.AuthenticationType' is null ")
                            .Append("and that 'ClaimsPrincipal.Identity.IsAuthenticated' returns 'false'.")
                            .ToString());
                    }

                    if (!string.IsNullOrEmpty(context.Principal.GetClaim(Claims.Subject)))
                    {
                        throw new InvalidOperationException(new StringBuilder()
                            .Append("The specified principal contains a subject claim, which is not valid ")
                            .Append("when the sign-in operation is triggered from the device authorization endpoint.")
                            .ToString());
                    }

                    return default;
                }

                if (!context.Principal.Identity.IsAuthenticated)
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .AppendLine("The specified principal doesn't contain a valid/authenticated identity.")
                        .Append("Make sure that 'ClaimsPrincipal.Identity.AuthenticationType' is not null ")
                        .Append("and that 'ClaimsPrincipal.Identity.IsAuthenticated' returns 'true'.")
                        .ToString());
                }

                if (string.IsNullOrEmpty(context.Principal.GetClaim(Claims.Subject)))
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .AppendLine("The specified principal was rejected because the mandatory subject claim was missing.")
                        .ToString());
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of re-attaching internal claims to the authentication principal.
        /// </summary>
        public class RestoreInternalClaims : IOpenIddictServerHandler<ProcessSigninContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .UseSingletonHandler<RestoreInternalClaims>()
                    .SetOrder(ValidateSigninDemand.Descriptor.Order + 1_000)
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

                switch (context.EndpointType)
                {
                    case OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType():
                    case OpenIddictServerEndpointType.Token when context.Request.IsDeviceCodeGrantType():
                    case OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType():
                    case OpenIddictServerEndpointType.Verification:
                        break;

                    default:
                        return default;
                }

                var identity = (ClaimsIdentity) context.Principal.Identity;

                var notification = context.Transaction.GetProperty<ProcessAuthenticationContext>(
                    typeof(ProcessAuthenticationContext).FullName) ??
                    throw new InvalidOperationException("The authentication context cannot be found.");

                // Restore the internal claims resolved from the authorization code/refresh token.
                foreach (var claims in notification.Principal.Claims
                    .Where(claim => claim.Type.StartsWith(Claims.Prefixes.Private))
                    .GroupBy(claim => claim.Type))
                {
                    // If the specified principal already contains one claim of the iterated type, ignore them.
                    if (context.Principal.Claims.Any(claim => claim.Type == claims.Key))
                    {
                        continue;
                    }

                    // When the request is a verification request, don't flow the copy from the user code.
                    if (context.EndpointType == OpenIddictServerEndpointType.Verification &&
                        string.Equals(claims.Key, Claims.Private.Scopes, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    identity.AddClaims(claims);
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of attaching default scopes to the authentication principal.
        /// </summary>
        public class AttachDefaultScopes : IOpenIddictServerHandler<ProcessSigninContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .UseSingletonHandler<AttachDefaultScopes>()
                    .SetOrder(RestoreInternalClaims.Descriptor.Order + 1_000)
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

                // Always include the "openid" scope when the developer doesn't explicitly call SetScopes.
                // Note: the application is allowed to specify a different "scopes": in this case,
                // don't replace the "scopes" property stored in the authentication ticket.
                if (!context.Principal.HasScope() && context.Request.HasScope(Scopes.OpenId))
                {
                    context.Principal.SetScopes(Scopes.OpenId);
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of attaching default presenters to the authentication principal.
        /// </summary>
        public class AttachDefaultPresenters : IOpenIddictServerHandler<ProcessSigninContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .UseSingletonHandler<AttachDefaultPresenters>()
                    .SetOrder(AttachDefaultScopes.Descriptor.Order + 1_000)
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

                // Add the validated client_id to the list of authorized presenters,
                // unless the presenters were explicitly set by the developer.
                if (!context.Principal.HasPresenter() && !string.IsNullOrEmpty(context.ClientId))
                {
                    context.Principal.SetPresenters(context.ClientId);
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of inferring resources from the audience claims if necessary.
        /// </summary>
        public class InferResources : IOpenIddictServerHandler<ProcessSigninContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .UseSingletonHandler<InferResources>()
                    .SetOrder(AttachDefaultPresenters.Descriptor.Order + 1_000)
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

                // When a "resources" property cannot be found in the ticket, infer it from the "audiences" property.
                if (context.Principal.HasAudience() && !context.Principal.HasResource())
                {
                    context.Principal.SetResources(context.Principal.GetAudiences());
                }

                // Reset the audiences collection, as it's later set, based on the token type.
                context.Principal.SetAudiences(Array.Empty<string>());

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of selecting the token types returned to the client application.
        /// </summary>
        public class EvaluateReturnedTokens : IOpenIddictServerHandler<ProcessSigninContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .UseSingletonHandler<EvaluateReturnedTokens>()
                    .SetOrder(InferResources.Descriptor.Order + 1_000)
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

                context.IncludeAccessToken = context.EndpointType switch
                {
                    // For authorization requests, return an access token if a response type containing token was specified.
                    OpenIddictServerEndpointType.Authorization => context.Request.HasResponseType(ResponseTypes.Token),

                    // For token requests, always return an access token.
                    OpenIddictServerEndpointType.Token => true,

                    _ => false
                };

                context.IncludeAuthorizationCode = context.EndpointType switch
                {
                    // For authorization requests, return an authorization code if a response type containing code was specified.
                    OpenIddictServerEndpointType.Authorization => context.Request.HasResponseType(ResponseTypes.Code),

                    _ => false
                };

                context.IncludeDeviceCode = context.EndpointType switch
                {
                    // For device requests, always return a device code.
                    OpenIddictServerEndpointType.Device => true,

                    // Note: a device code is not directly returned by the verification endpoint (that generally
                    // returns an empty response or redirects the user agent to another page), but a device code
                    // must be generated to replace the payload of the device code initially returned to the client.
                    // In this case, the new device code is not returned as part of the response but persisted in the DB.
                    OpenIddictServerEndpointType.Verification => true,

                    _ => false
                };

                context.IncludeRefreshToken = context.EndpointType switch
                {
                    // For token requests, never return a refresh token if the offline_access scope was not granted.
                    OpenIddictServerEndpointType.Token when !context.Principal.HasScope(Scopes.OfflineAccess) => false,

                    // For grant_type=refresh_token token requests, only return a refresh token if rolling tokens are enabled.
                    OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType() => context.Options.UseRollingTokens,

                    // For token requests that don't meet the previous criteria, allow a refresh token to be returned.
                    OpenIddictServerEndpointType.Token => true,

                    _ => false
                };

                context.IncludeIdentityToken = context.EndpointType switch
                {
                    // For authorization requests, return an identity token if a response type containing code
                    // was specified and if the openid scope was explicitly or implicitly granted.
                    OpenIddictServerEndpointType.Authorization => context.Principal.HasScope(Scopes.OpenId) &&
                                                                  context.Request.HasResponseType(ResponseTypes.IdToken),

                    // For token requests, only return an identity token if the openid scope was granted.
                    OpenIddictServerEndpointType.Token => context.Principal.HasScope(Scopes.OpenId),

                    _ => false
                };

                context.IncludeUserCode = context.EndpointType switch
                {
                    // Only return a user code if the request is a device authorization request.
                    OpenIddictServerEndpointType.Device => true,

                    _ => false
                };

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of creating an ad-hoc authorization, if necessary.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class AttachAuthorization : IOpenIddictServerHandler<ProcessSigninContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;
            private readonly IOpenIddictAuthorizationManager _authorizationManager;

            public AttachAuthorization() => throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                .ToString());

            public AttachAuthorization(
                [NotNull] IOpenIddictApplicationManager applicationManager,
                [NotNull] IOpenIddictAuthorizationManager authorizationManager)
            {
                _applicationManager = applicationManager;
                _authorizationManager = authorizationManager;
            }

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireAuthorizationStorageEnabled>()
                    .UseScopedHandler<AttachAuthorization>()
                    .SetOrder(EvaluateReturnedTokens.Descriptor.Order + 1_000)
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

                // If no authorization code, device code or refresh token is returned, don't create an authorization.
                if (!context.IncludeAuthorizationCode && !context.IncludeDeviceCode && !context.IncludeRefreshToken)
                {
                    return;
                }

                // If an authorization identifier was explicitly specified, don't create an ad-hoc authorization.
                if (!string.IsNullOrEmpty(context.Principal.GetInternalAuthorizationId()))
                {
                    return;
                }

                var descriptor = new OpenIddictAuthorizationDescriptor
                {
                    Principal = context.Principal,
                    Status = Statuses.Valid,
                    Subject = context.Principal.GetClaim(Claims.Subject),
                    Type = AuthorizationTypes.AdHoc
                };

                descriptor.Scopes.UnionWith(context.Principal.GetScopes());

                // If the client application is known, associate it to the authorization.
                if (!string.IsNullOrEmpty(context.Request.ClientId))
                {
                    var application = await _applicationManager.FindByClientIdAsync(context.Request.ClientId);
                    if (application == null)
                    {
                        throw new InvalidOperationException("The application entry cannot be found in the database.");
                    }

                    descriptor.ApplicationId = await _applicationManager.GetIdAsync(application);
                }

                var authorization = await _authorizationManager.CreateAsync(descriptor);
                if (authorization == null)
                {
                    return;
                }

                var identifier = await _authorizationManager.GetIdAsync(authorization);

                if (string.IsNullOrEmpty(context.Request.ClientId))
                {
                    context.Logger.LogInformation("An ad hoc authorization was automatically created and " +
                                                  "associated with an unknown application: {Identifier}.", identifier);
                }

                else
                {
                    context.Logger.LogInformation("An ad hoc authorization was automatically created and " +
                                                  "associated with the '{ClientId}' application: {Identifier}.",
                                                  context.Request.ClientId, identifier);
                }

                // Attach the unique identifier of the ad hoc authorization to the authentication principal
                // so that it is attached to all the derived tokens, allowing batched revocations support.
                context.Principal.SetInternalAuthorizationId(identifier);
            }
        }

        /// <summary>
        /// Contains the logic responsible of preparing and attaching the claims principal
        /// used to generate the access token, if one is going to be returned.
        /// </summary>
        public class PrepareAccessTokenPrincipal : IOpenIddictServerHandler<ProcessSigninContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireAccessTokenIncluded>()
                    .UseSingletonHandler<PrepareAccessTokenPrincipal>()
                    .SetOrder(AttachAuthorization.Descriptor.Order + 1_000)
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

                // Create a new principal containing only the filtered claims.
                // Actors identities are also filtered (delegation scenarios).
                var principal = context.Principal.Clone(claim =>
                {
                    // Never exclude the subject and authorization identifier claims.
                    if (string.Equals(claim.Type, Claims.Subject, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.Private.AuthorizationId, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }

                    // Never include the public or internal token identifiers to ensure the identifiers
                    // that are automatically inherited from the parent token are not reused for the new token.
                    if (string.Equals(claim.Type, Claims.JwtId, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.Private.TokenId, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }

                    // Never include the creation and expiration dates that are automatically
                    // inherited from the parent token are not reused for the new token.
                    if (string.Equals(claim.Type, Claims.ExpiresAt, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.IssuedAt, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.NotBefore, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }

                    // Always exclude private claims, whose values must generally be kept secret.
                    if (claim.Type.StartsWith(Claims.Prefixes.Private, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }

                    // Claims whose destination is not explicitly referenced or doesn't
                    // contain "access_token" are not included in the access token.
                    if (!claim.HasDestination(Destinations.AccessToken))
                    {
                        context.Logger.LogDebug("'{Claim}' was excluded from the access token claims.", claim.Type);

                        return false;
                    }

                    return true;
                });

                // Remove the destinations from the claim properties.
                foreach (var claim in principal.Claims)
                {
                    claim.Properties.Remove(OpenIddictConstants.Properties.Destinations);
                }

                principal.SetClaim(Claims.JwtId, Guid.NewGuid().ToString());
                principal.SetCreationDate(DateTimeOffset.UtcNow);

                var lifetime = context.Principal.GetAccessTokenLifetime() ?? context.Options.AccessTokenLifetime;
                if (lifetime.HasValue)
                {
                    principal.SetExpirationDate(principal.GetCreationDate() + lifetime.Value);
                }

                // Set the public audiences collection using the private resource claims stored in the principal.
                principal.SetAudiences(context.Principal.GetResources());

                // Set the authorized party using the first presenters (typically the client identifier), if available.
                principal.SetClaim(Claims.AuthorizedParty, context.Principal.GetPresenters().FirstOrDefault());

                // Set the public scope claim using the private scope claims from the principal.
                // Note: scopes are deliberately formatted as a single space-separated
                // string to respect the usual representation of the standard scope claim.
                // See https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-02.
                principal.SetClaim(Claims.Scope, string.Join(" ", context.Principal.GetScopes()));

                // When receiving a grant_type=refresh_token request, determine whether the client application
                // requests a limited set of scopes and immediately replace the scopes collection if necessary.
                if (context.EndpointType == OpenIddictServerEndpointType.Token &&
                    context.Request.IsRefreshTokenGrantType() && !string.IsNullOrEmpty(context.Request.Scope))
                {
                    var scopes = context.Request.GetScopes();
                    principal.SetClaim(Claims.Scope, string.Join(" ", scopes.Intersect(context.Principal.GetScopes())));

                    context.Logger.LogDebug("The access token scopes will be limited to the scopes " +
                                            "requested by the client application: {Scopes}.", scopes);
                }

                context.AccessTokenPrincipal = principal;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of preparing and attaching the claims principal
        /// used to generate the authorization code, if one is going to be returned.
        /// </summary>
        public class PrepareAuthorizationCodePrincipal : IOpenIddictServerHandler<ProcessSigninContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireAuthorizationCodeIncluded>()
                    .UseSingletonHandler<PrepareAuthorizationCodePrincipal>()
                    .SetOrder(PrepareAccessTokenPrincipal.Descriptor.Order + 1_000)
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

                // Create a new principal containing only the filtered claims.
                // Actors identities are also filtered (delegation scenarios).
                var principal = context.Principal.Clone(claim =>
                {
                    // Never include the public or internal token identifiers to ensure the identifiers
                    // that are automatically inherited from the parent token are not reused for the new token.
                    if (string.Equals(claim.Type, Claims.JwtId, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.Private.TokenId, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }

                    // Never include the creation and expiration dates that are automatically
                    // inherited from the parent token are not reused for the new token.
                    if (string.Equals(claim.Type, Claims.ExpiresAt, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.IssuedAt, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.NotBefore, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }

                    // Other claims are always included in the authorization code, even private claims.
                    return true;
                });

                principal.SetClaim(Claims.JwtId, Guid.NewGuid().ToString());
                principal.SetCreationDate(DateTimeOffset.UtcNow);

                var lifetime = context.Principal.GetAuthorizationCodeLifetime() ?? context.Options.AuthorizationCodeLifetime;
                if (lifetime.HasValue)
                {
                    principal.SetExpirationDate(principal.GetCreationDate() + lifetime.Value);
                }

                // Attach the redirect_uri to allow for later comparison when
                // receiving a grant_type=authorization_code token request.
                principal.SetClaim(Claims.Private.RedirectUri, context.Request.RedirectUri);

                // Attach the code challenge and the code challenge methods to allow the ValidateCodeVerifier
                // handler to validate the code verifier sent by the client as part of the token request.
                if (!string.IsNullOrEmpty(context.Request.CodeChallenge))
                {
                    principal.SetClaim(Claims.Private.CodeChallenge, context.Request.CodeChallenge);

                    // Default to S256 if no explicit code challenge method was specified.
                    principal.SetClaim(Claims.Private.CodeChallengeMethod,
                        !string.IsNullOrEmpty(context.Request.CodeChallengeMethod) ?
                        context.Request.CodeChallengeMethod : CodeChallengeMethods.Sha256);
                }

                // Attach the nonce so that it can be later returned by
                // the token endpoint as part of the JWT identity token.
                principal.SetClaim(Claims.Private.Nonce, context.Request.Nonce);

                context.AuthorizationCodePrincipal = principal;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of preparing and attaching the claims principal
        /// used to generate the device code, if one is going to be returned.
        /// </summary>
        public class PrepareDeviceCodePrincipal : IOpenIddictServerHandler<ProcessSigninContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .UseSingletonHandler<PrepareDeviceCodePrincipal>()
                    .SetOrder(PrepareAuthorizationCodePrincipal.Descriptor.Order + 1_000)
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

                // Note: a device code principal is produced when a device code is included in the response or when a
                // device code entry is replaced when processing a sign-in response sent to the verification endpoint.
                if (context.EndpointType != OpenIddictServerEndpointType.Verification && !context.IncludeDeviceCode)
                {
                    return default;
                }

                // Create a new principal containing only the filtered claims.
                // Actors identities are also filtered (delegation scenarios).
                var principal = context.Principal.Clone(claim =>
                {
                    // Never include the public or internal token identifiers to ensure the identifiers
                    // that are automatically inherited from the parent token are not reused for the new token.
                    if (string.Equals(claim.Type, Claims.JwtId, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.Private.TokenId, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }

                    // Never include the creation and expiration dates that are automatically
                    // inherited from the parent token are not reused for the new token.
                    if (string.Equals(claim.Type, Claims.ExpiresAt, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.IssuedAt, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.NotBefore, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }

                    // Other claims are always included in the device code, even private claims.
                    return true;
                });

                principal.SetClaim(Claims.JwtId, Guid.NewGuid().ToString());
                principal.SetCreationDate(DateTimeOffset.UtcNow);

                var lifetime = context.Principal.GetDeviceCodeLifetime() ?? context.Options.DeviceCodeLifetime;
                if (lifetime.HasValue)
                {
                    principal.SetExpirationDate(principal.GetCreationDate() + lifetime.Value);
                }

                context.DeviceCodePrincipal = principal;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of preparing and attaching the claims principal
        /// used to generate the refresh token, if one is going to be returned.
        /// </summary>
        public class PrepareRefreshTokenPrincipal : IOpenIddictServerHandler<ProcessSigninContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireRefreshTokenIncluded>()
                    .UseSingletonHandler<PrepareRefreshTokenPrincipal>()
                    .SetOrder(PrepareDeviceCodePrincipal.Descriptor.Order + 1_000)
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

                // Create a new principal containing only the filtered claims.
                // Actors identities are also filtered (delegation scenarios).
                var principal = context.Principal.Clone(claim =>
                {
                    // Never include the public or internal token identifiers to ensure the identifiers
                    // that are automatically inherited from the parent token are not reused for the new token.
                    if (string.Equals(claim.Type, Claims.JwtId, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.Private.TokenId, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }

                    // Never include the creation and expiration dates that are automatically
                    // inherited from the parent token are not reused for the new token.
                    if (string.Equals(claim.Type, Claims.ExpiresAt, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.IssuedAt, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.NotBefore, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }

                    // Other claims are always included in the refresh token, even private claims.
                    return true;
                });

                principal.SetClaim(Claims.JwtId, Guid.NewGuid().ToString());
                principal.SetCreationDate(DateTimeOffset.UtcNow);

                // When sliding expiration is disabled, the expiration date of generated refresh tokens is fixed
                // and must exactly match the expiration date of the refresh token used in the token request.
                if (context.EndpointType == OpenIddictServerEndpointType.Token &&
                    context.Request.IsRefreshTokenGrantType() && !context.Options.UseSlidingExpiration)
                {
                    var notification = context.Transaction.GetProperty<ProcessAuthenticationContext>(
                        typeof(ProcessAuthenticationContext).FullName) ??
                        throw new InvalidOperationException("The authentication context cannot be found.");

                    principal.SetExpirationDate(notification.Principal.GetExpirationDate());
                }

                else
                {
                    var lifetime = context.Principal.GetRefreshTokenLifetime() ?? context.Options.RefreshTokenLifetime;
                    if (lifetime.HasValue)
                    {
                        principal.SetExpirationDate(principal.GetCreationDate() + lifetime.Value);
                    }
                }

                context.RefreshTokenPrincipal = principal;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of preparing and attaching the claims principal
        /// used to generate the identity token, if one is going to be returned.
        /// </summary>
        public class PrepareIdentityTokenPrincipal : IOpenIddictServerHandler<ProcessSigninContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireIdentityTokenIncluded>()
                    .UseSingletonHandler<PrepareIdentityTokenPrincipal>()
                    .SetOrder(PrepareRefreshTokenPrincipal.Descriptor.Order + 1_000)
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

                // Replace the principal by a new one containing only the filtered claims.
                // Actors identities are also filtered (delegation scenarios).
                var principal = context.Principal.Clone(claim =>
                {
                    // Never exclude the subject claim.
                    if (string.Equals(claim.Type, Claims.Subject, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }

                    // Never include the public or internal token identifiers to ensure the identifiers
                    // that are automatically inherited from the parent token are not reused for the new token.
                    if (string.Equals(claim.Type, Claims.JwtId, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.Private.TokenId, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }

                    // Never include the creation and expiration dates that are automatically
                    // inherited from the parent token are not reused for the new token.
                    if (string.Equals(claim.Type, Claims.ExpiresAt, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.IssuedAt, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.NotBefore, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }

                    // Always exclude private claims by default, whose values must generally be kept secret.
                    if (claim.Type.StartsWith(Claims.Prefixes.Private, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }

                    // Claims whose destination is not explicitly referenced or doesn't
                    // contain "id_token" are not included in the identity token.
                    if (!claim.HasDestination(Destinations.IdentityToken))
                    {
                        context.Logger.LogDebug("'{Claim}' was excluded from the identity token claims.", claim.Type);

                        return false;
                    }

                    return true;
                });

                // Remove the destinations from the claim properties.
                foreach (var claim in principal.Claims)
                {
                    claim.Properties.Remove(OpenIddictConstants.Properties.Destinations);
                }

                principal.SetClaim(Claims.JwtId, Guid.NewGuid().ToString());
                principal.SetCreationDate(DateTimeOffset.UtcNow);

                var lifetime = context.Principal.GetIdentityTokenLifetime() ?? context.Options.IdentityTokenLifetime;
                if (lifetime.HasValue)
                {
                    principal.SetExpirationDate(principal.GetCreationDate() + lifetime.Value);
                }

                if (!string.IsNullOrEmpty(context.ClientId))
                {
                    principal.SetAudiences(context.ClientId);
                }

                // If a nonce was present in the authorization request, it MUST be included in the id_token generated
                // by the token endpoint. For that, OpenIddict simply flows the nonce as an authorization code claim.
                // See http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation for more information.
                principal.SetClaim(Claims.Nonce, context.EndpointType switch
                {
                    OpenIddictServerEndpointType.Authorization => context.Request.Nonce,
                    OpenIddictServerEndpointType.Token         => context.Principal.GetClaim(Claims.Private.Nonce),
                    _ => null
                });

                context.IdentityTokenPrincipal = principal;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of preparing and attaching the claims principal
        /// used to generate the user code, if one is going to be returned.
        /// </summary>
        public class PrepareUserCodePrincipal : IOpenIddictServerHandler<ProcessSigninContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireUserCodeIncluded>()
                    .UseSingletonHandler<PrepareUserCodePrincipal>()
                    .SetOrder(PrepareIdentityTokenPrincipal.Descriptor.Order + 1_000)
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

                // Create a new principal containing only the filtered claims.
                // Actors identities are also filtered (delegation scenarios).
                var principal = context.Principal.Clone(claim =>
                {
                    // Never include the public or internal token identifiers to ensure the identifiers
                    // that are automatically inherited from the parent token are not reused for the new token.
                    if (string.Equals(claim.Type, Claims.JwtId, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.Private.TokenId, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }

                    // Never include the creation and expiration dates that are automatically
                    // inherited from the parent token are not reused for the new token.
                    if (string.Equals(claim.Type, Claims.ExpiresAt, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.IssuedAt, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(claim.Type, Claims.NotBefore, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }

                    // Other claims are always included in the authorization code, even private claims.
                    return true;
                });

                principal.SetClaim(Claims.JwtId, Guid.NewGuid().ToString());
                principal.SetCreationDate(DateTimeOffset.UtcNow);

                var lifetime = context.Principal.GetUserCodeLifetime() ?? context.Options.UserCodeLifetime;
                if (lifetime.HasValue)
                {
                    principal.SetExpirationDate(principal.GetCreationDate() + lifetime.Value);
                }

                // Store the client_id as a public client_id claim.
                principal.SetClaim(Claims.ClientId, context.Request.ClientId);

                context.UserCodePrincipal = principal;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of redeeming the token entry
        /// corresponding to the received authorization code or refresh token.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class RedeemTokenEntry : IOpenIddictServerHandler<ProcessSigninContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public RedeemTokenEntry() => throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                .ToString());

            public RedeemTokenEntry([NotNull] IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .UseScopedHandler<RedeemTokenEntry>()
                    .SetOrder(100_000)
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

                if (context.EndpointType != OpenIddictServerEndpointType.Token)
                {
                    return;
                }

                if (!context.Request.IsAuthorizationCodeGrantType() &&
                    !context.Request.IsDeviceCodeGrantType() &&
                    !context.Request.IsRefreshTokenGrantType())
                {
                    return;
                }

                if (context.Request.IsRefreshTokenGrantType() && !context.Options.UseRollingTokens)
                {
                    return;
                }

                // Extract the token identifier from the authentication principal.
                // If no token identifier can be found, this indicates that the token has no backing database entry.
                var identifier = context.Principal.GetInternalTokenId();
                if (string.IsNullOrEmpty(identifier))
                {
                    return;
                }

                var token = await _tokenManager.FindByIdAsync(identifier);
                if (token == null)
                {
                    throw new InvalidOperationException("The token details cannot be found in the database.");
                }

                // If rolling tokens are enabled or if the request is an authorization_code or device_code request,
                // mark the authorization/device code or the refresh token as redeemed to prevent future reuses.
                // If the operation fails, return an error indicating the code/token is no longer valid.
                // See https://tools.ietf.org/html/rfc6749#section-6 for more information.
                if (!await _tokenManager.TryRedeemAsync(token))
                {
                    context.Reject(
                        error: Errors.InvalidGrant,
                        description:
                            context.Request.IsAuthorizationCodeGrantType() ?
                                "The specified authorization code is no longer valid." :
                            context.Request.IsDeviceCodeGrantType() ?
                                "The specified device code is no longer valid." :
                                "The specified refresh token is no longer valid.");

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of redeeming the device code entry associated with the user code.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class RedeemDeviceCodeEntry : IOpenIddictServerHandler<ProcessSigninContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public RedeemDeviceCodeEntry() => throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                .ToString());

            public RedeemDeviceCodeEntry([NotNull] IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .UseScopedHandler<RedeemDeviceCodeEntry>()
                    .SetOrder(RedeemTokenEntry.Descriptor.Order + 1_000)
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

                if (context.EndpointType != OpenIddictServerEndpointType.Token)
                {
                    return;
                }

                if (!context.Request.IsDeviceCodeGrantType())
                {
                    return;
                }

                // Extract the device code identifier from the authentication principal.
                var identifier = context.Principal.GetClaim(Claims.Private.DeviceCodeId);
                if (string.IsNullOrEmpty(identifier))
                {
                    throw new InvalidOperationException("The device code identifier cannot be extracted from the principal.");
                }

                var token = await _tokenManager.FindByIdAsync(identifier);
                if (token == null || !await _tokenManager.TryRedeemAsync(token))
                {
                    context.Reject(
                        error: Errors.InvalidGrant,
                        description: "The specified device code is no longer valid.");

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of redeeming the user code entry, if applicable.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class RedeemUserCodeEntry : IOpenIddictServerHandler<ProcessSigninContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public RedeemUserCodeEntry() => throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                .ToString());

            public RedeemUserCodeEntry([NotNull] IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .UseScopedHandler<RedeemUserCodeEntry>()
                    .SetOrder(RedeemDeviceCodeEntry.Descriptor.Order + 1_000)
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

                if (context.EndpointType != OpenIddictServerEndpointType.Verification)
                {
                    return;
                }

                // Extract the device code identifier from the authentication principal.
                var identifier = context.Principal.GetInternalTokenId();
                if (string.IsNullOrEmpty(identifier))
                {
                    return;
                }

                var token = await _tokenManager.FindByIdAsync(identifier);
                if (token == null || !await _tokenManager.TryRedeemAsync(token))
                {
                    context.Reject(
                        error: Errors.InvalidGrant,
                        description: "The specified user code is no longer valid.");

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of revoking all the tokens that were previously issued.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class RevokeExistingTokenEntries : IOpenIddictServerHandler<ProcessSigninContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public RevokeExistingTokenEntries() => throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                .ToString());

            public RevokeExistingTokenEntries([NotNull] IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .AddFilter<RequireRollingTokensEnabled>()
                    .UseScopedHandler<RevokeExistingTokenEntries>()
                    .SetOrder(RedeemUserCodeEntry.Descriptor.Order + 1_000)
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

                if (context.EndpointType != OpenIddictServerEndpointType.Token || !context.Request.IsRefreshTokenGrantType())
                {
                    return;
                }

                // When rolling tokens are enabled, try to revoke all the previously issued tokens
                // associated with the authorization if the request is a refresh_token request.
                // If the operation fails, silently ignore the error and keep processing the request:
                // this may indicate that one of the revoked tokens was modified by a concurrent request.

                var identifier = context.Principal.GetInternalAuthorizationId();
                if (string.IsNullOrEmpty(identifier))
                {
                    return;
                }

                await foreach (var token in _tokenManager.FindByAuthorizationIdAsync(identifier))
                {
                    // Don't change the status of the token used in the token request.
                    if (string.Equals(context.Principal.GetInternalTokenId(),
                        await _tokenManager.GetIdAsync(token), StringComparison.Ordinal))
                    {
                        continue;
                    }

                    await _tokenManager.TryRevokeAsync(token);
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of extending the lifetime of the refresh token entry.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ExtendRefreshTokenEntry : IOpenIddictServerHandler<ProcessSigninContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public ExtendRefreshTokenEntry() => throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                .ToString());

            public ExtendRefreshTokenEntry([NotNull] IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .AddFilter<RequireSlidingExpirationEnabled>()
                    .AddFilter<RequireRollingTokensDisabled>()
                    .UseScopedHandler<ExtendRefreshTokenEntry>()
                    .SetOrder(RevokeExistingTokenEntries.Descriptor.Order + 1_000)
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

                if (context.EndpointType != OpenIddictServerEndpointType.Token || !context.Request.IsRefreshTokenGrantType())
                {
                    return;
                }

                // Extract the token identifier from the authentication principal.
                // If no token identifier can be found, this indicates that the token has no backing database entry.
                var identifier = context.Principal.GetInternalTokenId();
                if (string.IsNullOrEmpty(identifier))
                {
                    return;
                }

                var token = await _tokenManager.FindByIdAsync(identifier);
                if (token == null)
                {
                    throw new InvalidOperationException("The token details cannot be found in the database.");
                }

                // Compute the new expiration date of the refresh token and update the token entry.
                var lifetime = context.Principal.GetRefreshTokenLifetime() ?? context.Options.RefreshTokenLifetime;
                if (lifetime.HasValue)
                {
                    await _tokenManager.TryExtendAsync(token, DateTimeOffset.UtcNow + lifetime.Value);
                }

                else
                {
                    await _tokenManager.TryExtendAsync(token, date: null);
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating an access token using IdentityModel.
        /// </summary>
        public class GenerateIdentityModelAccessToken : IOpenIddictServerHandler<ProcessSigninContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireAccessTokenIncluded>()
                    .UseSingletonHandler<GenerateIdentityModelAccessToken>()
                    .SetOrder(ExtendRefreshTokenEntry.Descriptor.Order + 1_000)
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

                var token = context.Options.JsonWebTokenHandler.CreateToken(new SecurityTokenDescriptor
                {
                    AdditionalHeaderClaims = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        [JwtHeaderParameterNames.Typ] = JsonWebTokenTypes.AccessToken
                    },
                    Issuer = context.Issuer?.AbsoluteUri,
                    SigningCredentials = context.Options.SigningCredentials.FirstOrDefault(credentials =>
                        credentials.Key is SymmetricSecurityKey) ?? context.Options.SigningCredentials.First(),
                    Subject = (ClaimsIdentity) context.AccessTokenPrincipal.Identity
                });

                var credentials = context.Options.EncryptionCredentials.FirstOrDefault(
                    credentials => credentials.Key is SymmetricSecurityKey);
                if (credentials != null)
                {
                    token = context.Options.JsonWebTokenHandler.EncryptToken(
                        token, credentials, new Dictionary<string, object>(StringComparer.Ordinal)
                        {
                            [JwtHeaderParameterNames.Typ] = JsonWebTokenTypes.AccessToken
                        });
                }

                context.Response.AccessToken = token;

                context.Logger.LogTrace("The access token '{Identifier}' was successfully created: {Payload}. " +
                                        "The principal used to create the token contained the following claims: {Claims}.",
                                        context.AccessTokenPrincipal.GetClaim(Claims.JwtId),
                                        context.Response.AccessToken, context.AccessTokenPrincipal.Claims);

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of creating a reference access token entry.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class CreateReferenceAccessTokenEntry : IOpenIddictServerHandler<ProcessSigninContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;
            private readonly IOpenIddictTokenManager _tokenManager;

            public CreateReferenceAccessTokenEntry() => throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                .ToString());

            public CreateReferenceAccessTokenEntry(
                [NotNull] IOpenIddictApplicationManager applicationManager,
                [NotNull] IOpenIddictTokenManager tokenManager)
            {
                _applicationManager = applicationManager;
                _tokenManager = tokenManager;
            }

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .AddFilter<RequireReferenceAccessTokensEnabled>()
                    .AddFilter<RequireAccessTokenIncluded>()
                    .UseScopedHandler<CreateReferenceAccessTokenEntry>()
                    .SetOrder(GenerateIdentityModelAccessToken.Descriptor.Order + 1_000)
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

                if (string.IsNullOrEmpty(context.Response.AccessToken))
                {
                    return;
                }

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
                    Payload = context.Response.AccessToken,
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

                context.AccessTokenPrincipal.SetInternalTokenId(await _tokenManager.GetIdAsync(token));
                context.Response.AccessToken = descriptor.ReferenceId;

                context.Logger.LogTrace("The reference token entry for access token '{Identifier}' was successfully " +
                                        "created with the reference identifier '{ReferenceId}'.",
                                        await _tokenManager.GetIdAsync(token), descriptor.ReferenceId);
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating an authorization code using IdentityModel.
        /// </summary>
        public class GenerateIdentityModelAuthorizationCode : IOpenIddictServerHandler<ProcessSigninContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireAuthorizationCodeIncluded>()
                    .UseSingletonHandler<GenerateIdentityModelAuthorizationCode>()
                    .SetOrder(CreateReferenceAccessTokenEntry.Descriptor.Order + 1_000)
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

                var descriptor = new SecurityTokenDescriptor
                {
                    AdditionalHeaderClaims = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        [JwtHeaderParameterNames.Typ] = JsonWebTokenTypes.Private.AuthorizationCode
                    },
                    Issuer = context.Issuer?.AbsoluteUri,
                    SigningCredentials = context.Options.SigningCredentials.FirstOrDefault(credentials =>
                        credentials.Key is SymmetricSecurityKey) ?? context.Options.SigningCredentials.First(),
                    Subject = (ClaimsIdentity) context.AuthorizationCodePrincipal.Identity
                };

                // Attach claims destinations to the JWT claims collection.
                var destinations = context.AuthorizationCodePrincipal.GetDestinations();
                if (destinations.Count != 0)
                {
                    descriptor.Claims = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        [Claims.Private.ClaimDestinations] = destinations
                    };
                }

                // Sign and encrypt the authorization code.
                var token = context.Options.JsonWebTokenHandler.CreateToken(descriptor);
                token = context.Options.JsonWebTokenHandler.EncryptToken(token,
                    context.Options.EncryptionCredentials.First(),
                    new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        [JwtHeaderParameterNames.Typ] = JsonWebTokenTypes.Private.AuthorizationCode
                    });

                context.Response.Code = token;

                context.Logger.LogTrace("The authorization code '{Identifier}' was successfully created: {Payload}. " +
                                        "The principal used to create the token contained the following claims: {Claims}.",
                                        context.AuthorizationCodePrincipal.GetClaim(Claims.JwtId), token,
                                        context.AuthorizationCodePrincipal.Claims);

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of creating a reference authorization code entry.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class CreateReferenceAuthorizationCodeEntry : IOpenIddictServerHandler<ProcessSigninContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;
            private readonly IOpenIddictTokenManager _tokenManager;

            public CreateReferenceAuthorizationCodeEntry() => throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                .ToString());

            public CreateReferenceAuthorizationCodeEntry(
                [NotNull] IOpenIddictApplicationManager applicationManager,
                [NotNull] IOpenIddictTokenManager tokenManager)
            {
                _applicationManager = applicationManager;
                _tokenManager = tokenManager;
            }

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .AddFilter<RequireAuthorizationCodeIncluded>()
                    .UseScopedHandler<CreateReferenceAuthorizationCodeEntry>()
                    .SetOrder(GenerateIdentityModelAuthorizationCode.Descriptor.Order + 1_000)
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

                if (string.IsNullOrEmpty(context.Response.Code))
                {
                    return;
                }

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
                    Payload = context.Response.Code,
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

                context.AuthorizationCodePrincipal.SetInternalTokenId(await _tokenManager.GetIdAsync(token));
                context.Response.Code = descriptor.ReferenceId;

                context.Logger.LogTrace("The reference token entry for authorization code '{Identifier}' was successfully " +
                                        "created with the reference identifier '{ReferenceId}'.",
                                        await _tokenManager.GetIdAsync(token), descriptor.ReferenceId);
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating a device code using IdentityModel.
        /// </summary>
        public class GenerateIdentityModelDeviceCode : IOpenIddictServerHandler<ProcessSigninContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireDeviceCodeIncluded>()
                    .UseSingletonHandler<GenerateIdentityModelDeviceCode>()
                    .SetOrder(CreateReferenceAuthorizationCodeEntry.Descriptor.Order + 1_000)
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

                // If a device code was already attached by another handler, don't overwrite it.
                if (!string.IsNullOrEmpty(context.Response.DeviceCode))
                {
                    return default;
                }

                var descriptor = new SecurityTokenDescriptor
                {
                    AdditionalHeaderClaims = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        [JwtHeaderParameterNames.Typ] = JsonWebTokenTypes.Private.DeviceCode
                    },
                    Issuer = context.Issuer?.AbsoluteUri,
                    SigningCredentials = context.Options.SigningCredentials.FirstOrDefault(credentials =>
                        credentials.Key is SymmetricSecurityKey) ?? context.Options.SigningCredentials.First(),
                    Subject = (ClaimsIdentity) context.DeviceCodePrincipal.Identity
                };

                // Attach claims destinations to the JWT claims collection.
                var destinations = context.DeviceCodePrincipal.GetDestinations();
                if (destinations.Count != 0)
                {
                    descriptor.Claims = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        [Claims.Private.ClaimDestinations] = destinations
                    };
                }

                // Sign and encrypt the device code.
                var token = context.Options.JsonWebTokenHandler.CreateToken(descriptor);
                token = context.Options.JsonWebTokenHandler.EncryptToken(token,
                    context.Options.EncryptionCredentials.First(),
                    new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        [JwtHeaderParameterNames.Typ] = JsonWebTokenTypes.Private.DeviceCode
                    });

                context.Response.DeviceCode = token;

                context.Logger.LogTrace("The device code '{Identifier}' was successfully created: {Payload}. " +
                                        "The principal used to create the token contained the following claims: {Claims}.",
                                        context.DeviceCodePrincipal.GetClaim(Claims.JwtId), token,
                                        context.DeviceCodePrincipal.Claims);

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of creating a reference device code entry.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class CreateReferenceDeviceCodeEntry : IOpenIddictServerHandler<ProcessSigninContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;
            private readonly IOpenIddictTokenManager _tokenManager;

            public CreateReferenceDeviceCodeEntry() => throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                .ToString());

            public CreateReferenceDeviceCodeEntry(
                [NotNull] IOpenIddictApplicationManager applicationManager,
                [NotNull] IOpenIddictTokenManager tokenManager)
            {
                _applicationManager = applicationManager;
                _tokenManager = tokenManager;
            }

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .AddFilter<RequireDeviceCodeIncluded>()
                    .UseScopedHandler<CreateReferenceDeviceCodeEntry>()
                    .SetOrder(GenerateIdentityModelDeviceCode.Descriptor.Order + 1_000)
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

                if (string.IsNullOrEmpty(context.Response.DeviceCode))
                {
                    return;
                }

                if (context.EndpointType == OpenIddictServerEndpointType.Verification)
                {
                    return;
                }

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
                    AuthorizationId = context.DeviceCodePrincipal.GetInternalAuthorizationId(),
                    CreationDate = context.DeviceCodePrincipal.GetCreationDate(),
                    ExpirationDate = context.DeviceCodePrincipal.GetExpirationDate(),
                    Payload = context.Response.DeviceCode,
                    Principal = context.DeviceCodePrincipal,
                    ReferenceId = Base64UrlEncoder.Encode(data),
                    Status = Statuses.Inactive,
                    Subject = null, // Device codes are not bound to a user, which is not known until the user code is populated.
                    Type = TokenUsages.DeviceCode
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

                context.DeviceCodePrincipal.SetInternalTokenId(await _tokenManager.GetIdAsync(token));
                context.Response.DeviceCode = descriptor.ReferenceId;

                context.Logger.LogTrace("The reference token entry for device code '{Identifier}' was successfully " +
                                        "created with the reference identifier '{ReferenceId}'.",
                                        await _tokenManager.GetIdAsync(token), descriptor.ReferenceId);
            }
        }

        /// <summary>
        /// Contains the logic responsible of updating the existing reference device code entry.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class UpdateReferenceDeviceCodeEntry : IOpenIddictServerHandler<ProcessSigninContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;
            private readonly IOpenIddictTokenManager _tokenManager;

            public UpdateReferenceDeviceCodeEntry() => throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                .ToString());

            public UpdateReferenceDeviceCodeEntry(
                [NotNull] IOpenIddictApplicationManager applicationManager,
                [NotNull] IOpenIddictTokenManager tokenManager)
            {
                _applicationManager = applicationManager;
                _tokenManager = tokenManager;
            }

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .AddFilter<RequireDeviceCodeIncluded>()
                    .UseScopedHandler<UpdateReferenceDeviceCodeEntry>()
                    .SetOrder(CreateReferenceDeviceCodeEntry.Descriptor.Order + 1_000)
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

                if (string.IsNullOrEmpty(context.Response.DeviceCode))
                {
                    return;
                }

                if (context.EndpointType != OpenIddictServerEndpointType.Verification)
                {
                    return;
                }

                // Extract the token identifier from the authentication principal.
                var identifier = context.Principal.GetClaim(Claims.Private.DeviceCodeId);
                if (string.IsNullOrEmpty(identifier))
                {
                    throw new InvalidOperationException("The device code identifier cannot be extracted from the principal.");
                }

                var token = await _tokenManager.FindByIdAsync(identifier);
                if (token == null)
                {
                    throw new InvalidOperationException("The token details cannot be found in the database.");
                }

                // Replace the device code details by the payload derived from the new device code principal,
                // that includes all the user claims populated by the application after authenticating the user.
                var descriptor = new OpenIddictTokenDescriptor();
                await _tokenManager.PopulateAsync(descriptor, token);

                // Note: the lifetime is deliberately extended to give more time to the client to redeem the code.
                descriptor.ExpirationDate = context.DeviceCodePrincipal.GetExpirationDate();
                descriptor.Payload = context.Response.DeviceCode;
                descriptor.Status = Statuses.Valid;
                descriptor.Subject = context.DeviceCodePrincipal.GetClaim(Claims.Subject);

                await _tokenManager.PopulateAsync(token, descriptor);
                await _tokenManager.UpdateAsync(token);

                // Don't return the prepared device code directly from the verification endpoint.
                context.Response.DeviceCode = null;

                context.Logger.LogTrace("The reference token entry for device code '{Identifier}' was successfully updated'.",
                                        await _tokenManager.GetIdAsync(token));
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating a refresh token using IdentityModel.
        /// </summary>
        public class GenerateIdentityModelRefreshToken : IOpenIddictServerHandler<ProcessSigninContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireRefreshTokenIncluded>()
                    .UseSingletonHandler<GenerateIdentityModelRefreshToken>()
                    .SetOrder(UpdateReferenceDeviceCodeEntry.Descriptor.Order + 1_000)
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

                var descriptor = new SecurityTokenDescriptor
                {
                    AdditionalHeaderClaims = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        [JwtHeaderParameterNames.Typ] = JsonWebTokenTypes.Private.RefreshToken
                    },
                    Issuer = context.Issuer?.AbsoluteUri,
                    SigningCredentials = context.Options.SigningCredentials.FirstOrDefault(credentials =>
                        credentials.Key is SymmetricSecurityKey) ?? context.Options.SigningCredentials.First(),
                    Subject = (ClaimsIdentity) context.RefreshTokenPrincipal.Identity
                };

                // Attach claims destinations to the JWT claims collection.
                var destinations = context.RefreshTokenPrincipal.GetDestinations();
                if (destinations.Count != 0)
                {
                    descriptor.Claims = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        [Claims.Private.ClaimDestinations] = destinations
                    };
                }

                // Sign and encrypt the refresh token.
                var token = context.Options.JsonWebTokenHandler.CreateToken(descriptor);
                token = context.Options.JsonWebTokenHandler.EncryptToken(token,
                    context.Options.EncryptionCredentials.First(),
                    new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        [JwtHeaderParameterNames.Typ] = JsonWebTokenTypes.Private.RefreshToken
                    });

                context.Response.RefreshToken = token;

                context.Logger.LogTrace("The refresh token '{Identifier}' was successfully created: {Payload}. " +
                                        "The principal used to create the token contained the following claims: {Claims}.",
                                        context.RefreshTokenPrincipal.GetClaim(Claims.JwtId), token,
                                        context.RefreshTokenPrincipal.Claims);

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of creating a reference refresh token entry.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class CreateReferenceRefreshTokenEntry : IOpenIddictServerHandler<ProcessSigninContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;
            private readonly IOpenIddictTokenManager _tokenManager;

            public CreateReferenceRefreshTokenEntry() => throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                .ToString());

            public CreateReferenceRefreshTokenEntry(
                [NotNull] IOpenIddictApplicationManager applicationManager,
                [NotNull] IOpenIddictTokenManager tokenManager)
            {
                _applicationManager = applicationManager;
                _tokenManager = tokenManager;
            }

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .AddFilter<RequireRefreshTokenIncluded>()
                    .UseScopedHandler<CreateReferenceRefreshTokenEntry>()
                    .SetOrder(GenerateIdentityModelRefreshToken.Descriptor.Order + 1_000)
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

                if (string.IsNullOrEmpty(context.Response.RefreshToken))
                {
                    return;
                }

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
                    Payload = context.Response.RefreshToken,
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

                context.RefreshTokenPrincipal.SetInternalTokenId(await _tokenManager.GetIdAsync(token));
                context.Response.RefreshToken = descriptor.ReferenceId;

                context.Logger.LogTrace("The reference token entry for refresh token '{Identifier}' was successfully " +
                                        "created with the reference identifier '{ReferenceId}'.",
                                        await _tokenManager.GetIdAsync(token), descriptor.ReferenceId);
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating and attaching the device code identifier to the user code principal.
        /// </summary>
        public class AttachDeviceCodeIdentifier : IOpenIddictServerHandler<ProcessSigninContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireDeviceCodeIncluded>()
                    .AddFilter<RequireUserCodeIncluded>()
                    .UseSingletonHandler<AttachDeviceCodeIdentifier>()
                    .SetOrder(CreateReferenceRefreshTokenEntry.Descriptor.Order + 1_000)
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

                var identifier = context.DeviceCodePrincipal.GetInternalTokenId();
                if (!string.IsNullOrEmpty(identifier))
                {
                    context.UserCodePrincipal.SetClaim(Claims.Private.DeviceCodeId, identifier);
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating a user code using IdentityModel.
        /// </summary>
        public class GenerateIdentityModelUserCode : IOpenIddictServerHandler<ProcessSigninContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireUserCodeIncluded>()
                    .UseSingletonHandler<GenerateIdentityModelUserCode>()
                    .SetOrder(AttachDeviceCodeIdentifier.Descriptor.Order + 1_000)
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

                // If a user code was already attached by another handler, don't overwrite it.
                if (!string.IsNullOrEmpty(context.Response.UserCode))
                {
                    return default;
                }

                // Sign and encrypt the user code.
                var token = context.Options.JsonWebTokenHandler.CreateToken(new SecurityTokenDescriptor
                {
                    AdditionalHeaderClaims = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        [JwtHeaderParameterNames.Typ] = JsonWebTokenTypes.Private.UserCode
                    },
                    Issuer = context.Issuer?.AbsoluteUri,
                    SigningCredentials = context.Options.SigningCredentials.FirstOrDefault(credentials =>
                        credentials.Key is SymmetricSecurityKey) ?? context.Options.SigningCredentials.First(),
                    Subject = (ClaimsIdentity) context.UserCodePrincipal.Identity
                });

                token = context.Options.JsonWebTokenHandler.EncryptToken(token,
                    context.Options.EncryptionCredentials.First(),
                    new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        [JwtHeaderParameterNames.Typ] = JsonWebTokenTypes.Private.UserCode
                    });

                context.Response.UserCode = token;

                context.Logger.LogTrace("The user code '{Identifier}' was successfully created: {Payload}. " +
                                        "The principal used to create the token contained the following claims: {Claims}.",
                                        context.UserCodePrincipal.GetClaim(Claims.JwtId), token,
                                        context.UserCodePrincipal.Claims);

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of creating a reference user code entry.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class CreateReferenceUserCodeEntry : IOpenIddictServerHandler<ProcessSigninContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;
            private readonly IOpenIddictTokenManager _tokenManager;

            public CreateReferenceUserCodeEntry() => throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                .ToString());

            public CreateReferenceUserCodeEntry(
                [NotNull] IOpenIddictApplicationManager applicationManager,
                [NotNull] IOpenIddictTokenManager tokenManager)
            {
                _applicationManager = applicationManager;
                _tokenManager = tokenManager;
            }

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .AddFilter<RequireUserCodeIncluded>()
                    .UseScopedHandler<CreateReferenceUserCodeEntry>()
                    .SetOrder(GenerateIdentityModelUserCode.Descriptor.Order + 1_000)
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

                if (string.IsNullOrEmpty(context.Response.UserCode))
                {
                    return;
                }

                // Note: unlike other reference tokens, user codes are meant to be used by humans,
                // who may have to enter it in a web form. To ensure it remains easy enough to type
                // even by users with non-Latin keyboards, user codes generated by OpenIddict are
                // only compound of 12 digits, generated using a crypto-secure random number generator.
                // In this case, the resulting user code is estimated to have at most ~40 bits of entropy.

                var data = new byte[12];
#if SUPPORTS_STATIC_RANDOM_NUMBER_GENERATOR_METHODS
                RandomNumberGenerator.Fill(data);
#else
                using var generator = RandomNumberGenerator.Create();
                generator.GetBytes(data);
#endif
                var builder = new StringBuilder(data.Length);

                for (var index = 0; index < data.Length; index += 4)
                {
                    builder.AppendFormat(CultureInfo.InvariantCulture, "{0:D4}", BitConverter.ToUInt32(data, index) % 10000);
                }

                var descriptor = new OpenIddictTokenDescriptor
                {
                    AuthorizationId = context.UserCodePrincipal.GetInternalAuthorizationId(),
                    CreationDate = context.UserCodePrincipal.GetCreationDate(),
                    ExpirationDate = context.UserCodePrincipal.GetExpirationDate(),
                    Payload = context.Response.UserCode,
                    Principal = context.UserCodePrincipal,
                    ReferenceId = builder.ToString(),
                    Status = Statuses.Valid,
                    Subject = null, // User codes are not bound to a user until authorization is granted.
                    Type = TokenUsages.UserCode
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

                context.UserCodePrincipal.SetInternalTokenId(await _tokenManager.GetIdAsync(token));
                context.Response.UserCode = builder.ToString();

                context.Logger.LogTrace("The reference token entry for user code '{Identifier}' was successfully " +
                                        "created with the reference identifier '{ReferenceId}'.",
                                        await _tokenManager.GetIdAsync(token), descriptor.ReferenceId);
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating and attaching the hashes of
        /// the access token and authorization code to the identity token principal.
        /// </summary>
        public class AttachTokenDigests : IOpenIddictServerHandler<ProcessSigninContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireIdentityTokenIncluded>()
                    .UseSingletonHandler<AttachTokenDigests>()
                    .SetOrder(CreateReferenceUserCodeEntry.Descriptor.Order + 1_000)
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

                if (string.IsNullOrEmpty(context.Response.AccessToken) &&
                    string.IsNullOrEmpty(context.Response.Code))
                {
                    return default;
                }

                var credentials = context.Options.SigningCredentials.FirstOrDefault(
                    credentials => credentials.Key is AsymmetricSecurityKey);
                if (credentials == null)
                {
                    throw new InvalidOperationException("No suitable signing credentials could be found.");
                }

                using var hash = GetHashAlgorithm(credentials);
                if (hash == null || hash is KeyedHashAlgorithm)
                {
                    throw new InvalidOperationException("The signing credentials algorithm is not valid.");
                }

                if (!string.IsNullOrEmpty(context.Response.AccessToken))
                {
                    var digest = hash.ComputeHash(Encoding.ASCII.GetBytes(context.Response.AccessToken));

                    // Note: only the left-most half of the hash is used.
                    // See http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
                    context.IdentityTokenPrincipal.SetClaim(Claims.AccessTokenHash, Base64UrlEncoder.Encode(digest, 0, digest.Length / 2));
                }

                if (!string.IsNullOrEmpty(context.Response.Code))
                {
                    var digest = hash.ComputeHash(Encoding.ASCII.GetBytes(context.Response.Code));

                    // Note: only the left-most half of the hash is used.
                    // See http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken
                    context.IdentityTokenPrincipal.SetClaim(Claims.CodeHash, Base64UrlEncoder.Encode(digest, 0, digest.Length / 2));
                }

                return default;

                static HashAlgorithm GetHashAlgorithm(SigningCredentials credentials)
                {
                    HashAlgorithm hash = null;

                    if (!string.IsNullOrEmpty(credentials.Digest))
                    {
                        hash = CryptoConfig.CreateFromName(credentials.Digest) as HashAlgorithm;
                    }

                    if (hash == null)
                    {
                        var algorithm = credentials.Digest switch
                        {
                            SecurityAlgorithms.Sha256 => HashAlgorithmName.SHA256,
                            SecurityAlgorithms.Sha384 => HashAlgorithmName.SHA384,
                            SecurityAlgorithms.Sha512 => HashAlgorithmName.SHA512,
                            SecurityAlgorithms.Sha256Digest => HashAlgorithmName.SHA256,
                            SecurityAlgorithms.Sha384Digest => HashAlgorithmName.SHA384,
                            SecurityAlgorithms.Sha512Digest => HashAlgorithmName.SHA512,

                            _ => credentials.Algorithm switch
                            {
#if SUPPORTS_ECDSA
                                SecurityAlgorithms.EcdsaSha256 => HashAlgorithmName.SHA256,
                                SecurityAlgorithms.EcdsaSha384 => HashAlgorithmName.SHA384,
                                SecurityAlgorithms.EcdsaSha512 => HashAlgorithmName.SHA512,
                                SecurityAlgorithms.EcdsaSha256Signature => HashAlgorithmName.SHA256,
                                SecurityAlgorithms.EcdsaSha384Signature => HashAlgorithmName.SHA384,
                                SecurityAlgorithms.EcdsaSha512Signature => HashAlgorithmName.SHA512,
#endif
                                SecurityAlgorithms.HmacSha256 => HashAlgorithmName.SHA256,
                                SecurityAlgorithms.HmacSha384 => HashAlgorithmName.SHA384,
                                SecurityAlgorithms.HmacSha512 => HashAlgorithmName.SHA512,
                                SecurityAlgorithms.HmacSha256Signature => HashAlgorithmName.SHA256,
                                SecurityAlgorithms.HmacSha384Signature => HashAlgorithmName.SHA384,
                                SecurityAlgorithms.HmacSha512Signature => HashAlgorithmName.SHA512,

                                SecurityAlgorithms.RsaSha256 => HashAlgorithmName.SHA256,
                                SecurityAlgorithms.RsaSha384 => HashAlgorithmName.SHA384,
                                SecurityAlgorithms.RsaSha512 => HashAlgorithmName.SHA512,
                                SecurityAlgorithms.RsaSha256Signature => HashAlgorithmName.SHA256,
                                SecurityAlgorithms.RsaSha384Signature => HashAlgorithmName.SHA384,
                                SecurityAlgorithms.RsaSha512Signature => HashAlgorithmName.SHA512,

                                SecurityAlgorithms.RsaSsaPssSha256 => HashAlgorithmName.SHA256,
                                SecurityAlgorithms.RsaSsaPssSha384 => HashAlgorithmName.SHA384,
                                SecurityAlgorithms.RsaSsaPssSha512 => HashAlgorithmName.SHA512,
                                SecurityAlgorithms.RsaSsaPssSha256Signature => HashAlgorithmName.SHA256,
                                SecurityAlgorithms.RsaSsaPssSha384Signature => HashAlgorithmName.SHA384,
                                SecurityAlgorithms.RsaSsaPssSha512Signature => HashAlgorithmName.SHA512,

                                _ => throw new InvalidOperationException("The signing credentials algorithm is not supported.")
                            }
                        };

                        hash = CryptoConfig.CreateFromName(algorithm.Name) as HashAlgorithm;
                    }

                    return hash;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating an identity token using IdentityModel.
        /// </summary>
        public class GenerateIdentityModelIdentityToken : IOpenIddictServerHandler<ProcessSigninContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireIdentityTokenIncluded>()
                    .UseSingletonHandler<GenerateIdentityModelIdentityToken>()
                    .SetOrder(AttachTokenDigests.Descriptor.Order + 1_000)
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

                // If an identity token was already attached by another handler, don't overwrite it.
                if (!string.IsNullOrEmpty(context.Response.IdToken))
                {
                    return default;
                }

                // Sign and attach the identity token.
                context.Response.IdToken = context.Options.JsonWebTokenHandler.CreateToken(new SecurityTokenDescriptor
                {
                    AdditionalHeaderClaims = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        [JwtHeaderParameterNames.Typ] = JsonWebTokenTypes.IdentityToken
                    },
                    Issuer = context.Issuer?.AbsoluteUri,
                    SigningCredentials = context.Options.SigningCredentials.First(credentials =>
                        credentials.Key is AsymmetricSecurityKey),
                    Subject = (ClaimsIdentity) context.IdentityTokenPrincipal.Identity
                });

                context.Logger.LogTrace("The identity token '{Identifier}' was successfully created: {Payload}. " +
                                        "The principal used to create the token contained the following claims: {Claims}.",
                                        context.IdentityTokenPrincipal.GetClaim(Claims.JwtId),
                                        context.Response.IdToken, context.IdentityTokenPrincipal.Claims);

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of beautifying the user code returned to the client.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class BeautifyUserCode : IOpenIddictServerHandler<ProcessSigninContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    // Technically, this handler doesn't require that the degraded mode be disabled
                    // but the default CreateReferenceUserCodeEntry that creates the user code
                    // reference identifiers only works when the degraded mode is disabled.
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireUserCodeIncluded>()
                    .UseSingletonHandler<BeautifyUserCode>()
                    .SetOrder(GenerateIdentityModelIdentityToken.Descriptor.Order + 1_000)
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

                // To make user codes easier to read and type by humans, a dash is automatically
                // appended before each new block of 4 integers. These dashes are expected to be
                // stripped from the user codes when receiving them at the verification endpoint.

                var builder = new StringBuilder(context.Response.UserCode);
                if (builder.Length % 4 != 0)
                {
                    return default;
                }

                for (var index = builder.Length; index >= 0; index -= 4)
                {
                    if (index != 0 && index != builder.Length)
                    {
                        builder.Insert(index, Separators.Dash[0]);
                    }
                }

                context.Response.UserCode = builder.ToString();

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of attaching additional access token properties to the sign-in response.
        /// </summary>
        public class AttachAccessTokenProperties : IOpenIddictServerHandler<ProcessSigninContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireAccessTokenIncluded>()
                    .UseSingletonHandler<AttachAccessTokenProperties>()
                    .SetOrder(BeautifyUserCode.Descriptor.Order + 1_000)
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

                context.Response.TokenType = TokenTypes.Bearer;

                // If an expiration date was set on the access token principal, return it to the client application.
                var date = context.AccessTokenPrincipal.GetExpirationDate();
                if (date.HasValue && date.Value > DateTimeOffset.UtcNow)
                {
                    context.Response.ExpiresIn = (long) ((date.Value - DateTimeOffset.UtcNow).TotalSeconds + .5);
                }

                // If the granted access token scopes differ from the requested scopes, return the granted scopes
                // list as a parameter to inform the client application of the fact the scopes set will be reduced.
                var scopes = new HashSet<string>(context.AccessTokenPrincipal.GetScopes(), StringComparer.Ordinal);
                if ((context.EndpointType == OpenIddictServerEndpointType.Token && context.Request.IsAuthorizationCodeGrantType()) ||
                    !scopes.SetEquals(context.Request.GetScopes()))
                {
                    context.Response.Scope = string.Join(" ", scopes);
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of attaching additional device code properties to the sign-in response.
        /// </summary>
        public class AttachDeviceCodeProperties : IOpenIddictServerHandler<ProcessSigninContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireDeviceCodeIncluded>()
                    .UseSingletonHandler<AttachDeviceCodeProperties>()
                    .SetOrder(AttachAccessTokenProperties.Descriptor.Order + 1_000)
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

                var endpoint = context.Options.VerificationEndpointUris.FirstOrDefault();
                if (endpoint != null)
                {
                    if (context.Issuer == null || !context.Issuer.IsAbsoluteUri)
                    {
                        throw new InvalidOperationException("An absolute URL cannot be built for the device endpoint path.");
                    }

                    var address = new Uri(context.Issuer, endpoint);
                    var builder = new UriBuilder(address)
                    {
                        Query = string.Concat(Parameters.UserCode, "=", context.Response.UserCode)
                    };

                    context.Response[Parameters.VerificationUri] = address.AbsoluteUri;
                    context.Response[Parameters.VerificationUriComplete] = builder.Uri.AbsoluteUri;
                }

                // If an expiration date was set on the device code principal, return it to the client application.
                var date = context.DeviceCodePrincipal.GetExpirationDate();
                if (date.HasValue && date.Value > DateTimeOffset.UtcNow)
                {
                    context.Response.ExpiresIn = (long) ((date.Value - DateTimeOffset.UtcNow).TotalSeconds + .5);
                }

                return default;
            }
        }
    }
}
