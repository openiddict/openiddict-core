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
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
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
            ValidateReferenceToken.Descriptor,
            ValidateSelfContainedToken.Descriptor,
            ValidatePrincipal.Descriptor,
            ValidateTokenEntry.Descriptor,
            ValidateAuthorizationEntry.Descriptor,
            ValidateExpirationDate.Descriptor,

            /*
             * Challenge processing:
             */
            AttachDefaultChallengeError.Descriptor,

            /*
            * Sign-in processing:
            */
            ValidateSigninResponse.Descriptor,
            RestoreInternalClaims.Descriptor,
            AttachDefaultScopes.Descriptor,
            AttachDefaultPresenters.Descriptor,
            InferResources.Descriptor,
            EvaluateReturnedTokens.Descriptor,
            AttachAuthorization.Descriptor,

            PrepareAccessTokenPrincipal.Descriptor,
            PrepareAuthorizationCodePrincipal.Descriptor,
            PrepareRefreshTokenPrincipal.Descriptor,
            PrepareIdentityTokenPrincipal.Descriptor,

            RedeemTokenEntry.Descriptor,
            RevokeRollingTokenEntries.Descriptor,
            ExtendRefreshTokenEntry.Descriptor,

            AttachReferenceAccessToken.Descriptor,
            AttachReferenceAuthorizationCode.Descriptor,
            AttachReferenceRefreshToken.Descriptor,

            CreateSelfContainedAuthorizationCodeEntry.Descriptor,
            CreateSelfContainedRefreshTokenEntry.Descriptor,

            AttachSelfContainedAccessToken.Descriptor,
            AttachSelfContainedAuthorizationCode.Descriptor,
            AttachSelfContainedRefreshToken.Descriptor,

            AttachTokenDigests.Descriptor,
            AttachSelfContainedIdentityToken.Descriptor)

            .AddRange(Authentication.DefaultHandlers)
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
                    case OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType():
                    case OpenIddictServerEndpointType.Userinfo:
                        return default;

                    default: throw new InvalidOperationException("No identity cannot be extracted from this request.");
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of rejecting authentication demands that use an invalid reference token.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class ValidateReferenceToken : IOpenIddictServerHandler<ProcessAuthenticationContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public ValidateReferenceToken() => throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                .ToString());

            public ValidateReferenceToken([NotNull] IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .AddFilter<RequireReferenceTokensEnabled>()
                    .UseScopedHandler<ValidateReferenceToken>()
                    .SetOrder(ValidateAuthenticationDemand.Descriptor.Order + 1_000)
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

                // If the reference token cannot be found, return a generic error.
                var token = await _tokenManager.FindByReferenceIdAsync(identifier);
                if (token == null || !await IsTokenTypeValidAsync(token))
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
                                => "The specified authorization code is not valid.",
                            OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                                => "The specified refresh token is not valid.",

                            _ => "The specified token is not valid."
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

                // If the token cannot be validated, don't return an error to allow another handle to validate it.
                if (!context.Options.SecurityTokenHandler.CanReadToken(payload))
                {
                    return;
                }

                var result = context.EndpointType switch
                {
                    OpenIddictServerEndpointType.Introspection => await ValidateAnyTokenAsync(payload),
                    OpenIddictServerEndpointType.Revocation    => await ValidateAnyTokenAsync(payload),

                    OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType()
                        => await ValidateTokenAsync(payload, TokenUsages.AuthorizationCode),

                    OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                        => await ValidateTokenAsync(payload, TokenUsages.RefreshToken),

                    OpenIddictServerEndpointType.Userinfo => await ValidateTokenAsync(payload, TokenUsages.AccessToken),

                    _ => new TokenValidationResult { IsValid = false }
                };

                // If the token cannot be validated, don't return an error to allow another handle to validate it.
                if (result.ClaimsIdentity == null)
                {
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

                async ValueTask<TokenValidationResult> ValidateTokenAsync(string token, string type)
                {
                    var parameters = new TokenValidationParameters
                    {
                        NameClaimType = Claims.Name,
                        PropertyBag = new Dictionary<string, object> { [Claims.Private.TokenUsage] = type },
                        RoleClaimType = Claims.Role,
                        ValidIssuer = context.Issuer?.AbsoluteUri,
                        ValidateAudience = false,
                        ValidateLifetime = false
                    };

                    parameters.IssuerSigningKeys = type switch
                    {
                        TokenUsages.AccessToken       => context.Options.SigningCredentials.Select(credentials => credentials.Key),
                        TokenUsages.AuthorizationCode => context.Options.SigningCredentials.Select(credentials => credentials.Key),
                        TokenUsages.RefreshToken      => context.Options.SigningCredentials.Select(credentials => credentials.Key),

                        _ => Array.Empty<SecurityKey>()
                    };

                    parameters.TokenDecryptionKeys = type switch
                    {
                        TokenUsages.AuthorizationCode => context.Options.EncryptionCredentials.Select(credentials => credentials.Key),
                        TokenUsages.RefreshToken      => context.Options.EncryptionCredentials.Select(credentials => credentials.Key),

                        TokenUsages.AccessToken => context.Options.EncryptionCredentials
                            .Select(credentials => credentials.Key)
                            .Where(key => key is SymmetricSecurityKey),

                        _ => Array.Empty<SecurityKey>()
                    };

                    return await context.Options.SecurityTokenHandler.ValidateTokenStringAsync(token, parameters);
                }

                async ValueTask<TokenValidationResult> ValidateAnyTokenAsync(string token)
                {
                    var result = await ValidateTokenAsync(token, TokenUsages.AccessToken);
                    if (result.IsValid)
                    {
                        return result;
                    }

                    result = await ValidateTokenAsync(token, TokenUsages.RefreshToken);
                    if (result.IsValid)
                    {
                        return result;
                    }

                    result = await ValidateTokenAsync(token, TokenUsages.AuthorizationCode);
                    if (result.IsValid)
                    {
                        return result;
                    }

                    return new TokenValidationResult { IsValid = false };
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
        /// Contains the logic responsible of rejecting authentication demands that specify an invalid self-contained token.
        /// </summary>
        public class ValidateSelfContainedToken : IOpenIddictServerHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
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

                var token = context.EndpointType switch
                {
                    OpenIddictServerEndpointType.Authorization => context.Request.IdTokenHint,
                    OpenIddictServerEndpointType.Logout        => context.Request.IdTokenHint,

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
                if (string.IsNullOrEmpty(token) || !context.Options.SecurityTokenHandler.CanReadToken(token))
                {
                    return;
                }

                var result = context.EndpointType switch
                {
                    OpenIddictServerEndpointType.Authorization => await ValidateTokenAsync(token, TokenUsages.IdToken),
                    OpenIddictServerEndpointType.Logout        => await ValidateTokenAsync(token, TokenUsages.IdToken),

                    // When reference tokens are enabled, this handler can only validate id_tokens.
                    OpenIddictServerEndpointType.Introspection when context.Options.UseReferenceTokens
                        => await ValidateTokenAsync(token, TokenUsages.IdToken),

                    OpenIddictServerEndpointType.Revocation when context.Options.UseReferenceTokens
                        => await ValidateTokenAsync(token, TokenUsages.IdToken),

                    _ when context.Options.UseReferenceTokens => new TokenValidationResult { IsValid = false },

                    OpenIddictServerEndpointType.Introspection => await ValidateAnyTokenAsync(token),
                    OpenIddictServerEndpointType.Revocation    => await ValidateAnyTokenAsync(token),

                    OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType()
                        => await ValidateTokenAsync(token, TokenUsages.AuthorizationCode),

                    OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                        => await ValidateTokenAsync(token, TokenUsages.RefreshToken),

                    OpenIddictServerEndpointType.Userinfo => await ValidateTokenAsync(token, TokenUsages.AccessToken),

                    _ => new TokenValidationResult { IsValid = false }
                };

                // If the token cannot be validated, don't return an error to allow another handle to validate it.
                if (result.ClaimsIdentity == null)
                {
                    return;
                }

                // Attach the principal extracted from the token to the parent event context.
                context.Principal = new ClaimsPrincipal(result.ClaimsIdentity);

                async ValueTask<TokenValidationResult> ValidateTokenAsync(string token, string type)
                {
                    var parameters = new TokenValidationParameters
                    {
                        NameClaimType = Claims.Name,
                        PropertyBag = new Dictionary<string, object> { [Claims.Private.TokenUsage] = type },
                        RoleClaimType = Claims.Role,
                        ValidIssuer = context.Issuer?.AbsoluteUri,
                        ValidateAudience = false,
                        ValidateLifetime = false
                    };

                    parameters.IssuerSigningKeys = type switch
                    {
                        TokenUsages.AccessToken       => context.Options.SigningCredentials.Select(credentials => credentials.Key),
                        TokenUsages.AuthorizationCode => context.Options.SigningCredentials.Select(credentials => credentials.Key),
                        TokenUsages.RefreshToken      => context.Options.SigningCredentials.Select(credentials => credentials.Key),

                        TokenUsages.IdToken => context.Options.SigningCredentials
                            .Select(credentials => credentials.Key)
                            .OfType<AsymmetricSecurityKey>(),

                        _ => Array.Empty<SecurityKey>()
                    };

                    parameters.TokenDecryptionKeys = type switch
                    {
                        TokenUsages.AuthorizationCode => context.Options.EncryptionCredentials.Select(credentials => credentials.Key),
                        TokenUsages.RefreshToken      => context.Options.EncryptionCredentials.Select(credentials => credentials.Key),

                        TokenUsages.AccessToken => context.Options.EncryptionCredentials
                            .Select(credentials => credentials.Key)
                            .Where(key => key is SymmetricSecurityKey),

                        _ => Array.Empty<SecurityKey>()
                    };

                    return await context.Options.SecurityTokenHandler.ValidateTokenStringAsync(token, parameters);
                }

                async ValueTask<TokenValidationResult> ValidateAnyTokenAsync(string token)
                {
                    var result = await ValidateTokenAsync(token, TokenUsages.AccessToken);
                    if (result.IsValid)
                    {
                        return result;
                    }

                    result = await ValidateTokenAsync(token, TokenUsages.RefreshToken);
                    if (result.IsValid)
                    {
                        return result;
                    }

                    result = await ValidateTokenAsync(token, TokenUsages.AuthorizationCode);
                    if (result.IsValid)
                    {
                        return result;
                    }

                    result = await ValidateTokenAsync(token, TokenUsages.IdToken);
                    if (result.IsValid)
                    {
                        return result;
                    }

                    return new TokenValidationResult { IsValid = false };
                }
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
                    .SetOrder(ValidateSelfContainedToken.Descriptor.Order + 1_000)
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
                            OpenIddictServerEndpointType.Authorization => "The specified identity token hint is not valid.",
                            OpenIddictServerEndpointType.Logout        => "The specified identity token hint is not valid.",

                            OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType()
                                => "The specified authorization code is not valid.",
                            OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                                => "The specified refresh token is not valid.",

                            _ => "The specified token is not valid."
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
                                => "The specified authorization code is not valid.",
                            OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                                => "The specified refresh token is not valid.",

                            _ => "The specified token is not valid."
                        });

                    return;
                }

                // If the authorization code/refresh token is already marked as redeemed, this may indicate that
                // it was compromised. In this case, revoke the authorization and all the associated tokens. 
                // See https://tools.ietf.org/html/rfc6749#section-10.5 for more information.
                if (context.EndpointType == OpenIddictServerEndpointType.Token &&
                   (context.Request.IsAuthorizationCodeGrantType() || context.Request.IsRefreshTokenGrantType()) &&
                    await _tokenManager.IsRedeemedAsync(token))
                {
                    await TryRevokeAuthorizationChainAsync(token);

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
                            OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                                => "The specified refresh token has already been redeemed.",

                            _ => "The specified token has already been redeemed."
                        });

                    return;
                }

                if (!await _tokenManager.IsValidAsync(token))
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

                async ValueTask TryRevokeAuthorizationChainAsync(object token)
                {
                    // First, mark the redeemed token submitted by the client as revoked.
                    await _tokenManager.TryRevokeAsync(token);

                    var identifier = context.Principal.GetInternalAuthorizationId();
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

                    await using var enumerator = _tokenManager.FindByAuthorizationIdAsync(identifier).GetAsyncEnumerator();
                    while (await enumerator.MoveNextAsync())
                    {
                        // Don't change the status of the token used in the token request.
                        if (string.Equals(context.Principal.GetInternalTokenId(),
                            await _tokenManager.GetIdAsync(enumerator.Current), StringComparison.Ordinal))
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
                if (authorization == null || !await _authorizationManager.IsValidAsync(authorization))
                {
                    context.Logger.LogError("The authorization associated with token '{Identifier}' " +
                                            "was no longer valid.", context.Principal.GetInternalTokenId());

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
                    context.Response.Error = context.EndpointType switch
                    {
                        OpenIddictServerEndpointType.Authorization => Errors.AccessDenied,
                        OpenIddictServerEndpointType.Token         => Errors.InvalidGrant,
                        OpenIddictServerEndpointType.Userinfo      => Errors.InvalidToken,

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

                        _ => throw new InvalidOperationException("An OpenID Connect response cannot be returned from this endpoint.")
                    };
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of ensuring that the sign-in response
        /// is compatible with the type of the endpoint that handled the request.
        /// </summary>
        public class ValidateSigninResponse : IOpenIddictServerHandler<ProcessSigninContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .UseSingletonHandler<ValidateSigninResponse>()
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
                    case OpenIddictServerEndpointType.Token:
                        break;

                    default: throw new InvalidOperationException("An OpenID Connect response cannot be returned from this endpoint.");
                }

                if (context.Principal.Identity == null || !context.Principal.Identity.IsAuthenticated)
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .AppendLine("The specified principal doesn't contain a valid or authenticated identity.")
                        .Append("Make sure that both 'ClaimsPrincipal.Identity' and 'ClaimsPrincipal.Identity.AuthenticationType' ")
                        .Append("are not null and that 'ClaimsPrincipal.Identity.IsAuthenticated' returns 'true'.")
                        .ToString());
                }

                if (string.IsNullOrEmpty(context.Principal.GetClaim(Claims.Subject)))
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .AppendLine("The security principal was rejected because the mandatory subject claim was missing.")
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
                    .SetOrder(ValidateSigninResponse.Descriptor.Order + 1_000)
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

                if (context.EndpointType != OpenIddictServerEndpointType.Token)
                {
                    return default;
                }

                if (!context.Request.IsAuthorizationCodeGrantType() && !context.Request.IsRefreshTokenGrantType())
                {
                    return default;
                }

                if (!context.Transaction.Properties.TryGetValue(Properties.OriginalPrincipal, out var principal))
                {
                    throw new InvalidOperationException("The original principal cannot be resolved from the transaction.");
                }

                // Restore the internal claims resolved from the authorization code/refresh token.
                foreach (var claims in ((ClaimsPrincipal) principal).Claims
                    .Where(claim => claim.Type.StartsWith(Claims.Prefixes.Private))
                    .GroupBy(claim => claim.Type))
                {
                    // If the specified principal already contains one claim of the iterated type, ignore them.
                    if (context.Principal.Claims.Any(claim => claim.Type == claims.Key))
                    {
                        continue;
                    }

                    ((ClaimsIdentity) context.Principal.Identity).AddClaims(claims);
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

                    // For token requests, prevent an authorization code from being returned as this type of token
                    // cannot be issued from the token endpoint in the standard OAuth 2.0/OpenID Connect flows.
                    OpenIddictServerEndpointType.Token => false,

                    _ => false
                };

                context.IncludeRefreshToken = context.EndpointType switch
                {
                    // For authorization requests, prevent a refresh token from being returned as OAuth 2.0
                    // explicitly disallows returning a refresh token from the authorization endpoint.
                    // See https://tools.ietf.org/html/rfc6749#section-4.2.2 for more information.
                    OpenIddictServerEndpointType.Authorization => false,

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

                // If no authorization code or refresh token is returned, don't create an authorization.
                if (!context.IncludeAuthorizationCode && !context.IncludeRefreshToken)
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
                    // Never exclude the subject claim.
                    if (string.Equals(claim.Type, Claims.Subject, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
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

                // Note: the internal token identifier is automatically reset to ensure
                // the identifier inherited from the parent token is not automatically reused.
                principal.SetClaim(Claims.JwtId, Guid.NewGuid().ToString())
                         .SetCreationDate(DateTimeOffset.UtcNow)
                         .SetInternalTokenId(identifier: null);

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
                    if (scopes.Count != 0)
                    {
                        context.Logger.LogDebug("The access token scopes will be limited to the scopes " +
                                                "requested by the client application: {Scopes}.", scopes);

                        principal.SetClaim(Claims.Scope, string.Join(" ", scopes.Intersect(context.Principal.GetScopes())));
                    }
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

                // Note: the internal token identifier is automatically reset to ensure
                // the identifier inherited from the parent token is not automatically reused.
                var principal = context.Principal.Clone(_ => true)
                    .SetClaim(Claims.JwtId, Guid.NewGuid().ToString())
                    .SetCreationDate(DateTimeOffset.UtcNow)
                    .SetInternalTokenId(identifier: null);

                var lifetime = context.Principal.GetAuthorizationCodeLifetime() ?? context.Options.AuthorizationCodeLifetime;
                if (lifetime.HasValue)
                {
                    principal.SetExpirationDate(principal.GetCreationDate() + lifetime.Value);
                }

                // Attach the redirect_uri to allow for later comparison when
                // receiving a grant_type=authorization_code token request.
                if (!string.IsNullOrEmpty(context.Request.RedirectUri))
                {
                    principal.SetClaim(Claims.Private.RedirectUri, context.Request.RedirectUri);
                }

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
                if (!string.IsNullOrEmpty(context.Request.Nonce))
                {
                    principal.SetClaim(Claims.Private.Nonce, context.Request.Nonce);
                }

                context.AuthorizationCodePrincipal = principal;

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

                // Note: the internal token identifier is automatically reset to ensure
                // the identifier inherited from the parent token is not automatically reused.
                var principal = context.Principal.Clone(_ => true)
                    .SetClaim(Claims.JwtId, Guid.NewGuid().ToString())
                    .SetCreationDate(DateTimeOffset.UtcNow)
                    .SetInternalTokenId(identifier: null);

                // When sliding expiration is disabled, the expiration date of generated refresh tokens is fixed
                // and must exactly match the expiration date of the refresh token used in the token request.
                if (context.EndpointType == OpenIddictServerEndpointType.Token &&
                    context.Request.IsRefreshTokenGrantType() && !context.Options.UseSlidingExpiration)
                {
                    if (!context.Transaction.Properties.TryGetValue(Properties.OriginalPrincipal, out var property))
                    {
                        throw new InvalidOperationException("The original principal cannot be resolved from the transaction.");
                    }

                    principal.SetExpirationDate(((ClaimsPrincipal) property).GetExpirationDate());
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

                    // Always exclude private claims, whose values must generally be kept secret.
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

                // Note: the internal token identifier is automatically reset to ensure
                // the identifier inherited from the parent token is not automatically reused.
                principal.SetClaim(Claims.JwtId, Guid.NewGuid().ToString())
                         .SetCreationDate(DateTimeOffset.UtcNow)
                         .SetInternalTokenId(identifier: null);

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

                if (context.EndpointType == OpenIddictServerEndpointType.Authorization && !string.IsNullOrEmpty(context.Request.Nonce))
                {
                    principal.SetClaim(Claims.Nonce, context.Request.Nonce);
                }

                else if (context.EndpointType == OpenIddictServerEndpointType.Token)
                {
                    principal.SetClaim(Claims.Nonce, context.Principal.GetClaim(Claims.Private.Nonce));
                }

                context.IdentityTokenPrincipal = principal;

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

                if (!context.Options.UseRollingTokens && !context.Request.IsAuthorizationCodeGrantType())
                {
                    return;
                }

                // If rolling tokens are enabled or if the request is a grant_type=authorization_code request,
                // mark the authorization code or the refresh token as redeemed to prevent future reuses.
                // If the operation fails, return an error indicating the code/token is no longer valid.
                // See https://tools.ietf.org/html/rfc6749#section-6 for more information.
                if (!await _tokenManager.TryRedeemAsync(token))
                {
                    context.Reject(
                        error: Errors.InvalidGrant,
                        description: context.Request.IsAuthorizationCodeGrantType() ?
                            "The specified authorization code is no longer valid." :
                            "The specified refresh token is no longer valid.");

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of redeeming the token entry
        /// corresponding to the received authorization code or refresh token.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class RevokeRollingTokenEntries : IOpenIddictServerHandler<ProcessSigninContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;

            public RevokeRollingTokenEntries() => throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                .ToString());

            public RevokeRollingTokenEntries([NotNull] IOpenIddictTokenManager tokenManager)
                => _tokenManager = tokenManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireTokenStorageEnabled>()
                    .AddFilter<RequireRollingTokensEnabled>()
                    .UseScopedHandler<RevokeRollingTokenEntries>()
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
                    .SetOrder(RevokeRollingTokenEntries.Descriptor.Order + 1_000)
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
        /// Contains the logic responsible of generating and attaching
        /// the reference access token returned as part of the response.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class AttachReferenceAccessToken : IOpenIddictServerHandler<ProcessSigninContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;
            private readonly IOpenIddictTokenManager _tokenManager;

            public AttachReferenceAccessToken() => throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                .ToString());

            public AttachReferenceAccessToken(
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
                    .AddFilter<RequireReferenceTokensEnabled>()
                    .AddFilter<RequireAccessTokenIncluded>()
                    .UseScopedHandler<AttachReferenceAccessToken>()
                    .SetOrder(ExtendRefreshTokenEntry.Descriptor.Order + 1_000)
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

                // Generate a new crypto-secure random identifier that will be substituted to the token.
                var data = new byte[256 / 8];
#if SUPPORTS_STATIC_RANDOM_NUMBER_GENERATOR_METHODS
                RandomNumberGenerator.Fill(data);
#else
                using var generator = RandomNumberGenerator.Create();
                generator.GetBytes(data);
#endif
                var identifier = Base64UrlEncoder.Encode(data);

                var descriptor = new OpenIddictTokenDescriptor
                {
                    AuthorizationId = context.AccessTokenPrincipal.GetInternalAuthorizationId(),
                    CreationDate = context.AccessTokenPrincipal.GetCreationDate(),
                    ExpirationDate = context.AccessTokenPrincipal.GetExpirationDate(),
                    Principal = context.AccessTokenPrincipal,
                    ReferenceId = identifier,
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

                descriptor.Payload = await context.Options.SecurityTokenHandler.CreateTokenFromDescriptorAsync(new SecurityTokenDescriptor
                {
                    Claims = new Dictionary<string, object> { [Claims.Private.TokenUsage] = TokenUsages.AccessToken },
                    EncryptingCredentials = context.Options.EncryptionCredentials.FirstOrDefault(
                        credentials => credentials.Key is SymmetricSecurityKey),
                    Issuer = context.Issuer?.AbsoluteUri,
                    SigningCredentials = context.Options.SigningCredentials.FirstOrDefault(credentials =>
                        credentials.Key is SymmetricSecurityKey) ?? context.Options.SigningCredentials.First(),
                    Subject = (ClaimsIdentity) context.AccessTokenPrincipal.Identity
                });

                await _tokenManager.CreateAsync(descriptor);

                context.Response.AccessToken = identifier;
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating and attaching
        /// the reference authorization code returned as part of the response.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class AttachReferenceAuthorizationCode : IOpenIddictServerHandler<ProcessSigninContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;
            private readonly IOpenIddictTokenManager _tokenManager;

            public AttachReferenceAuthorizationCode() => throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                .ToString());

            public AttachReferenceAuthorizationCode(
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
                    .AddFilter<RequireReferenceTokensEnabled>()
                    .AddFilter<RequireAuthorizationCodeIncluded>()
                    .UseScopedHandler<AttachReferenceAuthorizationCode>()
                    .SetOrder(AttachReferenceAccessToken.Descriptor.Order + 1_000)
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

                // Generate a new crypto-secure random identifier that will be substituted to the token.
                var data = new byte[256 / 8];
#if SUPPORTS_STATIC_RANDOM_NUMBER_GENERATOR_METHODS
                RandomNumberGenerator.Fill(data);
#else
                using var generator = RandomNumberGenerator.Create();
                generator.GetBytes(data);
#endif
                var identifier = Base64UrlEncoder.Encode(data);

                var descriptor = new OpenIddictTokenDescriptor
                {
                    AuthorizationId = context.AuthorizationCodePrincipal.GetInternalAuthorizationId(),
                    CreationDate = context.AuthorizationCodePrincipal.GetCreationDate(),
                    ExpirationDate = context.AuthorizationCodePrincipal.GetExpirationDate(),
                    Principal = context.AuthorizationCodePrincipal,
                    ReferenceId = identifier,
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

                descriptor.Payload = await context.Options.SecurityTokenHandler.CreateTokenFromDescriptorAsync(new SecurityTokenDescriptor
                {
                    Claims = new Dictionary<string, object> { [Claims.Private.TokenUsage] = TokenUsages.AuthorizationCode },
                    EncryptingCredentials = context.Options.EncryptionCredentials.FirstOrDefault(
                        credentials => credentials.Key is SymmetricSecurityKey),
                    Issuer = context.Issuer?.AbsoluteUri,
                    SigningCredentials = context.Options.SigningCredentials.FirstOrDefault(credentials =>
                        credentials.Key is SymmetricSecurityKey) ?? context.Options.SigningCredentials.First(),
                    Subject = (ClaimsIdentity) context.AuthorizationCodePrincipal.Identity
                });

                await _tokenManager.CreateAsync(descriptor);

                context.Response.Code = identifier;
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating and attaching
        /// the reference refresh token returned as part of the response.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class AttachReferenceRefreshToken : IOpenIddictServerHandler<ProcessSigninContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;
            private readonly IOpenIddictTokenManager _tokenManager;

            public AttachReferenceRefreshToken() => throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                .ToString());

            public AttachReferenceRefreshToken(
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
                    .AddFilter<RequireReferenceTokensEnabled>()
                    .AddFilter<RequireRefreshTokenIncluded>()
                    .UseScopedHandler<AttachReferenceRefreshToken>()
                    .SetOrder(AttachReferenceAuthorizationCode.Descriptor.Order + 1_000)
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

                // Generate a new crypto-secure random identifier that will be substituted to the token.
                var data = new byte[256 / 8];
#if SUPPORTS_STATIC_RANDOM_NUMBER_GENERATOR_METHODS
                RandomNumberGenerator.Fill(data);
#else
                using var generator = RandomNumberGenerator.Create();
                generator.GetBytes(data);
#endif
                var identifier = Base64UrlEncoder.Encode(data);

                var descriptor = new OpenIddictTokenDescriptor
                {
                    AuthorizationId = context.RefreshTokenPrincipal.GetInternalAuthorizationId(),
                    CreationDate = context.RefreshTokenPrincipal.GetCreationDate(),
                    ExpirationDate = context.RefreshTokenPrincipal.GetExpirationDate(),
                    Principal = context.RefreshTokenPrincipal,
                    ReferenceId = identifier,
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

                descriptor.Payload = await context.Options.SecurityTokenHandler.CreateTokenFromDescriptorAsync(new SecurityTokenDescriptor
                {
                    Claims = new Dictionary<string, object> { [Claims.Private.TokenUsage] = TokenUsages.RefreshToken },
                    EncryptingCredentials = context.Options.EncryptionCredentials[0],
                    Issuer = context.Issuer?.AbsoluteUri,
                    SigningCredentials = context.Options.SigningCredentials.FirstOrDefault(credentials =>
                        credentials.Key is SymmetricSecurityKey) ?? context.Options.SigningCredentials.First(),
                    Subject = (ClaimsIdentity) context.RefreshTokenPrincipal.Identity
                });

                await _tokenManager.CreateAsync(descriptor);

                context.Response.RefreshToken = identifier;
            }
        }

        /// <summary>
        /// Contains the logic responsible of creating a token entry in the database for the authorization code.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class CreateSelfContainedAuthorizationCodeEntry : IOpenIddictServerHandler<ProcessSigninContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;
            private readonly IOpenIddictTokenManager _tokenManager;

            public CreateSelfContainedAuthorizationCodeEntry() => throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                .ToString());

            public CreateSelfContainedAuthorizationCodeEntry(
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
                    .AddFilter<RequireReferenceTokensDisabled>()
                    .AddFilter<RequireAuthorizationCodeIncluded>()
                    .UseScopedHandler<CreateSelfContainedAuthorizationCodeEntry>()
                    .SetOrder(ExtendRefreshTokenEntry.Descriptor.Order + 1_000)
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

                // If a token identifier was already attached by another handler, don't overwrite it.
                if (!string.IsNullOrEmpty(context.AuthorizationCodePrincipal.GetInternalTokenId()))
                {
                    return;
                }

                var descriptor = new OpenIddictTokenDescriptor
                {
                    AuthorizationId = context.AuthorizationCodePrincipal.GetInternalAuthorizationId(),
                    CreationDate = context.AuthorizationCodePrincipal.GetCreationDate(),
                    ExpirationDate = context.AuthorizationCodePrincipal.GetExpirationDate(),
                    Principal = context.AuthorizationCodePrincipal,
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

                // Set the internal token identifier so that it can be added to the serialized code.
                context.AuthorizationCodePrincipal.SetInternalTokenId(await _tokenManager.GetIdAsync(token));
            }
        }

        /// <summary>
        /// Contains the logic responsible of creating a token entry in the database for the refresh token.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class CreateSelfContainedRefreshTokenEntry : IOpenIddictServerHandler<ProcessSigninContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;
            private readonly IOpenIddictTokenManager _tokenManager;

            public CreateSelfContainedRefreshTokenEntry() => throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                .ToString());

            public CreateSelfContainedRefreshTokenEntry(
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
                    .AddFilter<RequireReferenceTokensDisabled>()
                    .AddFilter<RequireRefreshTokenIncluded>()
                    .UseScopedHandler<CreateSelfContainedRefreshTokenEntry>()
                    .SetOrder(CreateSelfContainedAuthorizationCodeEntry.Descriptor.Order + 1_000)
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

                // If a token identifier was already attached by another handler, don't overwrite it.
                if (!string.IsNullOrEmpty(context.RefreshTokenPrincipal.GetInternalTokenId()))
                {
                    return;
                }

                var descriptor = new OpenIddictTokenDescriptor
                {
                    AuthorizationId = context.RefreshTokenPrincipal.GetInternalAuthorizationId(),
                    CreationDate = context.RefreshTokenPrincipal.GetCreationDate(),
                    ExpirationDate = context.RefreshTokenPrincipal.GetExpirationDate(),
                    Principal = context.RefreshTokenPrincipal,
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

                // Set the internal token identifier so that it can be added to the serialized token.
                context.RefreshTokenPrincipal.SetInternalTokenId(await _tokenManager.GetIdAsync(token));
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating and attaching
        /// the self-contained access token returned as part of the response.
        /// </summary>
        public class AttachSelfContainedAccessToken : IOpenIddictServerHandler<ProcessSigninContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireReferenceTokensDisabled>()
                    .AddFilter<RequireAccessTokenIncluded>()
                    .UseSingletonHandler<AttachSelfContainedAccessToken>()
                    .SetOrder(CreateSelfContainedRefreshTokenEntry.Descriptor.Order + 1_000)
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

                context.Response.AccessToken = await context.Options.SecurityTokenHandler.CreateTokenFromDescriptorAsync(
                    new SecurityTokenDescriptor
                    {
                        Claims = new Dictionary<string, object> { [Claims.Private.TokenUsage] = TokenUsages.AccessToken },
                        EncryptingCredentials = context.Options.EncryptionCredentials.FirstOrDefault(
                            credentials => credentials.Key is SymmetricSecurityKey),
                        Issuer = context.Issuer?.AbsoluteUri,
                        SigningCredentials = context.Options.SigningCredentials.FirstOrDefault(credentials =>
                            credentials.Key is SymmetricSecurityKey) ?? context.Options.SigningCredentials.First(),
                        Subject = (ClaimsIdentity) context.AccessTokenPrincipal.Identity
                    });
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating and attaching
        /// the self-contained authorization code returned as part of the response.
        /// </summary>
        public class AttachSelfContainedAuthorizationCode : IOpenIddictServerHandler<ProcessSigninContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireReferenceTokensDisabled>()
                    .AddFilter<RequireAuthorizationCodeIncluded>()
                    .UseSingletonHandler<AttachSelfContainedAuthorizationCode>()
                    .SetOrder(AttachSelfContainedAccessToken.Descriptor.Order + 1_000)
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

                context.Response.Code = await context.Options.SecurityTokenHandler.CreateTokenFromDescriptorAsync(
                    new SecurityTokenDescriptor
                    {
                        Claims = new Dictionary<string, object> { [Claims.Private.TokenUsage] = TokenUsages.AuthorizationCode },
                        EncryptingCredentials = context.Options.EncryptionCredentials.FirstOrDefault(
                            credentials => credentials.Key is SymmetricSecurityKey),
                        Issuer = context.Issuer?.AbsoluteUri,
                        SigningCredentials = context.Options.SigningCredentials.FirstOrDefault(credentials =>
                            credentials.Key is SymmetricSecurityKey) ?? context.Options.SigningCredentials.First(),
                        Subject = (ClaimsIdentity) context.AuthorizationCodePrincipal.Identity
                    });
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating and attaching
        /// the self-contained refresh token returned as part of the response.
        /// </summary>
        public class AttachSelfContainedRefreshToken : IOpenIddictServerHandler<ProcessSigninContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireReferenceTokensDisabled>()
                    .AddFilter<RequireRefreshTokenIncluded>()
                    .UseSingletonHandler<AttachSelfContainedRefreshToken>()
                    .SetOrder(AttachSelfContainedAuthorizationCode.Descriptor.Order + 1_000)
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

                context.Response.RefreshToken = await context.Options.SecurityTokenHandler.CreateTokenFromDescriptorAsync(
                    new SecurityTokenDescriptor
                    {
                        Claims = new Dictionary<string, object> { [Claims.Private.TokenUsage] = TokenUsages.RefreshToken },
                        EncryptingCredentials = context.Options.EncryptionCredentials[0],
                        Issuer = context.Issuer?.AbsoluteUri,
                        SigningCredentials = context.Options.SigningCredentials.FirstOrDefault(credentials =>
                            credentials.Key is SymmetricSecurityKey) ?? context.Options.SigningCredentials.First(),
                        Subject = (ClaimsIdentity) context.RefreshTokenPrincipal.Identity
                    });
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
                    .SetOrder(AttachSelfContainedRefreshToken.Descriptor.Order + 1_000)
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
        /// Contains the logic responsible of generating and attaching
        /// the self-contained identity token returned as part of the response.
        /// </summary>
        public class AttachSelfContainedIdentityToken : IOpenIddictServerHandler<ProcessSigninContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireIdentityTokenIncluded>()
                    .UseSingletonHandler<AttachSelfContainedIdentityToken>()
                    .SetOrder(AttachTokenDigests.Descriptor.Order + 1_000)
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

                // If an identity token was already attached by another handler, don't overwrite it.
                if (!string.IsNullOrEmpty(context.Response.IdToken))
                {
                    return;
                }

                context.Response.IdToken = await context.Options.SecurityTokenHandler.CreateTokenFromDescriptorAsync(
                    new SecurityTokenDescriptor
                    {
                        Claims = new Dictionary<string, object> { [Claims.Private.TokenUsage] = TokenUsages.IdToken },
                        Issuer = context.Issuer?.AbsoluteUri,
                        SigningCredentials = context.Options.SigningCredentials.First(credentials =>
                            credentials.Key is AsymmetricSecurityKey),
                        Subject = (ClaimsIdentity) context.IdentityTokenPrincipal.Identity
                    });
            }
        }

        /// <summary>
        /// Contains the logic responsible of attaching additional properties to the sign-in response.
        /// </summary>
        public class AttachAdditionalProperties : IOpenIddictServerHandler<ProcessSigninContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireAccessTokenIncluded>()
                    .UseSingletonHandler<AttachAdditionalProperties>()
                    .SetOrder(AttachSelfContainedIdentityToken.Descriptor.Order + 1_000)
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

                if (context.AccessTokenPrincipal == null)
                {
                    throw new InvalidOperationException("The access token principal couldn't be found.");
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
                if (context.Request.IsAuthorizationCodeGrantType() ||
                   !context.AccessTokenPrincipal.GetScopes().SetEquals(context.Request.GetScopes()))
                {
                    context.Response.Scope = string.Join(" ", context.AccessTokenPrincipal.GetScopes());
                }

                return default;
            }
        }
    }
}
