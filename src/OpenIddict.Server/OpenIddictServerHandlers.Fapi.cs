/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Globalization;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Server;

public static partial class OpenIddictServerHandlers
{
    /// <summary>
    /// Contains the handlers enforcing the FAPI 2.0 security profile
    /// (https://openid.net/specs/fapi-security-profile-2_0-final.html).
    /// </summary>
    public static class Fapi
    {
        public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } =
        [
            /*
             * Authentication processing:
             */
            ValidateClientAuthentication.Descriptor,
            ValidateSenderConstrainedAccessTokenRequest.Descriptor,

            /*
             * Pushed authorization request validation:
             */
            ValidatePushedRedirectUri.Descriptor,

            /*
             * Token validation:
             */
            RestrictClientTokenSigningAlgorithms.Descriptor,
            ValidateClientTokenDates.Descriptor,

            /*
             * Sign-in processing:
             */
            LimitAuthorizationCodeLifetime.Descriptor,
            LimitPushedAuthorizationRequestLifetime.Descriptor,

            /*
             * Discovery:
             */
            RestrictRequestObjectSigningAlgorithms.Descriptor
        ];

        /// <summary>
        /// Contains the logic responsible for rejecting client authentication methods and client
        /// types that are not allowed by the FAPI 2.0 security profile (section 5.3.2.1, items 3, 6 and 8).
        /// </summary>
        public sealed class ValidateClientAuthentication : IOpenIddictServerHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireFapi2SecurityProfileEnabled>()
                    .UseSingletonHandler<ValidateClientAuthentication>()
                    .SetOrder(ValidateClientCertificate.Descriptor.Order + 250)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessAuthenticationContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                // Only validate the endpoints that support client authentication.
                if (context.EndpointType is not (OpenIddictServerEndpointType.BackchannelAuthentication or
                                                 OpenIddictServerEndpointType.DeviceAuthorization       or
                                                 OpenIddictServerEndpointType.Introspection             or
                                                 OpenIddictServerEndpointType.PushedAuthorization       or
                                                 OpenIddictServerEndpointType.Revocation                or
                                                 OpenIddictServerEndpointType.Token))
                {
                    return;
                }

                // Client secrets (client_secret_basic, client_secret_post and client_secret_jwt) are not allowed.
                if (!string.IsNullOrEmpty(context.ClientSecret))
                {
                    context.Logger.LogInformation(6760, SR.GetResourceString(SR.ID6760), SR.GetResourceString(SR.ID2480));

                    context.Reject(
                        error: Errors.InvalidClient,
                        description: SR.GetResourceString(SR.ID2480),
                        uri: SR.FormatID8000(SR.ID2480));

                    return;
                }

                // Note: when the degraded mode is enabled, the client type cannot be resolved.
                if (context.Options.EnableDegradedMode || string.IsNullOrEmpty(context.ClientId))
                {
                    return;
                }

                var manager = context.ServiceProvider.GetService<IOpenIddictApplicationManager>()
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

                var application = await manager.FindByClientIdAsync(context.ClientId, context.CancellationToken);
                if (application is null)
                {
                    return;
                }

                // Only confidential clients are supported (section 5.3.2.1, item 3).
                if (await manager.HasClientTypeAsync(application, ClientTypes.Public, context.CancellationToken))
                {
                    context.Logger.LogInformation(6760, SR.GetResourceString(SR.ID6760), SR.GetResourceString(SR.ID2482));

                    context.Reject(
                        error: Errors.InvalidClient,
                        description: SR.GetResourceString(SR.ID2482),
                        uri: SR.FormatID8000(SR.ID2482));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting token requests that don't allow issuing
        /// sender-constrained access tokens (section 5.3.2.1, items 4 and 5).
        /// </summary>
        public sealed class ValidateSenderConstrainedAccessTokenRequest : IOpenIddictServerHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireFapi2SecurityProfileEnabled>()
                    .UseSingletonHandler<ValidateSenderConstrainedAccessTokenRequest>()
                    .SetOrder(ValidateDPoPProof.Descriptor.Order + 250)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessAuthenticationContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (context.EndpointType is not OpenIddictServerEndpointType.Token)
                {
                    return ValueTask.CompletedTask;
                }

                // Access tokens are bound to the DPoP proof key when a valid proof was sent
                // or to the TLS client certificate when mTLS token binding is enabled.
                if (context.Transaction.DPoPProofPrincipal is not null ||
                   (context.Options.UseClientCertificateBoundAccessTokens && context.Transaction.RemoteCertificate is not null))
                {
                    return ValueTask.CompletedTask;
                }

                context.Logger.LogInformation(6760, SR.GetResourceString(SR.ID6760), SR.GetResourceString(SR.ID2483));

                context.Reject(
                    // When DPoP is the only sender-constraining mechanism available, return the standard DPoP error.
                    error: context.Options.EnableDPoPSupport && !context.Options.UseClientCertificateBoundAccessTokens
                        ? Errors.InvalidDPoPProof
                        : Errors.InvalidRequest,
                    description: SR.GetResourceString(SR.ID2483),
                    uri: SR.FormatID8000(SR.ID2483));

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting pushed authorization requests that don't include
        /// a redirect_uri or use a non-loopback http redirect_uri (section 5.3.2.2, items 6 and 8).
        /// </summary>
        public sealed class ValidatePushedRedirectUri : IOpenIddictServerHandler<ValidatePushedAuthorizationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidatePushedAuthorizationRequestContext>()
                    .AddFilter<RequireFapi2SecurityProfileEnabled>()
                    .UseSingletonHandler<ValidatePushedRedirectUri>()
                    .SetOrder(Authentication.ValidatePushedRedirectUriParameter.Descriptor.Order + 250)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidatePushedAuthorizationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (string.IsNullOrEmpty(context.RedirectUri))
                {
                    context.Logger.LogInformation(6760, SR.GetResourceString(SR.ID6760), SR.FormatID2029(Parameters.RedirectUri));

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2029(Parameters.RedirectUri),
                        uri: SR.FormatID8000(SR.ID2029));

                    return ValueTask.CompletedTask;
                }

                // Note: the redirect_uri was already validated as an absolute URI at this stage.
                if (Uri.TryCreate(context.RedirectUri, UriKind.Absolute, out Uri? uri) &&
                    string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) && !uri.IsLoopback)
                {
                    context.Logger.LogInformation(6760, SR.GetResourceString(SR.ID6760), SR.FormatID2484(Parameters.RedirectUri));

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2484(Parameters.RedirectUri),
                        uri: SR.FormatID8000(SR.ID2484));

                    return ValueTask.CompletedTask;
                }

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for restricting the algorithms allowed for client assertions
        /// and request objects to the algorithms allowed by the FAPI 2.0 security profile (section 5.4.1).
        /// </summary>
        public sealed class RestrictClientTokenSigningAlgorithms : IOpenIddictServerHandler<ValidateTokenContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .AddFilter<RequireFapi2SecurityProfileEnabled>()
                    .UseSingletonHandler<RestrictClientTokenSigningAlgorithms>()
                    .SetOrder(Protection.ResolveTokenValidationParameters.Descriptor.Order + 250)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateTokenContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (!IsClientToken(context) || context.TokenValidationParameters is null)
                {
                    return ValueTask.CompletedTask;
                }

                context.TokenValidationParameters.ValidAlgorithms = OpenIddictServerFapi2Profile.SigningAlgorithms;

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting client assertions whose audience is not a single string
        /// (section 5.3.2.1, item 8) and client assertions and request objects whose "iat" or "nbf"
        /// claims represent a date more than 60 seconds in the future (section 5.3.2.1, item 13).
        /// </summary>
        public sealed class ValidateClientTokenDates : IOpenIddictServerHandler<ValidateTokenContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .AddFilter<RequireFapi2SecurityProfileEnabled>()
                    .UseSingletonHandler<ValidateClientTokenDates>()
                    .SetOrder(Protection.ValidateIdentityModelToken.Descriptor.Order + 250)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateTokenContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (!IsClientToken(context) || context.Principal is null)
                {
                    return ValueTask.CompletedTask;
                }

                // The authorization server "shall only accept its issuer identifier value [...] as a string
                // in the aud claim received in client authentication assertions" (section 5.3.2.1, item 8).
                //
                // Note: since IdentityModel flattens single-value arrays when creating the claims identity,
                // the JSON type of the "aud" claim is determined using the raw payload of the token, if readable.
                if (context.ValidTokenTypes.Contains(TokenTypeIdentifiers.Private.ClientAssertion) &&
                    !HasSingleStringAudience(context))
                {
                    context.Logger.LogInformation(6760, SR.GetResourceString(SR.ID6760), SR.GetResourceString(SR.ID2481));

                    context.Reject(
                        error: Errors.InvalidClient,
                        description: SR.GetResourceString(SR.ID2481),
                        uri: SR.FormatID8000(SR.ID2481));

                    return ValueTask.CompletedTask;
                }

                var limit = (context.Options.TimeProvider.GetUtcNow() + OpenIddictServerFapi2Profile.MaximumFutureDateOffset).ToUnixTimeSeconds();

                foreach (var name in (string[]) [Claims.IssuedAt, Claims.NotBefore])
                {
                    if (!double.TryParse(context.Principal.GetClaim(name), NumberStyles.Float, CultureInfo.InvariantCulture, out var value) || value <= limit)
                    {
                        continue;
                    }

                    context.Logger.LogInformation(6760, SR.GetResourceString(SR.ID6760), SR.FormatID2485(name));

                    context.Reject(
                        error: context.ValidTokenTypes.Contains(TokenTypeIdentifiers.Private.ClientAssertion)
                            ? Errors.InvalidClient
                            : Errors.InvalidRequestObject,
                        description: SR.FormatID2485(name),
                        uri: SR.FormatID8000(SR.ID2485));

                    return ValueTask.CompletedTask;
                }

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for ensuring authorization codes don't
        /// expire after more than 60 seconds (section 5.3.2.1, item 11), even when
        /// a longer lifetime was attached to the principal or to the client settings.
        /// </summary>
        public sealed class LimitAuthorizationCodeLifetime : IOpenIddictServerHandler<ProcessSignInContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireFapi2SecurityProfileEnabled>()
                    .AddFilter<RequireAuthorizationCodeGenerated>()
                    .UseSingletonHandler<LimitAuthorizationCodeLifetime>()
                    .SetOrder(PrepareAuthorizationCodePrincipal.Descriptor.Order + 250)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessSignInContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                Limit(context.AuthorizationCodePrincipal,
                    OpenIddictServerFapi2Profile.MaximumAuthorizationCodeLifetime, inclusive: true,
                    context.Options.AuthorizationCodeLifetime ?? OpenIddictServerFapi2Profile.MaximumAuthorizationCodeLifetime);

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for ensuring request tokens returned by the pushed authorization
        /// endpoint expire in less than 600 seconds (section 5.3.2.2, item 12), even when a longer
        /// lifetime was attached to the principal or to the client settings.
        /// </summary>
        public sealed class LimitPushedAuthorizationRequestLifetime : IOpenIddictServerHandler<ProcessSignInContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                    .AddFilter<RequireFapi2SecurityProfileEnabled>()
                    .AddFilter<RequireRequestTokenGenerated>()
                    .UseSingletonHandler<LimitPushedAuthorizationRequestLifetime>()
                    .SetOrder(PrepareRequestTokenPrincipal.Descriptor.Order + 250)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessSignInContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (context.EndpointType is OpenIddictServerEndpointType.PushedAuthorization)
                {
                    Limit(context.RequestTokenPrincipal,
                        OpenIddictServerFapi2Profile.MaximumRequestUriLifetime, inclusive: false,
                        context.Options.RequestTokenLifetime ?? OpenIddictServerFapi2Profile.DefaultRequestUriLifetime);
                }

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for restricting the request object signing algorithms
        /// returned in the discovery document to the algorithms allowed by the FAPI 2.0 security profile.
        /// </summary>
        public sealed class RestrictRequestObjectSigningAlgorithms : IOpenIddictServerHandler<HandleConfigurationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                    .AddFilter<RequireFapi2SecurityProfileEnabled>()
                    .UseSingletonHandler<RestrictRequestObjectSigningAlgorithms>()
                    .SetOrder(Discovery.AttachAdditionalMetadata.Descriptor.Order + 250)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (context.Metadata.ContainsKey(Metadata.RequestObjectSigningAlgValuesSupported))
                {
                    // Note: EdDSA is not natively supported by IdentityModel and is not returned.
                    context.Metadata[Metadata.RequestObjectSigningAlgValuesSupported] = new JsonArray(
                        SecurityAlgorithms.RsaSsaPssSha256, SecurityAlgorithms.EcdsaSha256);
                }

                return ValueTask.CompletedTask;
            }
        }

        private static bool IsClientToken(ValidateTokenContext context)
            => context.ValidTokenTypes.Count is 1 &&
              (context.ValidTokenTypes.Contains(TokenTypeIdentifiers.Private.ClientAssertion) ||
               context.ValidTokenTypes.Contains(TokenTypeIdentifiers.Private.RequestObject));

        private static bool HasSingleStringAudience(ValidateTokenContext context)
        {
            if (context.Principal is null ||
                context.Principal.Claims.Count(static claim => claim.Type is Claims.Audience) is not 1)
            {
                return false;
            }

            // Note: the payload of encrypted tokens cannot be read without decrypting them. In this
            // case, the single "aud" claim extracted by IdentityModel is considered sufficient.
            if (string.IsNullOrEmpty(context.Token) || !context.SecurityTokenHandler.CanReadToken(context.Token))
            {
                return true;
            }

            var token = context.SecurityTokenHandler.ReadJsonWebToken(context.Token);
            if (!string.IsNullOrEmpty(token.Enc))
            {
                return true;
            }

            try
            {
                using var document = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(token.EncodedPayload));

                return document.RootElement.ValueKind is JsonValueKind.Object &&
                       document.RootElement.TryGetProperty(Claims.Audience, out JsonElement audience) &&
                       audience.ValueKind is JsonValueKind.String;
            }

            catch (Exception exception) when (exception is JsonException or FormatException or ArgumentException)
            {
                return false;
            }
        }

        private static void Limit(ClaimsPrincipal? principal, TimeSpan maximum, bool inclusive, TimeSpan fallback)
        {
            if (principal?.GetCreationDate() is not DateTimeOffset creation)
            {
                return;
            }

            var lifetime = principal.GetExpirationDate() - creation;
            if (lifetime is TimeSpan value && (inclusive ? value <= maximum : value < maximum))
            {
                return;
            }

            principal.SetExpirationDate(creation + fallback);
        }
    }
}
