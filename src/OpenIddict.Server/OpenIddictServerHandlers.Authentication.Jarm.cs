/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Server;

public static partial class OpenIddictServerHandlers
{
    public static partial class Authentication
    {
        /// <summary>
        /// Contains the logic responsible for rejecting authorization requests made by applications for which
        /// JWT Secured Authorization Response Modes (JARM) are enforced and for rejecting requests that use
        /// response_mode=query.jwt with a response_type containing id_token or token when the JWT is not encrypted.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public sealed class ValidateJwtSecuredAuthorizationResponsesRequirement : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateAuthorizationRequestContext>()
                    // Note: unlike the other JARM handlers, this handler is deliberately not filtered by
                    // RequireJwtSecuredAuthorizationResponsesEnabled so that the per-client requirement
                    // fails closed (i.e plain responses are rejected) even if JARM support is disabled.
                    .AddFilter<RequireDegradedModeDisabled>()
                    .UseSingletonHandler<ValidateJwtSecuredAuthorizationResponsesRequirement>()
                    .SetOrder(ValidateSignedRequestObjectsRequirement.Descriptor.Order + 250)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

                var (error, description, uri) = await ValidateJwtSecuredAuthorizationResponsesRequirementAsync(
                    context.Request, context.ClientId, context.ServiceProvider, context.CancellationToken);

                if (error is { Length: > 0 })
                {
                    context.Logger.LogInformation(6442, SR.GetResourceString(SR.ID6442),
                        context.Request.ResponseType, context.Request.ResponseMode);

                    context.Reject(error, description, uri);

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for generating the JWT containing the authorization response parameters and
        /// replacing them by the "response" parameter when a JWT Secured Authorization Response Mode (JARM) is used.
        /// </summary>
        public sealed class GenerateAuthorizationResponseToken : IOpenIddictServerHandler<ApplyAuthorizationResponseContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public GenerateAuthorizationResponseToken(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyAuthorizationResponseContext>()
                    .AddFilter<RequireJwtSecuredAuthorizationResponsesEnabled>()
                    .UseSingletonHandler<GenerateAuthorizationResponseToken>()
                    // Note: this handler is deliberately executed as late as possible (just before the host handlers
                    // responsible for applying the response, whose order starts at 250_000) so that the parameters added
                    // by custom handlers are also included in the generated token. Parameters added by handlers whose
                    // order is 249_000 or higher are not protected by the JWT and are ignored by conforming clients.
                    .SetOrder(249_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ApplyAuthorizationResponseContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                // Only generate a token if the user agent is expected to be redirected to the client application
                // using a JWT response mode and if the response was not already wrapped by another handler.
                if (context.Request is null || string.IsNullOrEmpty(context.RedirectUri) ||
                    context.ResponseMode is not (ResponseModes.QueryJwt or ResponseModes.FragmentJwt or ResponseModes.FormPostJwt) ||
                    context.Response.HasParameter(Parameters.Response))
                {
                    return;
                }

                // Note: the "aud" claim MUST contain the client identifier of the client application.
                if (string.IsNullOrEmpty(context.Request.ClientId))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0642));
                }

                var date = context.Options.TimeProvider.GetUtcNow();

                // As required by the JARM specification, the JWT MUST contain the "iss", "aud" and "exp" claims.
                //
                // See https://openid.net/specs/oauth-v2-jarm.html#section-2.1 for more information.
                var principal = new ClaimsPrincipal(new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType))
                    .SetCreationDate(date)
                    .SetExpirationDate(date + context.Options.AuthorizationResponseLifetime)
                    .SetAudiences(context.Request.ClientId)
                    .SetClaim(Claims.Private.Issuer, (context.Options.Issuer ?? context.BaseUri) switch
                    {
                        { IsAbsoluteUri: true } uri => uri.AbsoluteUri,

                        // Throw an exception if the issuer cannot be retrieved or is not valid.
                        _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0496))
                    });

                var notification = new GenerateTokenContext(context.Transaction)
                {
                    ClientId = context.Request.ClientId,
                    CreateTokenEntry = false,
                    IsReferenceToken = false,
                    PersistTokenPayload = false,
                    Principal = principal,
                    TokenFormat = TokenFormats.Private.JsonWebToken,
                    TokenType = TokenTypeIdentifiers.Private.AuthorizationResponse
                };

                // Attach all the authorization response parameters (including errors) as top-level JSON claims.
                notification.SecurityTokenDescriptor.Claims = CreateResponseClaims(context.Response);

                await _dispatcher.DispatchAsync(notification);

                if (notification.IsRejected || string.IsNullOrEmpty(notification.Token))
                {
                    throw new InvalidOperationException(SR.FormatID0643(
                        notification.Error, notification.ErrorDescription, notification.ErrorUri));
                }

                context.Logger.LogInformation(6443, SR.GetResourceString(SR.ID6443), context.ResponseMode, context.Request.ClientId);

                // Replace the response parameters by the single "response" parameter.
                foreach (var name in context.Response.GetParameters().Select(static parameter => parameter.Key).ToList())
                {
                    context.Response.RemoveParameter(name);
                }

                context.Response[Parameters.Response] = notification.Token;

                static Dictionary<string, object> CreateResponseClaims(OpenIddictResponse response)
                {
                    using var stream = new MemoryStream();
                    using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
                    {
                        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                        Indented = false
                    }))
                    {
                        response.WriteTo(writer);
                    }

                    using var document = JsonDocument.Parse(stream.ToArray());

                    var claims = new Dictionary<string, object>(StringComparer.Ordinal);

                    foreach (var property in document.RootElement.EnumerateObject())
                    {
                        // Note: the registered JWT claims are set by the token generation pipeline and the
                        // "iss" parameter (RFC 9207) is represented by the "iss" claim of the JWT itself.
                        if (property.Name is Claims.Audience or Claims.ExpiresAt or Claims.IssuedAt or
                                             Claims.Issuer   or Claims.NotBefore)
                        {
                            continue;
                        }

                        claims[property.Name] = property.Value.Clone();
                    }

                    return claims;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for resolving the signing algorithm and the encryption credentials used to protect
        /// JWT authorization responses (JARM) from the settings and JSON Web Key Set of the client application, if applicable.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public sealed class AttachAuthorizationResponseSecurityCredentials : IOpenIddictServerHandler<GenerateTokenContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<GenerateTokenContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireJwtSecuredAuthorizationResponsesEnabled>()
                    .UseSingletonHandler<AttachAuthorizationResponseSecurityCredentials>()
                    .SetOrder(Protection.AttachSecurityCredentials.Descriptor.Order + 600)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(GenerateTokenContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (context.TokenType is not TokenTypeIdentifiers.Private.AuthorizationResponse || string.IsNullOrEmpty(context.ClientId))
                {
                    return;
                }

                var manager = context.ServiceProvider.GetService<IOpenIddictApplicationManager>()
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

                var application = await manager.FindByClientIdAsync(context.ClientId, context.CancellationToken)
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0017));

                var settings = await manager.GetSettingsAsync(application, context.CancellationToken);

                // If the client application registered a specific signing algorithm (the equivalent of the
                // "authorization_signed_response_alg" client metadata), use the first asymmetric signing
                // credentials matching this algorithm. An exception is thrown if no such credentials exist.
                //
                // See https://openid.net/specs/oauth-v2-jarm.html#section-3 for more information.
                if (settings.TryGetValue(Settings.AuthorizationResponse.SigningAlgorithm, out string? algorithm) &&
                    !string.IsNullOrEmpty(algorithm))
                {
                    var credentials = await OpenIddictServerKeyRing.ResolveCredentialsAsync(context.Transaction);

                    // Note: the algorithms advertised in the discovery document are JWA short names, so the
                    // algorithm attached to the signing credentials (that can be expressed using the XML-DSig
                    // form, e.g "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256") is normalized first.
                    context.SigningCredentials = NormalizeSigningCredentials(credentials.SigningCredentials.FirstOrDefault(credentials =>
                        credentials.Key is AsymmetricSecurityKey &&
                        string.Equals(GetJwaSigningAlgorithm(credentials.Algorithm), algorithm, StringComparison.Ordinal))
                        ?? throw new InvalidOperationException(SR.FormatID0644(algorithm, Settings.AuthorizationResponse.SigningAlgorithm)));
                }

                // Note: JWT authorization responses are only encrypted if the client application explicitly opted in
                // (the equivalent of the "authorization_encrypted_response_alg" client metadata).
                //
                // See https://openid.net/specs/oauth-v2-jarm.html#section-3 for more information.
                if (!settings.TryGetValue(Settings.AuthorizationResponse.EncryptionAlgorithm, out algorithm) ||
                    string.IsNullOrEmpty(algorithm))
                {
                    return;
                }

                if (!string.Equals(algorithm, SecurityAlgorithms.RsaOAEP, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(SR.FormatID0645(algorithm, Settings.AuthorizationResponse.EncryptionAlgorithm));
                }

                // If no content encryption algorithm was explicitly set, use A128CBC-HS256 (the default value defined by JARM).
                var method = settings.TryGetValue(Settings.AuthorizationResponse.EncryptionMethod, out string? value) &&
                    !string.IsNullOrEmpty(value) ? value : SecurityAlgorithms.Aes128CbcHmacSha256;

                if (method is not (SecurityAlgorithms.Aes128CbcHmacSha256 or SecurityAlgorithms.Aes256CbcHmacSha512))
                {
                    throw new InvalidOperationException(SR.FormatID0645(method, Settings.AuthorizationResponse.EncryptionMethod));
                }

                // Note: only RSA keys explicitly registered for encryption can be used. Since the client application
                // opted in for encrypted responses, an exception is thrown if no suitable key can be found to ensure
                // the authorization response is never returned unencrypted.
                var key = (await manager.GetJsonWebKeySetAsync(application, context.CancellationToken))?.Keys.FirstOrDefault(static key =>
                    string.Equals(key.Use, JsonWebKeyUseNames.Enc, StringComparison.Ordinal) &&
                    string.Equals(key.Kty, JsonWebAlgorithmsKeyTypes.RSA, StringComparison.Ordinal) &&
                    (string.IsNullOrEmpty(key.Alg) || string.Equals(key.Alg, SecurityAlgorithms.RsaOAEP, StringComparison.Ordinal)))
                    ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0646));

                context.EncryptionCredentials = new EncryptingCredentials(key, SecurityAlgorithms.RsaOAEP, method);
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting pushed authorization requests made by applications for which
        /// JWT Secured Authorization Response Modes (JARM) are enforced and for rejecting requests that use
        /// response_mode=query.jwt with a response_type containing id_token or token when the JWT is not encrypted.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public sealed class ValidatePushedJwtSecuredAuthorizationResponsesRequirement : IOpenIddictServerHandler<ValidatePushedAuthorizationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidatePushedAuthorizationRequestContext>()
                    // Note: this handler is deliberately not filtered by RequireJwtSecuredAuthorizationResponsesEnabled
                    // so that the per-client requirement fails closed even if JARM support is disabled.
                    .AddFilter<RequireDegradedModeDisabled>()
                    .UseSingletonHandler<ValidatePushedJwtSecuredAuthorizationResponsesRequirement>()
                    .SetOrder(ValidatePushedSignedRequestObjectsRequirement.Descriptor.Order + 250)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidatePushedAuthorizationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

                var (error, description, uri) = await ValidateJwtSecuredAuthorizationResponsesRequirementAsync(
                    context.Request, context.ClientId, context.ServiceProvider, context.CancellationToken);

                if (error is { Length: > 0 })
                {
                    context.Logger.LogInformation(6444, SR.GetResourceString(SR.ID6444),
                        context.Request.ResponseType, context.Request.ResponseMode);

                    context.Reject(error, description, uri);

                    return;
                }
            }
        }

        /// <summary>
        /// Resolves the JWA short name (RFC 7518, section 3.1) corresponding to the specified signing algorithm,
        /// which can be expressed using either the JWA or the XML-DSig form. The algorithm is returned as-is if
        /// no mapping exists.
        /// </summary>
        internal static string? GetJwaSigningAlgorithm(string? algorithm) => algorithm switch
        {
            SecurityAlgorithms.EcdsaSha256Signature     => SecurityAlgorithms.EcdsaSha256,
            SecurityAlgorithms.EcdsaSha384Signature     => SecurityAlgorithms.EcdsaSha384,
            SecurityAlgorithms.EcdsaSha512Signature     => SecurityAlgorithms.EcdsaSha512,
            SecurityAlgorithms.RsaSha256Signature       => SecurityAlgorithms.RsaSha256,
            SecurityAlgorithms.RsaSha384Signature       => SecurityAlgorithms.RsaSha384,
            SecurityAlgorithms.RsaSha512Signature       => SecurityAlgorithms.RsaSha512,
            SecurityAlgorithms.RsaSsaPssSha256Signature => SecurityAlgorithms.RsaSsaPssSha256,
            SecurityAlgorithms.RsaSsaPssSha384Signature => SecurityAlgorithms.RsaSsaPssSha384,
            SecurityAlgorithms.RsaSsaPssSha512Signature => SecurityAlgorithms.RsaSsaPssSha512,

            _ => algorithm
        };

        /// <summary>
        /// Returns signing credentials whose algorithm is expressed using its JWA short name (RFC 7518, section 3.1),
        /// so that the "alg" header of the generated JWT is a registered value (RFC 7515, section 4.1.1).
        /// The specified credentials are returned as-is if they already use a JWA algorithm name.
        /// </summary>
        internal static SigningCredentials NormalizeSigningCredentials(SigningCredentials credentials)
        {
            var algorithm = GetJwaSigningAlgorithm(credentials.Algorithm);
            if (string.Equals(algorithm, credentials.Algorithm, StringComparison.Ordinal))
            {
                return credentials;
            }

            return new SigningCredentials(credentials.Key, algorithm)
            {
                CryptoProviderFactory = credentials.CryptoProviderFactory
            };
        }

        /// <summary>
        /// Determines whether the JWT response mode specified in the request is enabled.
        /// </summary>
        private static bool ValidateJwtResponseMode(OpenIddictRequest request, OpenIddictServerOptions options)
        {
            Debug.Assert(request.IsJwtResponseMode(), SR.GetResourceString(SR.ID4120));

            if (!options.EnableJwtSecuredAuthorizationResponses)
            {
                return false;
            }

            // Note: the JWT variants are only considered enabled if the corresponding base response mode is enabled.
            return (request.ResponseMode is ResponseModes.Jwt ? ResolveJwtResponseMode(request) : request.ResponseMode) switch
            {
                ResponseModes.QueryJwt    => options.ResponseModes.Contains(ResponseModes.Query),
                ResponseModes.FragmentJwt => options.ResponseModes.Contains(ResponseModes.Fragment),
                ResponseModes.FormPostJwt => options.ResponseModes.Contains(ResponseModes.FormPost),

                _ => false
            };
        }

        /// <summary>
        /// Determines whether the request satisfies the global JARM requirement, if enforced.
        /// </summary>
        private static bool ValidateJwtResponseModeRequirement(OpenIddictRequest request, OpenIddictServerOptions options)
            => !options.RequireJwtSecuredAuthorizationResponses || request.IsJwtResponseMode();

        /// <summary>
        /// Determines whether the request uses response_mode=query.jwt (explicitly or inferred from "jwt")
        /// with a response_type containing id_token or token, which is only allowed if the JWT is encrypted.
        /// See https://openid.net/specs/oauth-v2-jarm.html#section-2.3.1 for more information.
        /// </summary>
        private static bool IsUnencryptedQueryJwtCombinationCandidate(OpenIddictRequest request)
            => request.ResponseMode is ResponseModes.QueryJwt &&
               (request.HasResponseType(ResponseTypes.IdToken) || request.HasResponseType(ResponseTypes.Token));

        /// <summary>
        /// Resolves the JWT response mode corresponding to response_mode=jwt for the specified request.
        /// See https://openid.net/specs/oauth-v2-jarm.html#section-2.3.4 for more information.
        /// </summary>
        private static string ResolveJwtResponseMode(OpenIddictRequest request)
            => request.HasResponseType(ResponseTypes.IdToken) || request.HasResponseType(ResponseTypes.Token)
                ? ResponseModes.FragmentJwt : ResponseModes.QueryJwt;

        /// <summary>
        /// Validates the per-client JARM requirement and the query.jwt encryption requirement.
        /// </summary>
        private static async ValueTask<(string? Error, string? Description, string? Uri)> ValidateJwtSecuredAuthorizationResponsesRequirementAsync(
            OpenIddictRequest request, string clientId, IServiceProvider provider, CancellationToken cancellationToken)
        {
            var jwt = request.IsJwtResponseMode();
            if (jwt && !IsUnencryptedQueryJwtCombinationCandidate(request))
            {
                return default;
            }

            var manager = provider.GetService<IOpenIddictApplicationManager>()
                ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            var application = await manager.FindByClientIdAsync(clientId, cancellationToken)
                ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0032));

            if (!jwt)
            {
                return await manager.HasRequirementAsync(application, Requirements.Features.JwtSecuredAuthorizationResponses, cancellationToken)
                    ? (Errors.InvalidRequest, SR.FormatID2320(Parameters.ResponseMode), SR.FormatID8000(SR.ID2320))
                    : default;
            }

            // Note: response_mode=query.jwt MUST NOT be used with a response_type containing id_token
            // or token unless the response JWT is encrypted (i.e the client application opted in).
            //
            // See https://openid.net/specs/oauth-v2-jarm.html#section-2.3.1 for more information.
            var settings = await manager.GetSettingsAsync(application, cancellationToken);
            if (!settings.TryGetValue(Settings.AuthorizationResponse.EncryptionAlgorithm, out string? algorithm) ||
                string.IsNullOrEmpty(algorithm))
            {
                return (Errors.InvalidRequest, SR.FormatID2033(Parameters.ResponseType, Parameters.ResponseMode), SR.FormatID8000(SR.ID2033));
            }

            return default;
        }
    }
}
