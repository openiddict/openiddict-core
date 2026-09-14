/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Client;

public static partial class OpenIddictClientHandlers
{
    /// <summary>
    /// Contains the logic responsible for replacing the negotiated response mode by its JWT Secured
    /// Authorization Response Mode (JARM) variant when required by the client registration.
    /// </summary>
    public sealed class AttachJwtResponseMode : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireInteractiveGrantType>()
                .UseSingletonHandler<AttachJwtResponseMode>()
                .SetOrder(AttachResponseMode.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            if (!context.Registration.RequireJwtSecuredAuthorizationResponses)
            {
                return ValueTask.CompletedTask;
            }

            // See https://openid.net/specs/oauth-v2-jarm.html#section-2.3 for more information.
            var mode = context.ResponseMode switch
            {
                ResponseModes.Query    => ResponseModes.QueryJwt,
                ResponseModes.Fragment => ResponseModes.FragmentJwt,
                ResponseModes.FormPost => ResponseModes.FormPostJwt,

                ResponseModes.Jwt or ResponseModes.QueryJwt or
                ResponseModes.FragmentJwt or ResponseModes.FormPostJwt => context.ResponseMode,

                _ => throw new InvalidOperationException(SR.FormatID0647(context.ResponseMode))
            };

            // If the server explicitly lists the supported response modes, ensure the JWT variant is supported.
            if (context.Configuration.ResponseModesSupported.Count is > 0 &&
               !context.Configuration.ResponseModesSupported.Contains(mode))
            {
                throw new InvalidOperationException(SR.FormatID0647(mode));
            }

            context.ResponseMode = mode;

            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Contains the logic responsible for extracting the JWT authorization response (JARM) from the
    /// "response" parameter and resolving the state token it contains, so that the state token
    /// (and the client registration it identifies) can be resolved and validated.
    /// </summary>
    public sealed class ResolveAuthorizationResponseToken : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireRedirectionRequest>()
                .UseSingletonHandler<ResolveAuthorizationResponseToken>()
                .SetOrder(ResolveValidatedStateToken.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            var token = (string?) context.Request[Parameters.Response];
            if (string.IsNullOrEmpty(token))
            {
                return ValueTask.CompletedTask;
            }

            context.AuthorizationResponseToken = token;

            // Note: when JARM is used, the "state" parameter is only present in the JWT. Since the JWT can only
            // be validated once the client registration is known (which is identified by the state token), the
            // state is extracted without validating the JWT at this stage. This is safe as the state token is
            // self-protected and bound to the user agent, and the JWT is fully validated later in the pipeline
            // (at which point its "state" claim is also compared to the state token that was resolved here).
            if (context.ExtractStateToken && string.IsNullOrEmpty(context.StateToken))
            {
                context.StateToken = ReadUnvalidatedState(context, token);
            }

            return ValueTask.CompletedTask;

            static string? ReadUnvalidatedState(ProcessAuthenticationContext context, string token)
            {
                try
                {
                    var handler = context.Options.JsonWebTokenHandler;
                    if (!handler.CanReadToken(token))
                    {
                        return null;
                    }

                    var jwt = new JsonWebToken(token);
                    if (jwt.IsEncrypted)
                    {
                        jwt = new JsonWebToken(handler.DecryptToken(jwt, context.Options.TokenValidationParameters));
                    }

                    return jwt.TryGetPayloadValue(Parameters.State, out string? state) ? state : null;
                }

                catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
                {
                    context.Logger.LogTrace(6000, exception, SR.GetResourceString(SR.ID6000), token);

                    return null;
                }
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the JWT authorization response (JARM) and replacing
    /// the authorization response parameters by the parameters extracted from the validated JWT.
    /// </summary>
    public sealed class ValidateAuthorizationResponseToken : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly IOpenIddictClientDispatcher _dispatcher;

        public ValidateAuthorizationResponseToken(IOpenIddictClientDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireRedirectionRequest>()
                .AddFilter<RequireStateTokenPrincipal>()
                .UseSingletonHandler<ValidateAuthorizationResponseToken>()
                .SetOrder(ResolveClientRegistrationFromStateToken.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            ArgumentNullException.ThrowIfNull(context);

            Debug.Assert(context.StateTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            if (string.IsNullOrEmpty(context.AuthorizationResponseToken))
            {
                // Reject plain authorization responses if a JWT response mode was used for the authorization
                // request (or is required by the client registration) to prevent downgrade attacks.
                if (context.Registration.RequireJwtSecuredAuthorizationResponses ||
                    context.StateTokenPrincipal.GetClaim(Claims.Private.ResponseMode) is
                        ResponseModes.Jwt or ResponseModes.QueryJwt or ResponseModes.FragmentJwt or ResponseModes.FormPostJwt)
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.GetResourceString(SR.ID2321),
                        uri: SR.FormatID8000(SR.ID2321));
                }

                return;
            }

            var notification = new ValidateTokenContext(context.Transaction)
            {
                // Note: the audience is manually validated below, as it is represented by the client identifier.
                DisableAudienceValidation = true,
                DisablePresenterValidation = true,
                Token = context.AuthorizationResponseToken,
                TokenFormat = TokenFormats.Private.JsonWebToken,
                ValidTokenTypes = { TokenTypeIdentifiers.Private.AuthorizationResponse }
            };

            await _dispatcher.DispatchAsync(notification);

            if (notification.IsRequestHandled)
            {
                context.HandleRequest();
                return;
            }

            if (notification.IsRequestSkipped)
            {
                context.SkipRequest();
                return;
            }

            if (notification.IsRejected || notification.Principal is not ClaimsPrincipal principal ||
                notification.TokenValidationResult?.SecurityToken is not JsonWebToken token)
            {
                Reject(SR.GetResourceString(SR.ID2322), SR.ID2322, notification.Error, notification.ErrorDescription);
                return;
            }

            if (token.InnerToken is not null)
            {
                token = token.InnerToken;
            }

            // Ensure the JWT was signed using the algorithm registered for the client (the equivalent of the
            // "authorization_signed_response_alg" client metadata) or, if no algorithm was explicitly set,
            // using one of the algorithms advertised by the server in "authorization_signing_alg_values_supported".
            //
            // See https://openid.net/specs/oauth-v2-jarm.html#section-2.4 for more information.
            if (!string.IsNullOrEmpty(context.Registration.AuthorizationResponseSigningAlgorithm)
                ? !string.Equals(token.Alg, context.Registration.AuthorizationResponseSigningAlgorithm, StringComparison.Ordinal)
                : context.Configuration.AuthorizationSigningAlgValuesSupported.Count is > 0 &&
                 !context.Configuration.AuthorizationSigningAlgValuesSupported.Contains(token.Alg))
            {
                Reject(SR.GetResourceString(SR.ID2325), SR.ID2325);
                return;
            }

            // As required by the JARM specification, the "iss" claim MUST match the expected issuer,
            // the "aud" claim MUST contain the client identifier and the "exp" claim MUST be present
            // and the JWT MUST NOT be expired.
            //
            // See https://openid.net/specs/oauth-v2-jarm.html#section-2.4 for more information.
            if (!token.TryGetPayloadValue(Claims.Issuer, out string? issuer) || string.IsNullOrEmpty(issuer))
            {
                Reject(SR.FormatID2324(Claims.Issuer), SR.ID2324);
                return;
            }

            if (!Uri.TryCreate(issuer, UriKind.Absolute, out Uri? uri) || uri != context.Registration.Issuer)
            {
                Reject(SR.GetResourceString(SR.ID2322), SR.ID2322);
                return;
            }

            if (string.IsNullOrEmpty(context.Registration.ClientId) ||
                !token.Audiences.Contains(context.Registration.ClientId, StringComparer.Ordinal))
            {
                Reject(SR.GetResourceString(SR.ID2323), SR.ID2323);
                return;
            }

            if (!token.TryGetPayloadValue(Claims.ExpiresAt, out long expiration))
            {
                Reject(SR.FormatID2324(Claims.ExpiresAt), SR.ID2324);
                return;
            }

            if (DateTimeOffset.FromUnixTimeSeconds(expiration) + context.Registration.TokenValidationParameters.ClockSkew <
                context.Options.TimeProvider.GetUtcNow())
            {
                Reject(SR.GetResourceString(SR.ID2322), SR.ID2322);
                return;
            }

            // Ensure the state contained in the JWT matches the state token that was resolved and validated.
            if (!token.TryGetPayloadValue(Parameters.State, out string? state) ||
                !string.Equals(state, context.StateToken, StringComparison.Ordinal))
            {
                Reject(SR.GetResourceString(SR.ID2322), SR.ID2322);
                return;
            }

            // Replace the parameters of the authorization response by the parameters extracted from the JWT.
            // Note: parameters sent outside of the JWT are deliberately discarded as they are not protected.
            foreach (var name in context.Request.GetParameters().Select(static parameter => parameter.Key).ToList())
            {
                context.Request.RemoveParameter(name);
            }

            using (var document = JsonDocument.Parse(Base64UrlEncoder.Decode(token.EncodedPayload)))
            {
                foreach (var property in document.RootElement.EnumerateObject())
                {
                    // Note: the registered JWT claims are not authorization response parameters. The "iss" claim
                    // is only kept if the server advertises support for the "iss" authorization response parameter
                    // (RFC 9207), which allows the issuer to be validated by the generic handler.
                    if (property.Name is Claims.Audience or Claims.ExpiresAt or Claims.IssuedAt or
                                         Claims.NotBefore or Claims.JwtId ||
                       (property.Name is Claims.Issuer && context.Configuration.AuthorizationResponseIssParameterSupported is not true))
                    {
                        continue;
                    }

                    context.Request.SetParameter(property.Name, new OpenIddictParameter(property.Value.Clone()));
                }
            }

            context.AuthorizationResponseTokenPrincipal = principal;

            void Reject(string description, string identifier, string? error = null, string? details = null)
            {
                context.Logger.LogInformation(6445, SR.GetResourceString(SR.ID6445), error ?? Errors.InvalidRequest, details ?? description);

                context.Reject(
                    error: Errors.InvalidRequest,
                    description: description,
                    uri: SR.FormatID8000(identifier));
            }
        }
    }
}