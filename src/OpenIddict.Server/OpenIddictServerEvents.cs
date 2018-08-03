/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;

namespace OpenIddict.Server
{
    /// <summary>
    /// Contains common events used by the OpenIddict server handler.
    /// </summary>
    public static class OpenIddictServerEvents
    {
        /// <summary>
        /// Represents an event called for each HTTP request to determine if
        /// it should be handled by the OpenID Connect server middleware.
        /// </summary>
        public sealed class MatchEndpoint : OpenIddictServerEvent<MatchEndpointContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="MatchEndpoint"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public MatchEndpoint([NotNull] MatchEndpointContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called for each request to the authorization endpoint to give the user code
        /// a chance to manually extract the authorization request from the ambient HTTP context.
        /// </summary>
        public sealed class ExtractAuthorizationRequest : OpenIddictServerEvent<ExtractAuthorizationRequestContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="ExtractAuthorizationRequest"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public ExtractAuthorizationRequest([NotNull] ExtractAuthorizationRequestContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called for each request to the configuration endpoint to give the user code
        /// a chance to manually extract the configuration request from the ambient HTTP context.
        /// </summary>
        public sealed class ExtractConfigurationRequest : OpenIddictServerEvent<ExtractConfigurationRequestContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="ExtractConfigurationRequest"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public ExtractConfigurationRequest([NotNull] ExtractConfigurationRequestContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called for each request to the cryptography endpoint to give the user code
        /// a chance to manually extract the cryptography request from the ambient HTTP context.
        /// </summary>

        public sealed class ExtractCryptographyRequest : OpenIddictServerEvent<ExtractCryptographyRequestContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="ExtractCryptographyRequest"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public ExtractCryptographyRequest([NotNull] ExtractCryptographyRequestContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called for each request to the introspection endpoint to give the user code
        /// a chance to manually extract the introspection request from the ambient HTTP context.
        /// </summary>
        public sealed class ExtractIntrospectionRequest : OpenIddictServerEvent<ExtractIntrospectionRequestContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="ExtractIntrospectionRequest"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public ExtractIntrospectionRequest([NotNull] ExtractIntrospectionRequestContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called for each request to the logout endpoint to give the user code
        /// a chance to manually extract the logout request from the ambient HTTP context.
        /// </summary>
        public sealed class ExtractLogoutRequest : OpenIddictServerEvent<ExtractLogoutRequestContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="ExtractLogoutRequest"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public ExtractLogoutRequest([NotNull] ExtractLogoutRequestContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called for each request to the revocation endpoint to give the user code
        /// a chance to manually extract the revocation request from the ambient HTTP context.
        /// </summary>
        public sealed class ExtractRevocationRequest : OpenIddictServerEvent<ExtractRevocationRequestContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="ExtractRevocationRequest"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public ExtractRevocationRequest([NotNull] ExtractRevocationRequestContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called for each request to the token endpoint to give the user code
        /// a chance to manually extract the token request from the ambient HTTP context.
        /// </summary>
        public sealed class ExtractTokenRequest : OpenIddictServerEvent<ExtractTokenRequestContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="ExtractTokenRequest"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public ExtractTokenRequest([NotNull] ExtractTokenRequestContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called for each request to the userinfo endpoint to give the user code
        /// a chance to manually extract the userinfo request from the ambient HTTP context.
        /// </summary>
        public sealed class ExtractUserinfoRequest : OpenIddictServerEvent<ExtractUserinfoRequestContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="ExtractUserinfoRequest"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public ExtractUserinfoRequest([NotNull] ExtractUserinfoRequestContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called for each request to the authorization endpoint
        /// to determine if the request is valid and should continue to be processed.
        /// </summary>
        public sealed class ValidateAuthorizationRequest : OpenIddictServerEvent<ValidateAuthorizationRequestContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="ValidateAuthorizationRequest"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public ValidateAuthorizationRequest([NotNull] ValidateAuthorizationRequestContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called for each request to the configuration endpoint
        /// to determine if the request is valid and should continue to be processed.
        /// </summary>
        public sealed class ValidateConfigurationRequest : OpenIddictServerEvent<ValidateConfigurationRequestContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="ValidateConfigurationRequest"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public ValidateConfigurationRequest([NotNull] ValidateConfigurationRequestContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called for each request to the cryptography endpoint
        /// to determine if the request is valid and should continue to be processed.
        /// </summary>
        public sealed class ValidateCryptographyRequest : OpenIddictServerEvent<ValidateCryptographyRequestContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="ValidateCryptographyRequest"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public ValidateCryptographyRequest([NotNull] ValidateCryptographyRequestContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called for each request to the introspection endpoint
        /// to determine if the request is valid and should continue to be processed.
        /// </summary>
        public sealed class ValidateIntrospectionRequest : OpenIddictServerEvent<ValidateIntrospectionRequestContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="ValidateIntrospectionRequest"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public ValidateIntrospectionRequest([NotNull] ValidateIntrospectionRequestContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called for each request to the logout endpoint
        /// to determine if the request is valid and should continue to be processed.
        /// </summary>
        public sealed class ValidateLogoutRequest : OpenIddictServerEvent<ValidateLogoutRequestContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="ValidateLogoutRequest"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public ValidateLogoutRequest([NotNull] ValidateLogoutRequestContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called for each request to the revocation endpoint
        /// to determine if the request is valid and should continue to be processed.
        /// </summary>
        public sealed class ValidateRevocationRequest : OpenIddictServerEvent<ValidateRevocationRequestContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="ValidateRevocationRequest"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public ValidateRevocationRequest([NotNull] ValidateRevocationRequestContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called for each request to the token endpoint
        /// to determine if the request is valid and should continue to be processed.
        /// </summary>
        public sealed class ValidateTokenRequest : OpenIddictServerEvent<ValidateTokenRequestContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="ValidateTokenRequest"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public ValidateTokenRequest([NotNull] ValidateTokenRequestContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called for each request to the userinfo endpoint
        /// to determine if the request is valid and should continue to be processed.
        /// </summary>
        public sealed class ValidateUserinfoRequest : OpenIddictServerEvent<ValidateUserinfoRequestContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="ValidateUserinfoRequest"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public ValidateUserinfoRequest([NotNull] ValidateUserinfoRequestContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called for each validated authorization request
        /// to allow the user code to decide how the request should be handled.
        /// </summary>
        public sealed class HandleAuthorizationRequest : OpenIddictServerEvent<HandleAuthorizationRequestContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="HandleAuthorizationRequest"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public HandleAuthorizationRequest([NotNull] HandleAuthorizationRequestContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called for each validated configuration request
        /// to allow the user code to decide how the request should be handled.
        /// </summary>
        public sealed class HandleConfigurationRequest : OpenIddictServerEvent<HandleConfigurationRequestContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="HandleConfigurationRequest"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public HandleConfigurationRequest([NotNull] HandleConfigurationRequestContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called for each validated cryptography request
        /// to allow the user code to decide how the request should be handled.
        /// </summary>
        public sealed class HandleCryptographyRequest : OpenIddictServerEvent<HandleCryptographyRequestContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="HandleCryptographyRequest"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public HandleCryptographyRequest([NotNull] HandleCryptographyRequestContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called for each validated introspection request
        /// to allow the user code to decide how the request should be handled.
        /// </summary>
        public sealed class HandleIntrospectionRequest : OpenIddictServerEvent<HandleIntrospectionRequestContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="HandleIntrospectionRequest"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public HandleIntrospectionRequest([NotNull] HandleIntrospectionRequestContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called for each validated logout request
        /// to allow the user code to decide how the request should be handled.
        /// </summary>
        public sealed class HandleLogoutRequest : OpenIddictServerEvent<HandleLogoutRequestContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="HandleLogoutRequest"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public HandleLogoutRequest([NotNull] HandleLogoutRequestContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called for each validated revocation request
        /// to allow the user code to decide how the request should be handled.
        /// </summary>
        public sealed class HandleRevocationRequest : OpenIddictServerEvent<HandleRevocationRequestContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="HandleRevocationRequest"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public HandleRevocationRequest([NotNull] HandleRevocationRequestContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called for each validated token request
        /// to allow the user code to decide how the request should be handled.
        /// </summary>
        public sealed class HandleTokenRequest : OpenIddictServerEvent<HandleTokenRequestContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="HandleTokenRequest"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public HandleTokenRequest([NotNull] HandleTokenRequestContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called for each validated userinfo request
        /// to allow the user code to decide how the request should be handled.
        /// </summary>
        public sealed class HandleUserinfoRequest : OpenIddictServerEvent<HandleUserinfoRequestContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="HandleUserinfoRequest"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public HandleUserinfoRequest([NotNull] HandleUserinfoRequestContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called when processing a challenge response.
        /// </summary>
        public sealed class ProcessChallengeResponse : OpenIddictServerEvent<ProcessChallengeResponseContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="ProcessChallengeResponse"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public ProcessChallengeResponse([NotNull] ProcessChallengeResponseContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called when processing a sign-in response.
        /// </summary>
        public sealed class ProcessSigninResponse : OpenIddictServerEvent<ProcessSigninResponseContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="ProcessSigninResponse"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public ProcessSigninResponse([NotNull] ProcessSigninResponseContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called when processing a sign-out response.
        /// </summary>
        public sealed class ProcessSignoutResponse : OpenIddictServerEvent<ProcessSignoutResponseContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="ProcessSignoutResponse"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public ProcessSignoutResponse([NotNull] ProcessSignoutResponseContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called before the authorization response is returned to the caller.
        /// </summary>
        public sealed class ApplyAuthorizationResponse : OpenIddictServerEvent<ApplyAuthorizationResponseContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="ApplyAuthorizationResponse"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public ApplyAuthorizationResponse([NotNull] ApplyAuthorizationResponseContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called before the configuration response is returned to the caller.
        /// </summary>
        public sealed class ApplyConfigurationResponse : OpenIddictServerEvent<ApplyConfigurationResponseContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="ApplyConfigurationResponse"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public ApplyConfigurationResponse([NotNull] ApplyConfigurationResponseContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called before the cryptography response is returned to the caller.
        /// </summary>
        public sealed class ApplyCryptographyResponse : OpenIddictServerEvent<ApplyCryptographyResponseContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="ApplyCryptographyResponse"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public ApplyCryptographyResponse([NotNull] ApplyCryptographyResponseContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called before the introspection response is returned to the caller.
        /// </summary>
        public sealed class ApplyIntrospectionResponse : OpenIddictServerEvent<ApplyIntrospectionResponseContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="ApplyIntrospectionResponse"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public ApplyIntrospectionResponse([NotNull] ApplyIntrospectionResponseContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called before the logout response is returned to the caller.
        /// </summary>
        public sealed class ApplyLogoutResponse : OpenIddictServerEvent<ApplyLogoutResponseContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="ApplyLogoutResponse"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public ApplyLogoutResponse([NotNull] ApplyLogoutResponseContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called before the revocation response is returned to the caller.
        /// </summary>
        public sealed class ApplyRevocationResponse : OpenIddictServerEvent<ApplyRevocationResponseContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="ApplyRevocationResponse"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public ApplyRevocationResponse([NotNull] ApplyRevocationResponseContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called before the token response is returned to the caller.
        /// </summary>
        public sealed class ApplyTokenResponse : OpenIddictServerEvent<ApplyTokenResponseContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="ApplyTokenResponse"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public ApplyTokenResponse([NotNull] ApplyTokenResponseContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called before the userinfo response is returned to the caller.
        /// </summary>
        public sealed class ApplyUserinfoResponse : OpenIddictServerEvent<ApplyUserinfoResponseContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="ApplyUserinfoResponse"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public ApplyUserinfoResponse([NotNull] ApplyUserinfoResponseContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called when serializing an authorization code.
        /// </summary>
        public sealed class SerializeAuthorizationCode : OpenIddictServerEvent<SerializeAuthorizationCodeContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="SerializeAuthorizationCode"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public SerializeAuthorizationCode([NotNull] SerializeAuthorizationCodeContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called when serializing an access token.
        /// </summary>
        public sealed class SerializeAccessToken : OpenIddictServerEvent<SerializeAccessTokenContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="SerializeAccessToken"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public SerializeAccessToken([NotNull] SerializeAccessTokenContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called when serializing an identity token.
        /// </summary>
        public sealed class SerializeIdentityToken : OpenIddictServerEvent<SerializeIdentityTokenContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="SerializeIdentityToken"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public SerializeIdentityToken([NotNull] SerializeIdentityTokenContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called when serializing a refresh token.
        /// </summary>
        public sealed class SerializeRefreshToken : OpenIddictServerEvent<SerializeRefreshTokenContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="SerializeRefreshToken"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public SerializeRefreshToken([NotNull] SerializeRefreshTokenContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called when deserializing an authorization code.
        /// </summary>
        public sealed class DeserializeAuthorizationCode : OpenIddictServerEvent<DeserializeAuthorizationCodeContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="DeserializeAuthorizationCode"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public DeserializeAuthorizationCode([NotNull] DeserializeAuthorizationCodeContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called when deserializing an access token.
        /// </summary>
        public sealed class DeserializeAccessToken : OpenIddictServerEvent<DeserializeAccessTokenContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="DeserializeAccessToken"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public DeserializeAccessToken([NotNull] DeserializeAccessTokenContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called when deserializing an identity token.
        /// </summary>
        public sealed class DeserializeIdentityToken : OpenIddictServerEvent<DeserializeIdentityTokenContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="DeserializeIdentityToken"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public DeserializeIdentityToken([NotNull] DeserializeIdentityTokenContext context) : base(context) { }
        }

        /// <summary>
        /// Represents an event called when deserializing a refresh token.
        /// </summary>
        public sealed class DeserializeRefreshToken : OpenIddictServerEvent<DeserializeRefreshTokenContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="DeserializeRefreshToken"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public DeserializeRefreshToken([NotNull] DeserializeRefreshTokenContext context) : base(context) { }
        }
    }
}
