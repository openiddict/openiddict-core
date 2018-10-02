/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Abstractions
{
    public static class OpenIddictConstants
    {
        public static class AuthorizationTypes
        {
            public const string AdHoc = "ad-hoc";
            public const string Permanent = "permanent";
        }

        public static class Claims
        {
            public const string AccessTokenHash = "at_hash";
            public const string Active = "active";
            public const string Address = "address";
            public const string Audience = "aud";
            public const string AuthenticationContextReference = "acr";
            public const string AuthenticationMethodReference = "amr";
            public const string AuthenticationTime = "auth_time";
            public const string AuthorizedParty = "azp";
            public const string Birthdate = "birthdate";
            public const string ClientId = "client_id";
            public const string CodeHash = "c_hash";
            public const string ConfidentialityLevel = "cfd_lvl";
            public const string Country = "country";
            public const string Email = "email";
            public const string EmailVerified = "email_verified";
            public const string ExpiresAt = "exp";
            public const string FamilyName = "family_name";
            public const string Formatted = "formatted";
            public const string Gender = "gender";
            public const string GivenName = "given_name";
            public const string IssuedAt = "iat";
            public const string Issuer = "iss";
            public const string Locale = "locale";
            public const string Locality = "locality";
            public const string JwtId = "jti";
            public const string KeyId = "kid";
            public const string MiddleName = "middle_name";
            public const string Name = "name";
            public const string Nickname = "nickname";
            public const string Nonce = "nonce";
            public const string NotBefore = "nbf";
            public const string PhoneNumber = "phone_number";
            public const string PhoneNumberVerified = "phone_number_verified";
            public const string Picture = "picture";
            public const string PostalCode = "postal_code";
            public const string PreferredUsername = "preferred_username";
            public const string Profile = "profile";
            public const string Region = "region";
            public const string Role = "role";
            public const string Roles = "roles";
            public const string Scope = "scope";
            public const string StreetAddress = "street_address";
            public const string Subject = "sub";
            public const string TokenType = "token_type";
            public const string TokenUsage = "token_usage";
            public const string UpdatedAt = "updated_at";
            public const string Username = "username";
            public const string Website = "website";
            public const string Zoneinfo = "zoneinfo";
        }

        public static class ClientTypes
        {
            public const string Confidential = "confidential";
            public const string Hybrid = "hybrid";
            public const string Public = "public";
        }

        public static class ConsentTypes
        {
            public const string Explicit = "explicit";
            public const string External = "external";
            public const string Implicit = "implicit";
        }

        public static class Destinations
        {
            public const string AccessToken = "access_token";
            public const string IdentityToken = "id_token";
        }

        public static class Environment
        {
            public const string AuthorizationRequest = "openiddict-authorization-request:";
            public const string LogoutRequest = "openiddict-logout-request:";
        }

        public static class Errors
        {
            public const string AccessDenied = "access_denied";
            public const string AccountSelectionRequired = "account_selection_required";
            public const string ConsentRequired = "consent_required";
            public const string InteractionRequired = "interaction_required";
            public const string InvalidClient = "invalid_client";
            public const string InvalidGrant = "invalid_grant";
            public const string InvalidRequest = "invalid_request";
            public const string InvalidRequestObject = "invalid_request_object";
            public const string InvalidRequestUri = "invalid_request_uri";
            public const string InvalidScope = "invalid_scope";
            public const string InvalidToken = "invalid_token";
            public const string LoginRequired = "login_required";
            public const string RegistrationNotSupported = "registration_not_supported";
            public const string RequestNotSupported = "request_not_supported";
            public const string RequestUriNotSupported = "request_uri_not_supported";
            public const string ServerError = "server_error";
            public const string TemporarilyUnavailable = "temporarily_unavailable";
            public const string UnauthorizedClient = "unauthorized_client";
            public const string UnsupportedGrantType = "unsupported_grant_type";
            public const string UnsupportedResponseType = "unsupported_response_type";
            public const string UnsupportedTokenType = "unsupported_token_type";
        }

        public static class GrantTypes
        {
            public const string AuthorizationCode = "authorization_code";
            public const string ClientCredentials = "client_credentials";
            public const string Implicit = "implicit";
            public const string Password = "password";
            public const string RefreshToken = "refresh_token";
        }

        public static class Metadata
        {
            public const string AcrValuesSupported = "acr_values_supported";
            public const string AuthorizationEndpoint = "authorization_endpoint";
            public const string ClaimsLocalesSupported = "claims_locales_supported";
            public const string ClaimsParameterSupported = "claims_parameter_supported";
            public const string ClaimsSupported = "claims_supported";
            public const string ClaimTypesSupported = "claim_types_supported";
            public const string CodeChallengeMethodsSupported = "code_challenge_methods_supported";
            public const string DisplayValuesSupported = "display_values_supported";
            public const string EndSessionEndpoint = "end_session_endpoint";
            public const string GrantTypesSupported = "grant_types_supported";
            public const string IdTokenEncryptionAlgValuesSupported = "id_token_encryption_alg_values_supported";
            public const string IdTokenEncryptionEncValuesSupported = "id_token_encryption_enc_values_supported";
            public const string IdTokenSigningAlgValuesSupported = "id_token_signing_alg_values_supported";
            public const string IntrospectionEndpoint = "introspection_endpoint";
            public const string IntrospectionEndpointAuthMethodsSupported = "introspection_endpoint_auth_methods_supported";
            public const string IntrospectionEndpointAuthSigningAlgValuesSupported = "introspection_endpoint_auth_signing_alg_values_supported";
            public const string Issuer = "issuer";
            public const string JwksUri = "jwks_uri";
            public const string OpPolicyUri = "op_policy_uri";
            public const string OpTosUri = "op_tos_uri";
            public const string RequestObjectEncryptionAlgValuesSupported = "request_object_encryption_alg_values_supported";
            public const string RequestObjectEncryptionEncValuesSupported = "request_object_encryption_enc_values_supported";
            public const string RequestObjectSigningAlgValuesSupported = "request_object_signing_alg_values_supported";
            public const string RequestParameterSupported = "request_parameter_supported";
            public const string RequestUriParameterSupported = "request_uri_parameter_supported";
            public const string RequireRequestUriRegistration = "require_request_uri_registration";
            public const string ResponseModesSupported = "response_modes_supported";
            public const string ResponseTypesSupported = "response_types_supported";
            public const string RevocationEndpoint = "revocation_endpoint";
            public const string RevocationEndpointAuthMethodsSupported = "revocation_endpoint_auth_methods_supported";
            public const string RevocationEndpointAuthSigningAlgValuesSupported = "revocation_endpoint_auth_signing_alg_values_supported";
            public const string ScopesSupported = "scopes_supported";
            public const string ServiceDocumentation = "service_documentation";
            public const string SubjectTypesSupported = "subject_types_supported";
            public const string TokenEndpoint = "token_endpoint";
            public const string TokenEndpointAuthMethodsSupported = "token_endpoint_auth_methods_supported";
            public const string TokenEndpointAuthSigningAlgValuesSupported = "token_endpoint_auth_signing_alg_values_supported";
            public const string UiLocalesSupported = "ui_locales_supported";
            public const string UserinfoEncryptionAlgValuesSupported = "userinfo_encryption_alg_values_supported";
            public const string UserinfoEncryptionEncValuesSupported = "userinfo_encryption_enc_values_supported";
            public const string UserinfoEndpoint = "userinfo_endpoint";
            public const string UserinfoSigningAlgValuesSupported = "userinfo_signing_alg_values_supported";
        }

        public static class Parameters
        {
            public const string AccessToken = "access_token";
            public const string Active = "active";
            public const string AcrValues = "acr_values";
            public const string Assertion = "assertion";
            public const string Audience = "audience";
            public const string Claims = "claims";
            public const string ClaimsLocales = "claims_locales";
            public const string ClientAssertion = "client_assertion";
            public const string ClientAssertionType = "client_assertion_type";
            public const string ClientId = "client_id";
            public const string ClientSecret = "client_secret";
            public const string Code = "code";
            public const string CodeChallenge = "code_challenge";
            public const string CodeChallengeMethod = "code_challenge_method";
            public const string CodeVerifier = "code_verifier";
            public const string Display = "display";
            public const string Error = "error";
            public const string ErrorDescription = "error_description";
            public const string ErrorUri = "error_uri";
            public const string ExpiresIn = "expires_in";
            public const string GrantType = "grant_type";
            public const string IdentityProvider = "identity_provider";
            public const string IdToken = "id_token";
            public const string IdTokenHint = "id_token_hint";
            public const string LoginHint = "login_hint";
            public const string Keys = "keys";
            public const string MaxAge = "max_age";
            public const string Nonce = "nonce";
            public const string Password = "password";
            public const string PostLogoutRedirectUri = "post_logout_redirect_uri";
            public const string Prompt = "prompt";
            public const string Realm = "realm";
            public const string RedirectUri = "redirect_uri";
            public const string RefreshToken = "refresh_token";
            public const string Registration = "registration";
            public const string Request = "request";
            public const string RequestId = "request_id";
            public const string RequestUri = "request_uri";
            public const string Resource = "resource";
            public const string ResponseMode = "response_mode";
            public const string ResponseType = "response_type";
            public const string Scope = "scope";
            public const string State = "state";
            public const string Token = "token";
            public const string TokenType = "token_type";
            public const string TokenTypeHint = "token_type_hint";
            public const string UiLocales = "ui_locales";
            public const string Username = "username";
        }

        public static class Permissions
        {
            public static class Endpoints
            {
                public const string Authorization = "ept:authorization";
                public const string Introspection = "ept:introspection";
                public const string Logout = "ept:logout";
                public const string Revocation = "ept:revocation";
                public const string Token = "ept:token";
            }

            public static class GrantTypes
            {
                public const string AuthorizationCode = "gt:authorization_code";
                public const string ClientCredentials = "gt:client_credentials";
                public const string Implicit = "gt:implicit";
                public const string Password = "gt:password";
                public const string RefreshToken = "gt:refresh_token";
            }

            public static class Prefixes
            {
                public const string Endpoint = "ept:";
                public const string GrantType = "gt:";
                public const string Scope = "scp:";
            }

            public static class Scopes
            {
                public const string Address = "scp:address";
                public const string Email = "scp:email";
                public const string Phone = "scp:phone";
                public const string Profile = "scp:profile";
                public const string Roles = "scp:roles";
            }
        }

        public static class Prompts
        {
            public const string Consent = "consent";
            public const string Login = "login";
            public const string None = "none";
            public const string SelectAccount = "select_account";
        }

        public static class Properties
        {
            public const string Application = ".application";
            public const string AuthenticationTicket = ".authentication_ticket";
            public const string Error = ".error";
            public const string ErrorDescription = ".error_description";
            public const string ErrorUri = ".error_uri";
            public const string InternalAuthorizationId = ".internal_authorization_id";
            public const string InternalTokenId = ".internal_token_id";
            public const string ReferenceToken = ".reference_token";
            public const string Token = ".token";
        }

        public static class PropertyTypes
        {
            public const string Boolean = "#public_boolean";
            public const string Integer = "#public_integer";
            public const string Json = "#public_json";
            public const string String = "#public_string";
        }

        public static class ResponseModes
        {
            public const string FormPost = "form_post";
            public const string Fragment = "fragment";
            public const string Query = "query";
        }

        public static class ResponseTypes
        {
            public const string Code = "code";
            public const string IdToken = "id_token";
            public const string None = "none";
            public const string Token = "token";
        }

        public static class Separators
        {
            public const string Space = " ";
        }

        public static class Scopes
        {
            public const string Address = "address";
            public const string Email = "email";
            public const string OfflineAccess = "offline_access";
            public const string OpenId = "openid";
            public const string Phone = "phone";
            public const string Profile = "profile";
            public const string Roles = "roles";
        }

        public static class Statuses
        {
            public const string Redeemed = "redeemed";
            public const string Revoked = "revoked";
            public const string Valid = "valid";
        }

        public static class TokenTypes
        {
            public const string AccessToken = "access_token";
            public const string AuthorizationCode = "authorization_code";
            public const string IdToken = "id_token";
            public const string RefreshToken = "refresh_token";
        }
    }
}
