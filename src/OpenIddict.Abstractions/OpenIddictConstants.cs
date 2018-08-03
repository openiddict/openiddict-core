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

        public static class Exceptions
        {
            public const string ConcurrencyError = "concurrency_error";
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
                public const string OfflineAccess = "scp:offline_access";
                public const string OpenId = "scp:openid";
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
