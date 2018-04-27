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
            public const string Roles = "roles";
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

        public static class Environment
        {
            public const string AuthorizationRequest = "openiddict-authorization-request:";
            public const string LogoutRequest = "openiddict-logout-request:";
        }

        public static class Metadata
        {
            public const string ExternalProvidersSupported = "external_providers_supported";
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
        }

        public static class Properties
        {
            public const string Application = ".application";
            public const string AuthenticationTicket = ".authentication_ticket";
            public const string AuthorizationId = ".authorization_id";
            public const string ReferenceToken = ".reference_token";
            public const string Token = ".token";
            public const string TokenId = ".token_id";
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
