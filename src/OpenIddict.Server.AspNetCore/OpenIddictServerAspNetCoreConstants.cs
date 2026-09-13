/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Server.AspNetCore;

/// <summary>
/// Exposes common constants used by the OpenIddict ASP.NET Core host.
/// </summary>
public static class OpenIddictServerAspNetCoreConstants
{
    public static class AdminApi
    {
        public static class ErrorCodes
        {
            public const string Conflict = "conflict";
            public const string NotFound = "not_found";
        }

        public static class Paths
        {
            public const string Applications = "applications";
            public const string Authorizations = "authorizations";
            public const string Keys = "keys";
            public const string Revoke = "revoke";
            public const string Scopes = "scopes";
            public const string Tokens = "tokens";
        }

        public static class Fields
        {
            public const string ActivationDate = "activation_date";
            public const string Algorithm = "algorithm";
            public const string ApplicationId = "application_id";
            public const string ApplicationType = "application_type";
            public const string AuthorizationId = "authorization_id";
            public const string ClientId = "client_id";
            public const string ClientSecret = "client_secret";
            public const string ClientType = "client_type";
            public const string ConsentType = "consent_type";
            public const string CreationDate = "creation_date";
            public const string Description = "description";
            public const string Descriptions = "descriptions";
            public const string DisplayName = "display_name";
            public const string DisplayNames = "display_names";
            public const string Errors = "errors";
            public const string ExpirationDate = "expiration_date";
            public const string Id = "id";
            public const string JsonWebKeySet = "json_web_key_set";
            public const string KeyId = "key_id";
            public const string Name = "name";
            public const string Permissions = "permissions";
            public const string PostLogoutRedirectUris = "post_logout_redirect_uris";
            public const string Properties = "properties";
            public const string RedemptionDate = "redemption_date";
            public const string RedirectUris = "redirect_uris";
            public const string Requirements = "requirements";
            public const string Resources = "resources";
            public const string RetirementDate = "retirement_date";
            public const string Scopes = "scopes";
            public const string SessionId = "session_id";
            public const string Settings = "settings";
            public const string Status = "status";
            public const string Subject = "subject";
            public const string Type = "type";
            public const string Usage = "usage";
        }

        public static class QueryStringParameters
        {
            public const string ApplicationId = "application_id";
            public const string Count = "count";
            public const string Offset = "offset";
            public const string Status = "status";
            public const string Subject = "subject";
            public const string Type = "type";
        }
    }

    public static class Headers
    {
        public const string DPoP = "DPoP";
        public const string DPoPNonce = "DPoP-Nonce";
    }

    public static class Properties
    {
        public const string AccessTokenPrincipal = ".access_token_principal";
        public const string ActorTokenPrincipal = ".actor_token_principal";
        public const string ClientAssertionPrincipal = ".client_assertion_principal";
        public const string AuthorizationCodePrincipal = ".authorization_code_principal";
        public const string DeviceCodePrincipal = ".device_code_principal";
        public const string Error = ".error";
        public const string ErrorDescription = ".error_description";
        public const string ErrorUri = ".error_uri";
        public const string IdentityTokenPrincipal = ".identity_token_principal";
        public const string RefreshTokenPrincipal = ".refresh_token_principal";
        public const string RequestTokenPrincipal = ".request_token_principal";
        public const string Scope = ".scope";
        public const string SubjectTokenPrincipal = ".subject_token_principal";
        public const string UserCodePrincipal = ".user_code_principal";
    }

    public static class Tokens
    {
        public const string AccessToken = "access_token";
        public const string ActorToken = "actor_token";
        public const string ActorTokenType = "actor_token_type";
        public const string AuthorizationCode = "authorization_code";
        public const string ClientAssertion = "client_assertion";
        public const string DeviceCode = "device_code";
        public const string IdentityToken = "id_token";
        public const string RefreshToken = "refresh_token";
        public const string RequestToken = "request_token";
        public const string SubjectToken = "subject_token";
        public const string SubjectTokenType = "subject_token_type";
        public const string UserCode = "user_code";
    }
}
