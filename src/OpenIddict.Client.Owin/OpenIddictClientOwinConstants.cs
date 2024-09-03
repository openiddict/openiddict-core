/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Client.Owin;

/// <summary>
/// Exposes common constants used by the OpenIddict OWIN host.
/// </summary>
public static class OpenIddictClientOwinConstants
{
    public static class Headers
    {
        public const string CacheControl = "Cache-Control";
        public const string ContentType = "Content-Type";
        public const string Expires = "Expires";
        public const string Host = "Host";
        public const string Pragma = "Pragma";
    }

    public static class Properties
    {
        public const string AuthorizationCodePrincipal = ".authorization_code_principal";
        public const string BackchannelAccessTokenPrincipal = ".backchannel_access_token_principal";
        public const string BackchannelIdentityTokenPrincipal = ".backchannel_identity_token_principal";
        public const string CodeChallengeMethod = ".code_challenge_method";
        public const string Error = ".error";
        public const string ErrorDescription = ".error_description";
        public const string ErrorUri = ".error_uri";
        public const string FrontchannelAccessTokenPrincipal = ".frontchannel_access_token_principal";
        public const string FrontchannelIdentityTokenPrincipal = ".frontchannel_identity_token_principal";
        public const string GrantType = ".grant_type";
        public const string IdentityTokenHint = ".identity_token_hint";
        public const string Issuer = ".issuer";
        public const string LoginHint = ".login_hint";
        public const string ProviderName = ".provider_name";
        public const string RefreshTokenPrincipal = ".refresh_token_principal";
        public const string RegistrationId = ".registration_id";
        public const string ResponseMode = ".response_mode";
        public const string ResponseType = ".response_type";
        public const string Scope = ".scope";
        public const string StateTokenPrincipal = ".state_token_principal";
        public const string UserInfoTokenPrincipal = ".userinfo_token_principal";
    }

    public static class PropertyTypes
    {
        public const string Boolean = "#boolean";
        public const string Integer = "#integer";
        public const string Json = "#json";
        public const string String = "#string";
    }

    public static class Tokens
    {
        public const string AuthorizationCode = "authorization_code";
        public const string BackchannelAccessToken = "backchannel_access_token";
        public const string BackchannelAccessTokenExpirationDate = "backchannel_access_token_expiration_date";
        public const string BackchannelIdentityToken = "backchannel_id_token";
        public const string FrontchannelAccessToken = "frontchannel_access_token";
        public const string FrontchannelAccessTokenExpirationDate = "frontchannel_access_token_expiration_date";
        public const string FrontchannelIdentityToken = "frontchannel_id_token";
        public const string RefreshToken = "refresh_token";
        public const string StateToken = "state_token";
        public const string UserInfoToken = "userinfo_token";
    }
}
