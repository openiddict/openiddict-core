/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Client.AspNetCore;

/// <summary>
/// Exposes common constants used by the OpenIddict ASP.NET Core host.
/// </summary>
public static class OpenIddictClientAspNetCoreConstants
{
    public static class Properties
    {
        public const string BackchannelAccessTokenPrincipal = ".backchannel_access_token_principal";
        public const string BackchannelIdentityTokenPrincipal = ".backchannel_id_token_principal";
        public const string BackchannelRefreshTokenPrincipal = ".backchannel_refresh_token_principal";
        public const string FrontchannelAccessTokenPrincipal = ".frontchannel_access_token_principal";
        public const string FrontchannelAuthorizationCodePrincipal = ".frontchannel_authorization_code_principal";
        public const string FrontchannelIdentityTokenPrincipal = ".frontchannel_id_token_principal";
        public const string FrontchannelStateTokenPrincipal = ".frontchannel_state_token_principal";
        public const string Issuer = ".issuer";
        public const string Error = ".error";
        public const string ErrorDescription = ".error_description";
        public const string ErrorUri = ".error_uri";
    }

    public static class Tokens
    {
        public const string BackchannelAccessToken = "backchannel_access_token";
        public const string BackchannelIdentityToken = "backchannel_id_token";
        public const string BackchannelRefreshToken = "backchannel_refresh_token";
        public const string FrontchannelAccessToken = "frontchannel_access_token";
        public const string FrontchannelAuthorizationCode = "frontchannel_authorization_code";
        public const string FrontchannelIdentityToken = "frontchannel_id_token";
        public const string FrontchannelStateToken = "frontchannel_state_token";
    }
}
