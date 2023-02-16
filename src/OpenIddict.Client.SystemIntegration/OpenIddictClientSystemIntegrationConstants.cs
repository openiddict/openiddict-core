/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Client.SystemIntegration;

/// <summary>
/// Exposes common constants used by the OpenIddict client system integration.
/// </summary>
public static class OpenIddictClientSystemIntegrationConstants
{
    public static class Headers
    {
        public const string CacheControl = "Cache-Control";
        public const string ContentType = "Content-Type";
        public const string Expires = "Expires";
        public const string Pragma = "Pragma";
    }

    public static class Tokens
    {
        public const string AuthorizationCode = "authorization_code";
        public const string BackchannelAccessToken = "backchannel_access_token";
        public const string BackchannelIdentityToken = "backchannel_id_token";
        public const string FrontchannelAccessToken = "frontchannel_access_token";
        public const string FrontchannelIdentityToken = "frontchannel_id_token";
        public const string RefreshToken = "refresh_token";
        public const string StateToken = "state_token";
        public const string UserinfoToken = "userinfo_token";
    }
}
