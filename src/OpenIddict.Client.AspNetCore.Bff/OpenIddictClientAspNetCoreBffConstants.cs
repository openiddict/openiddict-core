/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Client.AspNetCore.Bff;

/// <summary>
/// Exposes common constants used by the OpenIddict backend-for-frontend (BFF) components.
/// </summary>
public static class OpenIddictClientAspNetCoreBffConstants
{
    public static class CacheKeys
    {
        public const string LogoutToken = "openiddict:bff:logout_token:";
        public const string RefreshLock = "openiddict:bff:refresh_lock:";
        public const string RefreshResult = "openiddict:bff:refresh_result:";
    }

    public static class Claims
    {
        public const string LogoutUrl = "bff:logout_url";
        public const string SessionExpiresIn = "bff:session_expires_in";
    }

    public static class Events
    {
        public const string BackchannelLogout = OpenIddictConstants.SecurityEventTypes.BackchannelLogout;
    }

    public static class Headers
    {
        public const string Antiforgery = "X-CSRF";
        public const string CacheControl = "Cache-Control";
        public const string Cookie = "Cookie";
        public const string DPoP = "DPoP";
        public const string DPoPNonce = "DPoP-Nonce";
        public const string Pragma = "Pragma";
        public const string WwwAuthenticate = "WWW-Authenticate";
    }

    public static class Metadata
    {
        /// <summary>
        /// Name of the YARP route metadata indicating the type of access token attached to proxied requests
        /// (see <see cref="OpenIddictClientAspNetCoreBffTokenType"/> for the supported values).
        /// </summary>
        public const string AccessToken = "OpenIddict.Bff.AccessToken";

        /// <summary>
        /// Name of the YARP route metadata allowing to disable the antiforgery header check ("true" to disable).
        /// </summary>
        public const string DisableAntiforgeryCheck = "OpenIddict.Bff.DisableAntiforgeryCheck";

        /// <summary>
        /// Name of the YARP route metadata containing the client registration used to get client access tokens.
        /// </summary>
        public const string RegistrationId = "OpenIddict.Bff.RegistrationId";

        /// <summary>
        /// Name of the YARP route metadata containing the space-separated scopes requested for client access tokens.
        /// </summary>
        public const string Scopes = "OpenIddict.Bff.Scopes";
    }

    public static class Purposes
    {
        public const string RefreshResult = "OpenIddict.Client.AspNetCore.Bff.RefreshResult";
    }

    public static class QueryStringParameters
    {
        public const string Provider = "provider";
        public const string ReturnUrl = "returnUrl";
        public const string SessionId = "sid";
    }
}
