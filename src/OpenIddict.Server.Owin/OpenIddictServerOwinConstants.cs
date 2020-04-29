/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Server.Owin
{
    /// <summary>
    /// Exposes common constants used by the OpenIddict OWIN host.
    /// </summary>
    public static class OpenIddictServerOwinConstants
    {
        public static class Cache
        {
            public const string AuthorizationRequest = "openiddict-authorization-request:";
            public const string LogoutRequest = "openiddict-logout-request:";
        }

        public static class JsonWebTokenTypes
        {
            public static class Private
            {
                public const string AuthorizationRequest = "oi_authrq+jwt";
                public const string LogoutRequest = "oi_lgtrq+jwt";
            }
        }

        public static class Properties
        {
            public const string Error = ".error";
            public const string ErrorDescription = ".error_description";
            public const string ErrorUri = ".error_uri";
            public const string Realm = ".realm";
            public const string Scope = ".scope";
        }
    }
}
