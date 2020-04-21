/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Validation.AspNetCore
{
    /// <summary>
    /// Exposes common constants used by the OpenIddict ASP.NET Core host.
    /// </summary>
    public static class OpenIddictValidationAspNetCoreConstants
    {
        public static class Cache
        {
            public const string AuthorizationRequest = "openiddict-authorization-request:";
            public const string LogoutRequest = "openiddict-logout-request:";
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
