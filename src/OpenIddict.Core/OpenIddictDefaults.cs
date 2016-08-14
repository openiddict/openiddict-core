/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using AspNet.Security.OpenIdConnect.Server;

namespace OpenIddict {
    /// <summary>
    /// Exposes the default values used by OpenIddict.
    /// </summary>
    public static class OpenIddictDefaults {
        /// <summary>
        /// Default value for <see cref="OpenIdConnectServerOptions.AuthorizationEndpointPath"/>.
        /// </summary>
        public const string AuthorizationEndpointPath = "/connect/authorize";

        /// <summary>
        /// Default value for <see cref="OpenIdConnectServerOptions.IntrospectionEndpointPath"/>.
        /// </summary>
        public const string IntrospectionEndpointPath = "/connect/introspect";

        /// <summary>
        /// Default value for <see cref="OpenIdConnectServerOptions.LogoutEndpointPath"/>.
        /// </summary>
        public const string LogoutEndpointPath = "/connect/logout";

        /// <summary>
        /// Default value for <see cref="OpenIdConnectServerOptions.RevocationEndpointPath"/>.
        /// </summary>
        public const string RevocationEndpointPath = "/connect/revoke";

        /// <summary>
        /// Default value for <see cref="OpenIdConnectServerOptions.TokenEndpointPath"/>.
        /// </summary>
        public const string TokenEndpointPath = "/connect/token";

        /// <summary>
        /// Default value for <see cref="OpenIdConnectServerOptions.UserinfoEndpointPath"/>.
        /// </summary>
        public const string UserinfoEndpointPath = "/connect/userinfo";
    }
}
