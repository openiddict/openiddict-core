/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNet.Http;

namespace OpenIddict {
    public class OpenIddictOptions {
        public string AuthenticationScheme { get; set; } = OpenIddictDefaults.AuthenticationScheme;

        /// <summary>
        /// The base address used to uniquely identify the authorization server.
        /// The URI must be absolute and may contain a path, but no query string or fragment part.
        /// Unless AllowInsecureHttp has been set to true, an HTTPS address must be provided.
        /// </summary>
        public Uri Issuer { get; set; }

        /// <summary>
        /// The request path where client applications will redirect the user-agent in order to 
        /// obtain user consent to issue a token. Must begin with a leading slash, like "/connect/authorize".
        /// This setting can be set to <see cref="PathString.Empty"/> to disable the authorization endpoint.
        /// </summary>
        public PathString AuthorizationEndpointPath { get; set; } = new PathString(OpenIdConnectServerDefaults.AuthorizationEndpointPath);

        /// <summary>
        /// The request path client applications communicate with to log out. 
        /// Must begin with a leading slash, like "/connect/logout".
        /// You can set it to <see cref="PathString.Empty"/> to disable the logout endpoint.
        /// </summary>
        public PathString LogoutEndpointPath { get; set; } = new PathString(OpenIdConnectServerDefaults.LogoutEndpointPath);

        /// <summary>
        /// The period of time the authorization code remains valid after being issued. The default is 5 minutes.
        /// This time span must also take into account clock synchronization between servers in a web farm, so a very 
        /// brief value could result in unexpectedly expired tokens.
        /// </summary>
        public TimeSpan AuthorizationCodeLifetime { get; set; } = TimeSpan.FromMinutes(5);

        /// <summary>
        /// The period of time the access token remains valid after being issued. The default is 1 hour.
        /// The client application is expected to refresh or acquire a new access token after the token has expired. 
        /// </summary>
        public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromHours(1);

        /// <summary>
        /// The period of time the identity token remains valid after being issued. The default is 20 minutes.
        /// The client application is expected to refresh or acquire a new identity token after the token has expired. 
        /// </summary>
        public TimeSpan IdentityTokenLifetime { get; set; } = TimeSpan.FromMinutes(20);

        /// <summary>
        /// The period of time the refresh token remains valid after being issued. The default is 6 hours.
        /// The client application is expected to start a whole new authentication flow after the refresh token has expired. 
        /// </summary>
        public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromHours(6);

        /// <summary>
        /// Determines whether refresh tokens issued during a grant_type=refresh_token request should be generated
        /// with a new expiration date or should re-use the same expiration date as the original refresh token.
        /// Set this property to <c>true</c> to assign a new expiration date each time a refresh token is issued,
        /// <c>false</c> to use the expiration date of the original refresh token. When set to <c>false</c>,
        /// access and identity tokens' lifetime cannot exceed the expiration date of the refresh token.
        /// </summary>
        public bool UseSlidingExpiration { get; set; } = true;

        /// <summary>
        /// Set to true if the web application is able to render error messages on the authorization endpoint. This is only needed for cases where
        /// the browser is not redirected back to the client application, for example, when the client_id or redirect_uri are incorrect. The 
        /// authorization endpoint should expect to see the OpenID Connect response added to the ASP.NET 5 environment.
        /// </summary>
        public bool ApplicationCanDisplayErrors { get; set; }

        /// <summary>
        /// True to allow incoming requests to arrive on HTTP and to allow redirect_uri parameters to have HTTP URI addresses.
        /// Setting this option to false in production is strongly encouraged to mitigate man-in-the-middle attacks.
        /// </summary>
        public bool AllowInsecureHttp { get; set; }
    }
}
