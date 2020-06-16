/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Distributed;

namespace OpenIddict.Server.AspNetCore
{
    /// <summary>
    /// Provides various settings needed to configure the OpenIddict ASP.NET Core server integration.
    /// </summary>
    public class OpenIddictServerAspNetCoreOptions : AuthenticationSchemeOptions
    {
        /// <summary>
        /// Gets or sets a boolean indicating whether incoming requests arriving on insecure endpoints should be rejected.
        /// By default, this property is set to <c>false</c> to help mitigate man-in-the-middle attacks.
        /// </summary>
        public bool DisableTransportSecurityRequirement { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the pass-through mode is enabled for the authorization endpoint.
        /// When the pass-through mode is used, OpenID Connect requests are initially handled by OpenIddict.
        /// Once validated, the rest of the request processing pipeline is invoked, so that OpenID Connect requests
        /// can be handled at a later stage (in a custom middleware or in a MVC controller, for instance).
        /// </summary>
        public bool EnableAuthorizationEndpointPassthrough { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether OpenIddict should allow the rest of the request processing pipeline
        /// to be invoked when returning an error from the interactive authorization and logout endpoints.
        /// When this option is enabled, special logic must be added to these actions to handle errors, that can be
        /// retrieved using <see cref="OpenIddictServerAspNetCoreHelpers.GetOpenIddictServerResponse(HttpContext)"/>.
        /// </summary>
        /// <remarks>
        /// Important: the error pass-through mode cannot be used when the status code pages integration is enabled.
        /// </remarks>
        public bool EnableErrorPassthrough { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the pass-through mode is enabled for the logout endpoint.
        /// When the pass-through mode is used, OpenID Connect requests are initially handled by OpenIddict.
        /// Once validated, the rest of the request processing pipeline is invoked, so that OpenID Connect requests
        /// can be handled at a later stage (in a custom middleware or in a MVC controller, for instance).
        /// </summary>
        public bool EnableLogoutEndpointPassthrough { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the pass-through mode is enabled for the token endpoint.
        /// When the pass-through mode is used, OpenID Connect requests are initially handled by OpenIddict.
        /// Once validated, the rest of the request processing pipeline is invoked, so that OpenID Connect requests
        /// can be handled at a later stage (in a custom middleware or in a MVC controller, for instance).
        /// </summary>
        public bool EnableTokenEndpointPassthrough { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the pass-through mode is enabled for the userinfo endpoint.
        /// When the pass-through mode is used, OpenID Connect requests are initially handled by OpenIddict.
        /// Once validated, the rest of the request processing pipeline is invoked, so that OpenID Connect requests
        /// can be handled at a later stage (in a custom middleware or in a MVC controller, for instance).
        /// </summary>
        public bool EnableUserinfoEndpointPassthrough { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the pass-through mode is enabled for the user verification endpoint.
        /// When the pass-through mode is used, OpenID Connect requests are initially handled by OpenIddict.
        /// Once validated, the rest of the request processing pipeline is invoked, so that OpenID Connect requests
        /// can be handled at a later stage (in a custom middleware or in a MVC controller, for instance).
        /// </summary>
        public bool EnableVerificationEndpointPassthrough { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether requests received by the authorization endpoint
        /// should be cached. When enabled, authorization requests are automatically stored
        /// in the distributed cache, which allows flowing large payloads across requests.
        /// Enabling this option is recommended when using external authentication providers
        /// or when large GET or POST OpenID Connect authorization requests support is required.
        /// </summary>
        public bool EnableAuthorizationEndpointCaching { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether requests received by the logout endpoint should be cached.
        /// When enabled, authorization requests are automatically stored in the distributed cache.
        /// </summary>
        public bool EnableLogoutEndpointCaching { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether integration with the status code pages
        /// middleware should be enabled or not. Once enabled, errors generated by the OpenIddict
        /// interactive endpoints (e.g authorization or logout) can be handled by ASP.NET Core.
        /// </summary>
        public bool EnableStatusCodePagesIntegration { get; set; }

        /// <summary>
        /// Gets or sets the optional "realm" value returned to
        /// the caller as part of the WWW-Authenticate header.
        /// </summary>
        public string Realm { get; set; }

        /// <summary>
        /// Gets or sets the caching policy used by the authorization endpoint.
        /// </summary>
        public DistributedCacheEntryOptions AuthorizationEndpointCachingPolicy { get; set; } = new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(1),
            SlidingExpiration = TimeSpan.FromMinutes(30)
        };

        /// <summary>
        /// Gets or sets the caching policy used by the logout endpoint.
        /// </summary>
        public DistributedCacheEntryOptions LogoutEndpointCachingPolicy { get; set; } = new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(1),
            SlidingExpiration = TimeSpan.FromMinutes(30)
        };
    }
}
