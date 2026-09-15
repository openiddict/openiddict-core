/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Client.AspNetCore.Bff;

/// <summary>
/// Provides various settings needed to configure the OpenIddict backend-for-frontend (BFF) components.
/// </summary>
public sealed class OpenIddictClientAspNetCoreBffOptions
{
    /// <summary>
    /// Gets or sets the name of the cookie authentication scheme storing the user session and tokens.
    /// If set to <see langword="null"/>, the default authentication/sign-in schemes are used and the
    /// automatic token refresh logic is attached to all the cookie authentication schemes.
    /// </summary>
    public string? CookieScheme { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether the access tokens stored in the authentication cookie
    /// should NOT be automatically refreshed when they are about to expire.
    /// </summary>
    public bool DisableAutomaticTokenRefresh { get; set; }

    /// <summary>
    /// Gets or sets the margin applied to the expiration date of access tokens when determining
    /// whether they must be refreshed or renewed. By default, tokens are refreshed 1 minute before they expire.
    /// </summary>
    public TimeSpan AccessTokenRefreshMargin { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// Gets or sets the period during which the result of a refresh token request is kept in memory
    /// and returned to concurrent or subsequent requests still carrying the same refresh token
    /// (e.g requests sent by the browser before the renewed authentication cookie was received).
    /// By default, results are retained for 30 seconds. <see cref="TimeSpan.Zero"/> disables retention.
    /// </summary>
    public TimeSpan TokenRefreshResultRetentionPeriod { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Gets or sets the name of the header that must be sent by the frontend application
    /// when calling the user endpoint and the API endpoints (as an antiforgery measure).
    /// </summary>
    public string AntiforgeryHeaderName { get; set; } = OpenIddictClientAspNetCoreBffConstants.Headers.Antiforgery;

    /// <summary>
    /// Gets or sets the value of the antiforgery header.
    /// </summary>
    public string AntiforgeryHeaderValue { get; set; } = "1";

    /// <summary>
    /// Gets or sets the path of the login endpoint.
    /// </summary>
    public PathString LoginPath { get; set; } = "/bff/login";

    /// <summary>
    /// Gets or sets the path of the logout endpoint.
    /// </summary>
    public PathString LogoutPath { get; set; } = "/bff/logout";

    /// <summary>
    /// Gets or sets the path of the user endpoint.
    /// </summary>
    public PathString UserPath { get; set; } = "/bff/user";

    /// <summary>
    /// Gets or sets the path of the back-channel logout endpoint.
    /// </summary>
    public PathString BackchannelLogoutPath { get; set; } = "/bff/backchannel-logout";

    /// <summary>
    /// Gets or sets the path of the redirection endpoint (login callback). Unless automatic
    /// endpoint registration is disabled, this path is added to the redirection endpoint URIs.
    /// </summary>
    public PathString RedirectionPath { get; set; } = "/bff/callback/login";

    /// <summary>
    /// Gets or sets the path of the post-logout redirection endpoint (logout callback). Unless automatic
    /// endpoint registration is disabled, this path is added to the post-logout redirection endpoint URIs.
    /// </summary>
    public PathString PostLogoutRedirectionPath { get; set; } = "/bff/callback/logout";

    /// <summary>
    /// Gets or sets a boolean indicating whether the redirection and post-logout redirection paths should NOT be
    /// automatically added to the OpenIddict client options (and their pass-through mode automatically enabled).
    /// </summary>
    public bool DisableAutomaticEndpointRegistration { get; set; }

    /// <summary>
    /// Gets or sets the default return URL used when no local return URL was specified.
    /// </summary>
    public string DefaultReturnUrl { get; set; } = "/";

    /// <summary>
    /// Gets or sets the lifetime of the logout token identifiers kept in memory to prevent replay attacks.
    /// Logout tokens without an "exp" claim are only accepted if their "iat" claim is within this window.
    /// </summary>
    public TimeSpan LogoutTokenReplayCacheLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Gets or sets a boolean indicating whether the <see cref="Microsoft.Extensions.Caching.Distributed.IDistributedCache"/>
    /// registered in the dependency injection container should be used, in addition to the in-memory caches, to share the
    /// results of refresh token requests (protected using ASP.NET Core Data Protection) between multiple instances
    /// of the application (e.g in a web farm). When enabled, a distributed cache must be registered.
    /// </summary>
    /// <remarks>
    /// Note: when enabled, the Data Protection key ring must be shared between all the instances of the application.
    /// The identifiers of the logout tokens already received are shared by the OpenIddict client stack
    /// whenever a distributed cache is registered, independently of this option.
    /// </remarks>
    public bool EnableDistributedCaching { get; set; }

    /// <summary>
    /// Gets or sets the maximum period during which an instance waits for the result of a refresh token request sent
    /// by another instance using the same refresh token, when distributed caching is enabled. By default, 10 seconds.
    /// </summary>
    public TimeSpan DistributedTokenRefreshLockTimeout { get; set; } = TimeSpan.FromSeconds(10);
}
