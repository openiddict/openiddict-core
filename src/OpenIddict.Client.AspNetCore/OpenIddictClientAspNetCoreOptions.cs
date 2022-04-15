﻿/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.AspNetCore;

namespace OpenIddict.Client.AspNetCore;

/// <summary>
/// Provides various settings needed to configure the OpenIddict ASP.NET Core client integration.
/// </summary>
public class OpenIddictClientAspNetCoreOptions : AuthenticationSchemeOptions
{
    /// <summary>
    /// Gets or sets a boolean indicating whether the pass-through mode is enabled for the redirection endpoint.
    /// When the pass-through mode is used, OpenID Connect requests are initially handled by OpenIddict.
    /// Once validated, the rest of the request processing pipeline is invoked, so that OpenID Connect requests
    /// can be handled at a later stage (in a custom middleware or in a MVC controller, for instance).
    /// </summary>
    public bool EnableRedirectionEndpointPassthrough { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether OpenIddict should allow the rest of the request processing pipeline
    /// to be invoked when returning an error from the interactive authorization and logout endpoints.
    /// When this option is enabled, special logic must be added to these actions to handle errors, that can be
    /// retrieved using <see cref="OpenIddictClientAspNetCoreHelpers.GetOpenIddictClientResponse(HttpContext)"/>.
    /// </summary>
    /// <remarks>
    /// Important: the error pass-through mode cannot be used when the status code pages integration is enabled.
    /// </remarks>
    public bool EnableErrorPassthrough { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether integration with the status code pages
    /// middleware should be enabled or not. Once enabled, errors generated by the OpenIddict
    /// interactive endpoints (e.g authorization or logout) can be handled by ASP.NET Core.
    /// </summary>
    public bool EnableStatusCodePagesIntegration { get; set; }

    /// <summary>
    /// Gets or sets the cookie builder used to create the cookies that are
    /// used to protect against forged requests/session fixation attacks.
    /// </summary>
    public CookieBuilder CookieBuilder { get; set; } = new()
    {
        HttpOnly = true,
        IsEssential = true,
        Name = "OpenIddict.Client.RequestForgeryProtection",
        SameSite = SameSiteMode.None,
        SecurePolicy = CookieSecurePolicy.Always // Note: same-site=none requires using HTTPS.
    };
}
