// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using System;
using NWebsec.Core.Fluent;

namespace NWebsec.Middleware
{
    /// <summary>
    /// Fluent interface to configure options for Http Strict Transport Security.
    /// </summary>
    public interface IFluentHstsOptions : IFluentInterface
    {
        /// <summary>
        /// Specifies the max age for the HSTS header.
        /// </summary>
        /// <param name="days">The number of days added to max age.</param>
        /// <param name="hours">The number of hours added to max age.</param>
        /// <param name="minutes">The number of minutes added to max age.</param>
        /// <param name="seconds">The number of seconds added to max age.</param>
        /// <returns>The current instance.</returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown if a negative value was supplied in any of the parameters.</exception>
        IFluentHstsOptions MaxAge(int days = 0, int hours = 0, int minutes = 0, int seconds = 0);

        /// <summary>
        /// Enables the IncludeSubdomains directive in the Hsts header.
        /// </summary>
        /// <returns>The current instance.</returns>
        IFluentHstsOptions IncludeSubdomains();

        /// <summary>
        /// Enables the Preload directive in the HSTS header. MaxAge must be at least 18 weeks, and IncludeSubdomains must be enabled.
        /// </summary>
        /// <remarks>Read more about preloaded HSTS sites at <a href="https://www.chromium.org/hsts">www.chromium.org/sts</a></remarks>
        /// <returns>The current instance.</returns>
        IFluentHstsOptions Preload();

        /// <summary>
        /// Sets the HSTS header only when the user agent signals that it supports the upgrade-insecure-requests CSP directive.
        /// </summary>
        /// <remarks>This setting is intended to be used in combination with the upgrade-insecure-requests CSP directive.</remarks>
        /// <returns>The current instance.</returns>
        IFluentHstsOptions UpgradeInsecureRequests();

        /// <summary>
        /// Specifies that the HSTS header should also be set for HTTP responses. The header is always set for HTTPS responses.
        /// </summary>
        /// <remarks>The HSTS standard specifies that the header should only be set over secure connections, which is the default behavior.
        /// This configuration option exists to accomodate websites running behind an SSL terminator.</remarks>
        /// <returns>The current instance.</returns>
        IFluentHstsOptions AllResponses();

        /// <summary>
        /// Specifies that the HSTS header should be set for HTTPS responses only.
        /// </summary>
        /// <returns>The current instance.</returns>
        [Obsolete("This method is deprecated as the default has been changed to HTTPS only.", false)]
        IFluentHstsOptions HttpsOnly();
    }
}