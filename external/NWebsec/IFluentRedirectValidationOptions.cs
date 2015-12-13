// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using NWebsec.Core.Fluent;

namespace NWebsec.Middleware
{
    /// <summary>
    /// Fluent interface to configure options for redirect validation.
    /// </summary>
    public interface IFluentRedirectValidationOptions : IFluentInterface
    {
        /// <summary>
        /// Configures the allowed redirect destinations. These must be well formed absolute URIs.
        /// </summary>
        /// <param name="uris">Allowed redirect destinations.</param>
        /// <returns>The current instance.</returns>
        IFluentRedirectValidationOptions AllowedDestinations(params string[] uris);

        /// <summary>
        /// Allows same host redirects to HTTPS.
        /// </summary>
        /// <param name="httpsPorts">Allowed destination port(s) for redirects to HTTPS. The default HTTPS port (443) is assumed if no values are configured.</param>
        /// <returns>The current instance.</returns>
        IFluentRedirectValidationOptions AllowSameHostRedirectsToHttps(params int[] httpsPorts);
    }
}