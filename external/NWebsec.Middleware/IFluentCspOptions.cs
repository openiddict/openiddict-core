// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using System;
using NWebsec.Core.Fluent;
using NWebsec.Core.HttpHeaders.Configuration;

namespace NWebsec.Middleware
{
    /// <summary>
    /// Fluent interface to configure options for Content-Security-Options.
    /// </summary>
    public interface IFluentCspOptions : IFluentInterface
    {
        /// <summary>
        /// Configures the default-src directive (CSP 1.0).
        /// </summary>
        /// <param name="configurer">An <see cref="Action"/> that configures the sources for the directive.</param>
        /// <returns>The current <see cref="CspOptions" /> instance.</returns>
        IFluentCspOptions DefaultSources(Action<ICspDirectiveBasicConfiguration> configurer);

        /// <summary>
        /// Configures the script-src directive (CSP 1.0).
        /// </summary>
        /// <param name="configurer">An <see cref="Action"/> that configures the sources for the directive.</param>
        /// <returns>The current <see cref="CspOptions" /> instance.</returns>
        IFluentCspOptions ScriptSources(Action<ICspDirectiveConfiguration> configurer);

        /// <summary>
        /// Configures the object-src directive (CSP 1.0).
        /// </summary>
        /// <param name="configurer">An <see cref="Action"/> that configures the sources for the directive.</param>
        /// <returns>The current <see cref="CspOptions" /> instance.</returns>
        IFluentCspOptions ObjectSources(Action<ICspDirectiveBasicConfiguration> configurer);

        /// <summary>
        /// Configures the style-src directive (CSP 1.0).
        /// </summary>
        /// <param name="configurer">An <see cref="Action"/> that configures the sources for the directive.</param>
        /// <returns>The current <see cref="CspOptions" /> instance.</returns>
        IFluentCspOptions StyleSources(Action<ICspDirectiveUnsafeInlineConfiguration> configurer);

        /// <summary>
        /// Configures the image-src directive (CSP 1.0).
        /// </summary>
        /// <param name="configurer">An <see cref="Action"/> that configures the sources for the directive.</param>
        /// <returns>The current <see cref="CspOptions" /> instance.</returns>
        IFluentCspOptions ImageSources(Action<ICspDirectiveBasicConfiguration> configurer);

        /// <summary>
        /// Configures the media-src directive (CSP 1.0).
        /// </summary>
        /// <param name="configurer">An <see cref="Action"/> that configures the sources for the directive.</param>
        /// <returns>The current <see cref="CspOptions" /> instance.</returns>
        IFluentCspOptions MediaSources(Action<ICspDirectiveBasicConfiguration> configurer);

        /// <summary>
        /// Configures the frame-src directive (CSP 1.0).
        /// </summary>
        /// <param name="configurer">An <see cref="Action"/> that configures the sources for the directive.</param>
        /// <returns>The current <see cref="CspOptions" /> instance.</returns>
        IFluentCspOptions FrameSources(Action<ICspDirectiveBasicConfiguration> configurer);

        /// <summary>
        /// Configures the font-src directive (CSP 1.0).
        /// </summary>
        /// <param name="configurer">An <see cref="Action"/> that configures the sources for the directive.</param>
        /// <returns>The current <see cref="CspOptions" /> instance.</returns>
        IFluentCspOptions FontSources(Action<ICspDirectiveBasicConfiguration> configurer);

        /// <summary>
        /// Configures the connect-src directive (CSP 1.0).
        /// </summary>
        /// <param name="configurer">An <see cref="Action"/> that configures the sources for the directive.</param>
        /// <returns>The current <see cref="CspOptions" /> instance.</returns>
        IFluentCspOptions ConnectSources(Action<ICspDirectiveBasicConfiguration> configurer);

        /// <summary>
        /// Configures the base-uri directive (CSP 2).
        /// </summary>
        /// <param name="configurer">An <see cref="Action"/> that configures the sources for the directive.</param>
        /// <returns>The current <see cref="CspOptions" /> instance.</returns>
        IFluentCspOptions BaseUris(Action<ICspDirectiveBasicConfiguration> configurer);

        /// <summary>
        /// Configures the child-src directive (CSP 2).
        /// </summary>
        /// <param name="configurer">An <see cref="Action"/> that configures the sources for the directive.</param>
        /// <returns>The current <see cref="CspOptions" /> instance.</returns>
        IFluentCspOptions ChildSources(Action<ICspDirectiveBasicConfiguration> configurer);

        /// <summary>
        /// Configures the form-action directive (CSP 2).
        /// </summary>
        /// <param name="configurer">An <see cref="Action"/> that configures the sources for the directive.</param>
        /// <returns>The current <see cref="CspOptions" /> instance.</returns>
        IFluentCspOptions FormActions(Action<ICspDirectiveBasicConfiguration> configurer);

        /// <summary>
        /// Configures the fram-ancestors directive (CSP 2).
        /// </summary>
        /// <param name="configurer">An <see cref="Action"/> that configures the sources for the directive.</param>
        /// <returns>The current <see cref="CspOptions" /> instance.</returns>
        IFluentCspOptions FrameAncestors(Action<ICspDirectiveBasicConfiguration> configurer);

        /// <summary>
        /// Configures the plugin-types directive (CSP 2).
        /// </summary>
        /// <param name="configurer">An <see cref="Action"/> that configures the media types for the directive.</param>
        /// <returns>The current <see cref="CspOptions" /> instance.</returns>
        IFluentCspOptions PluginTypes(Action<IFluentCspPluginTypesDirective> configurer);

        /// <summary>
        /// Enables the sandbox directive (CSP 2) without further ado.
        /// </summary>
        /// <remarks>Support for this directive was optional in CSP 1.0, but is mandatory as of CSP 2.</remarks>
        /// <returns>The current <see cref="CspOptions" /> instance.</returns>
        IFluentCspOptions Sandbox();

        /// <summary>
        /// Configures the sandbox directive (CSP 2) with one or more sources.
        /// </summary>
        /// <remarks>Support for this directive was optional in CSP 1.0, but is mandatory as of CSP 2.</remarks>
        /// <param name="configurer">An <see cref="Action"/> that configures the sources for the directive.</param>
        /// <returns>The current <see cref="CspOptions" /> instance.</returns>
        IFluentCspOptions Sandbox(Action<IFluentCspSandboxDirective> configurer);

        /// <summary>
        /// Enables the upgrade-insecure-requests directive and redirects conformant UAs to HTTPS.
        /// </summary>
        /// <remarks>This directive is not part of CSP 1.0 or CSP 2, but is described in a separate specification.</remarks>
        /// <param name="httpsPort">The HTTPS port. Defaults to 443.</param>
        /// <returns>The current <see cref="CspOptions" /> instance.</returns>
        IFluentCspOptions UpgradeInsecureRequests(int httpsPort = 443);

        /// <summary>
        /// Configures the report-uri directive (CSP 1.0). Support for absolute URIs was introduced in CSP 2.
        /// </summary>
        /// <param name="configurer">An <see cref="Action"/> that configures the report URIs.</param>
        /// <returns>The current <see cref="CspOptions" /> instance.</returns>
        IFluentCspOptions ReportUris(Action<IFluentCspReportUriDirective> configurer);
    }
}