// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using NWebsec.Core.Fluent;

namespace NWebsec.Middleware
{
    /// <summary>
    /// Fluent interface to configure options for X-Robots-Tag.
    /// </summary>
    public interface IFluentXRobotsTagOptions : IFluentInterface
    {
        /// <summary>
        /// Enables the noindex directive.
        /// </summary>
        /// <returns>The current instance.</returns>
        IFluentXRobotsTagOptions NoIndex();

        /// <summary>
        /// Enables the nofollow directive.
        /// </summary>
        /// <returns>The current instance.</returns>
        IFluentXRobotsTagOptions NoFollow();

        /// <summary>
        /// Enables the nosnippet directive.
        /// </summary>
        /// <returns>The current instance.</returns>
        IFluentXRobotsTagOptions NoSnippet();

        /// <summary>
        /// Enables the noarchive directive.
        /// </summary>
        /// <returns>The current instance.</returns>
        IFluentXRobotsTagOptions NoArchive();

        /// <summary>
        /// Enables the noodp directive.
        /// </summary>
        /// <returns>The current instance.</returns>
        IFluentXRobotsTagOptions NoOdp();

        /// <summary>
        /// Enables the notranslate directive.
        /// </summary>
        /// <returns>The current instance.</returns>
        IFluentXRobotsTagOptions NoTranslate();

        /// <summary>
        /// Enables the noimageindex directive.
        /// </summary>
        /// <returns>The current instance.</returns>
        IFluentXRobotsTagOptions NoImageIndex();
    }
}