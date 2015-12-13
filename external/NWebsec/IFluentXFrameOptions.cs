// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using NWebsec.Core.Fluent;

namespace NWebsec.Middleware
{
    /// <summary>
    /// Fluent interface to configure options for X-Frame-Options.
    /// </summary>
    public interface IFluentXFrameOptions : IFluentInterface
    {
        /// <summary>
        /// Enables the Deny directive.
        /// </summary>
        void Deny();

        /// <summary>
        /// Enables the SameOrigin directive.
        /// </summary>
        void SameOrigin();
    }
}