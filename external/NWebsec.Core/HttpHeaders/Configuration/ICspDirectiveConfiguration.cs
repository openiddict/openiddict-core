// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using System.ComponentModel;

namespace NWebsec.Core.HttpHeaders.Configuration
{
    /// <summary>
    ///     Defines the properties required for CSP directive configuration.
    /// </summary>
    public interface ICspDirectiveConfiguration : ICspDirectiveUnsafeInlineConfiguration
    {
        /// <summary>
        ///     Infrastructure. Not intended to be used by your code directly. An attempt to hide this from Intellisense has been
        ///     made.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        bool UnsafeEvalSrc { get; set; }
    }
}