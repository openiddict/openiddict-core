// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using System.ComponentModel;

namespace NWebsec.Core.HttpHeaders.Configuration
{
    /// <summary>
    ///     Defines the properties required for CSP directive configuration.
    /// </summary>
    public interface ICspDirectiveUnsafeInlineConfiguration : ICspDirectiveBasicConfiguration
    {
        /// <summary>
        ///     Infrastructure. Not intended to be used by your code directly. An attempt to hide this from Intellisense has been
        ///     made.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        bool UnsafeInlineSrc { get; set; }

        /// <summary>
        ///     Infrastructure. Not intended to be used by your code directly. An attempt to hide this from Intellisense has been
        ///     made.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        string Nonce { get; set; }
    }
}