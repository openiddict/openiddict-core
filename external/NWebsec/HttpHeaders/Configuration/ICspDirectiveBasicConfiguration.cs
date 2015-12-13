// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using System.Collections.Generic;
using System.ComponentModel;
using NWebsec.Core.Fluent;

namespace NWebsec.Core.HttpHeaders.Configuration
{
    /// <summary>
    ///     Defines the properties required for CSP directive configuration.
    /// </summary>
    public interface ICspDirectiveBasicConfiguration : IFluentInterface
    {
        /// <summary>
        ///     Infrastructure. Not intended to be used by your code directly. An attempt to hide this from Intellisense has been
        ///     made.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        bool Enabled { get; set; }

        /// <summary>
        ///     Infrastructure. Not intended to be used by your code directly. An attempt to hide this from Intellisense has been
        ///     made.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        bool NoneSrc { get; set; }

        /// <summary>
        ///     Infrastructure. Not intended to be used by your code directly. An attempt to hide this from Intellisense has been
        ///     made.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        bool SelfSrc { get; set; }

        /// <summary>
        ///     Infrastructure. Not intended to be used by your code directly. An attempt to hide this from Intellisense has been
        ///     made.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        IEnumerable<string> CustomSources { get; set; }
    }
}