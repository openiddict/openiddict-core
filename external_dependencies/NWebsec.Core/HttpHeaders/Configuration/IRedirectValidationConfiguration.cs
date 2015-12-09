// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using System.Collections.Generic;

namespace NWebsec.Core.HttpHeaders.Configuration
{
    public interface IRedirectValidationConfiguration
    {
        bool Enabled { get; set; }

        /// <summary>
        ///     URIs allowed for redirect. Strings in this list should be created with Uri.AbsoluteUri to assure consistency.
        /// </summary>
        IEnumerable<string> AllowedUris { get; set; }

        ISameHostHttpsRedirectConfiguration SameHostRedirectConfiguration { get; set; }
    }
}