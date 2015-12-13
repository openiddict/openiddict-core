// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using System.Collections.Generic;

namespace NWebsec.Core.HttpHeaders.Configuration
{
    internal class RedirectValidationConfiguration : IRedirectValidationConfiguration
    {
        public RedirectValidationConfiguration()
        {
            AllowedUris = new string[0];
            SameHostRedirectConfiguration = new SameHostHttpsRedirectConfiguration();
        }

        public bool Enabled { get; set; }
        public IEnumerable<string> AllowedUris { get; set; }
        public ISameHostHttpsRedirectConfiguration SameHostRedirectConfiguration { get; set; }
    }
}