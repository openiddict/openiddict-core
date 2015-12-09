// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using System.Collections.Generic;

namespace NWebsec.Core.HttpHeaders.Configuration
{
    public class CspReportUriDirectiveConfiguration : ICspReportUriDirectiveConfiguration
    {
        public CspReportUriDirectiveConfiguration()
        {
            ReportUris = new string[0];
        }

        public bool Enabled { get; set; }
        //TODO figure out what to do with this property
        public bool EnableBuiltinHandler { get; set; }
        public IEnumerable<string> ReportUris { get; set; }
    }
}