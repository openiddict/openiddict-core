// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using NWebsec.Core.HttpHeaders.Configuration;
using NWebsec.Core.HttpHeaders.Csp;

namespace NWebsec.Middleware
{
    public class CspReportUriDirective : ICspReportUriDirectiveConfiguration, IFluentCspReportUriDirective
    {
        internal CspReportUriDirective()
        {
            Enabled = true;
        }

        public bool Enabled { get; set; }
        public bool EnableBuiltinHandler { get; set; }
        public IEnumerable<string> ReportUris { get; set; }

        public void Uris(params string[] reportUris)
        {
            if (reportUris.Length == 0) throw new ArgumentException("You must supply at least one report URI.", "reportUris");

            var reportUriList = new List<string>();

            foreach (var reportUri in reportUris)
            {
                Uri uri;
                if (!Uri.TryCreate(reportUri, UriKind.RelativeOrAbsolute, out uri))
                {
                    throw new ArgumentException("Could not parse reportUri: " + reportUri);
                }

                reportUriList.Add(CspUriSource.EncodeUri(uri));
            }
            ReportUris = reportUriList.ToArray();
        }
    }
}