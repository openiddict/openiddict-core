// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;

namespace NWebsec.Core.HttpHeaders.Configuration
{
    public class HpkpConfiguration : IHpkpConfiguration
    {
        public IEnumerable<string> Pins { get; set; }
        public TimeSpan MaxAge { get; set; }
        public bool IncludeSubdomains { get; set; }
        public string ReportUri { get; set; }
        public bool HttpsOnly { get; set; }
    }
}