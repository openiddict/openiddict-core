// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;

namespace NWebsec.Core.HttpHeaders.Configuration
{
    public interface IHpkpConfiguration
    {
        IEnumerable<string> Pins { get; set; }
        TimeSpan MaxAge { get; set; }
        bool IncludeSubdomains { get; set; }
        string ReportUri { get; set; }
        bool HttpsOnly { get; set; }
    }
}