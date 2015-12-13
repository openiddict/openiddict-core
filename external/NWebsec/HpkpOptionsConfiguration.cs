// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.ComponentModel;
using NWebsec.Core.HttpHeaders.Configuration;

namespace NWebsec.Middleware
{
    public class HpkpOptionsConfiguration : IHpkpConfiguration
    {
        internal HpkpOptionsConfiguration()
        {
            MaxAge = TimeSpan.Zero;
            HttpsOnly = true;
            Pins = new string[0];
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public IEnumerable<string> Pins { get; set; }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public TimeSpan MaxAge { get; set; }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool IncludeSubdomains { get; set; }

        public string ReportUri { get; set; }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool HttpsOnly { get; set; }
    }
}