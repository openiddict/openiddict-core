// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using System;
using System.ComponentModel;
using NWebsec.Core.HttpHeaders.Configuration;

namespace NWebsec.Middleware
{
    public class HstsOptionsConfiguration : IHstsConfiguration
    {
        internal HstsOptionsConfiguration()
        {
            MaxAge = TimeSpan.Zero;
            HttpsOnly = true;
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public TimeSpan MaxAge { get; set; }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool IncludeSubdomains { get; set; }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool Preload { get; set; }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool HttpsOnly { get; set; }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool UpgradeInsecureRequests { get; set; }
    }
}