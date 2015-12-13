// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using System;

namespace NWebsec.Core.HttpHeaders.Configuration
{
    public interface IHstsConfiguration
    {
        TimeSpan MaxAge { get; set; }

        bool IncludeSubdomains { get; set; }

        bool Preload { get; set; }

        bool HttpsOnly { get; set; }

        bool UpgradeInsecureRequests { get; set; }
    }
}