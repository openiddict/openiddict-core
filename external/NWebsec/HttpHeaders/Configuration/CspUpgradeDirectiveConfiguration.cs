// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

namespace NWebsec.Core.HttpHeaders.Configuration
{
    public class CspUpgradeDirectiveConfiguration : ICspUpgradeDirectiveConfiguration
    {

        public bool Enabled { get; set; }
        public int HttpsPort { get; set; } = 443;
    }
}