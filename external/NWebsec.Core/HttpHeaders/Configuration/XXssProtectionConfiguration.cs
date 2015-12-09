// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

namespace NWebsec.Core.HttpHeaders.Configuration
{
    public class XXssProtectionConfiguration : IXXssProtectionConfiguration
    {
        public XXssPolicy Policy { get; set; }
        public bool BlockMode { get; set; }
    }
}