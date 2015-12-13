// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

namespace NWebsec.Core.HttpHeaders.Configuration
{
    public class CspSandboxDirectiveConfiguration : ICspSandboxDirectiveConfiguration
    {
        public bool Enabled { get; set; }
        public bool AllowForms { get; set; }
        public bool AllowPointerLock { get; set; }
        public bool AllowPopups { get; set; }
        public bool AllowSameOrigin { get; set; }
        public bool AllowScripts { get; set; }
        public bool AllowTopNavigation { get; set; }
    }
}