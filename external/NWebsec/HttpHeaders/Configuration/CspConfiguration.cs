// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

namespace NWebsec.Core.HttpHeaders.Configuration
{
    public class CspConfiguration : ICspConfiguration
    {
        public CspConfiguration(bool initializeDirectives=true)
        {
            if (!initializeDirectives)
            {
                return;
            }

            DefaultSrcDirective = new CspDirectiveConfiguration();
            ScriptSrcDirective = new CspDirectiveConfiguration();
            ObjectSrcDirective = new CspDirectiveConfiguration();
            StyleSrcDirective = new CspDirectiveConfiguration();
            ImgSrcDirective = new CspDirectiveConfiguration();
            MediaSrcDirective = new CspDirectiveConfiguration();
            FrameSrcDirective = new CspDirectiveConfiguration();
            FontSrcDirective = new CspDirectiveConfiguration();
            ConnectSrcDirective = new CspDirectiveConfiguration();
            BaseUriDirective = new CspDirectiveConfiguration();
            ChildSrcDirective = new CspDirectiveConfiguration();
            FormActionDirective = new CspDirectiveConfiguration();
            FrameAncestorsDirective = new CspDirectiveConfiguration();
            PluginTypesDirective = new CspPluginTypesDirectiveConfiguration();
            SandboxDirective = new CspSandboxDirectiveConfiguration();
            UpgradeInsecureRequestsDirective = new CspUpgradeDirectiveConfiguration();
            ReportUriDirective = new CspReportUriDirectiveConfiguration();
        }

        public bool Enabled { get; set; }
        public ICspDirectiveConfiguration DefaultSrcDirective { get; set; }
        public ICspDirectiveConfiguration ScriptSrcDirective { get; set; }
        public ICspDirectiveConfiguration ObjectSrcDirective { get; set; }
        public ICspDirectiveConfiguration StyleSrcDirective { get; set; }
        public ICspDirectiveConfiguration ImgSrcDirective { get; set; }
        public ICspDirectiveConfiguration MediaSrcDirective { get; set; }
        public ICspDirectiveConfiguration FrameSrcDirective { get; set; }
        public ICspDirectiveConfiguration FontSrcDirective { get; set; }
        public ICspDirectiveConfiguration ConnectSrcDirective { get; set; }
        public ICspDirectiveConfiguration BaseUriDirective { get; set; }
        public ICspDirectiveConfiguration ChildSrcDirective { get; set; }
        public ICspDirectiveConfiguration FormActionDirective { get; set; }
        public ICspDirectiveConfiguration FrameAncestorsDirective { get; set; }
        public ICspPluginTypesDirectiveConfiguration PluginTypesDirective { get; set; }
        public ICspSandboxDirectiveConfiguration SandboxDirective { get; set; }
        public ICspUpgradeDirectiveConfiguration UpgradeInsecureRequestsDirective { get; set; }
        public ICspReportUriDirectiveConfiguration ReportUriDirective { get; set; }
    }
}