// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using System;
using NWebsec.Core.HttpHeaders.Configuration;

namespace NWebsec.Middleware
{
    public class CspOptions : ICspConfiguration, IFluentCspOptions
    {
        public bool Enabled { get; set; } = true;

        public ICspDirectiveConfiguration DefaultSrcDirective { get; set; } = new CspDirective();

        public ICspDirectiveConfiguration ScriptSrcDirective { get; set; } = new CspDirective();

        public ICspDirectiveConfiguration ObjectSrcDirective { get; set; } = new CspDirective();

        public ICspDirectiveConfiguration StyleSrcDirective { get; set; } = new CspDirective();

        public ICspDirectiveConfiguration ImgSrcDirective { get; set; } = new CspDirective();

        public ICspDirectiveConfiguration MediaSrcDirective { get; set; } = new CspDirective();

        public ICspDirectiveConfiguration FrameSrcDirective { get; set; } = new CspDirective();

        public ICspDirectiveConfiguration FontSrcDirective { get; set; } = new CspDirective();

        public ICspDirectiveConfiguration ConnectSrcDirective { get; set; } = new CspDirective();

        public ICspDirectiveConfiguration BaseUriDirective { get; set; } = new CspDirective();

        public ICspDirectiveConfiguration ChildSrcDirective { get; set; } = new CspDirective();

        public ICspDirectiveConfiguration FormActionDirective { get; set; } = new CspDirective();

        public ICspDirectiveConfiguration FrameAncestorsDirective { get; set; } = new CspDirective();

        public ICspPluginTypesDirectiveConfiguration PluginTypesDirective { get; set; } = new FluentCspPluginTypesDirective();

        public ICspSandboxDirectiveConfiguration SandboxDirective { get; set; } = new FluentCspSandboxDirective();

        public ICspUpgradeDirectiveConfiguration UpgradeInsecureRequestsDirective { get; set; } = new CspUpgradeDirectiveConfiguration();

        public ICspReportUriDirectiveConfiguration ReportUriDirective { get; set; } = new CspReportUriDirective();

        public IFluentCspOptions DefaultSources(Action<ICspDirectiveBasicConfiguration> configurer)
        {
            configurer(DefaultSrcDirective);
            return this;
        }

        public IFluentCspOptions ScriptSources(Action<ICspDirectiveConfiguration> configurer)
        {
            configurer(ScriptSrcDirective);
            return this;
        }

        public IFluentCspOptions ObjectSources(Action<ICspDirectiveBasicConfiguration> configurer)
        {
            configurer(ObjectSrcDirective);
            return this;
        }

        public IFluentCspOptions StyleSources(Action<ICspDirectiveUnsafeInlineConfiguration> configurer)
        {
            configurer(StyleSrcDirective);
            return this;
        }

        public IFluentCspOptions ImageSources(Action<ICspDirectiveBasicConfiguration> configurer)
        {
            configurer(ImgSrcDirective);
            return this;
        }

        public IFluentCspOptions MediaSources(Action<ICspDirectiveBasicConfiguration> configurer)
        {
            configurer(MediaSrcDirective);
            return this;
        }

        public IFluentCspOptions FrameSources(Action<ICspDirectiveBasicConfiguration> configurer)
        {
            configurer(FrameSrcDirective);
            return this;
        }

        public IFluentCspOptions FontSources(Action<ICspDirectiveBasicConfiguration> configurer)
        {
            configurer(FontSrcDirective);
            return this;
        }

        public IFluentCspOptions ConnectSources(Action<ICspDirectiveBasicConfiguration> configurer)
        {
            configurer(ConnectSrcDirective);
            return this;
        }

        public IFluentCspOptions BaseUris(Action<ICspDirectiveBasicConfiguration> configurer)
        {
            configurer(BaseUriDirective);
            return this;
        }

        public IFluentCspOptions ChildSources(Action<ICspDirectiveBasicConfiguration> configurer)
        {
            configurer(ChildSrcDirective);
            return this;
        }

        public IFluentCspOptions FormActions(Action<ICspDirectiveBasicConfiguration> configurer)
        {
            configurer(FormActionDirective);
            return this;
        }

        public IFluentCspOptions FrameAncestors(Action<ICspDirectiveBasicConfiguration> configurer)
        {
            configurer(FrameAncestorsDirective);
            return this;
        }

        public IFluentCspOptions PluginTypes(Action<IFluentCspPluginTypesDirective> configurer)
        {
            configurer((IFluentCspPluginTypesDirective)PluginTypesDirective);
            return this;
        }

        public IFluentCspOptions Sandbox()
        {
            SandboxDirective.Enabled = true;
            return this;
        }

        public IFluentCspOptions Sandbox(Action<IFluentCspSandboxDirective> configurer)
        {
            SandboxDirective.Enabled = true;
            configurer((IFluentCspSandboxDirective)SandboxDirective);
            return this;
        }

        public IFluentCspOptions UpgradeInsecureRequests(int httpsPort = 443)
        {
            if (httpsPort < 1 || httpsPort > 65535)
            {
                throw new ArgumentOutOfRangeException(nameof(httpsPort),"The port number must be in the range 1-65535.");
            }

            UpgradeInsecureRequestsDirective.Enabled = true;
            UpgradeInsecureRequestsDirective.HttpsPort = httpsPort;
            return this;
        }

        public IFluentCspOptions ReportUris(Action<IFluentCspReportUriDirective> configurer)
        {
            configurer((IFluentCspReportUriDirective)ReportUriDirective);
            return this;
        }
    }
}