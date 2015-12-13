// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using System;

namespace NWebsec.Core.HttpHeaders.Configuration.Validation
{
    public class XRobotsTagConfigurationValidator
    {
        public void Validate(IXRobotsTagConfiguration xRobotsConfig)
        {
            if (!xRobotsConfig.Enabled) return;

            if (xRobotsConfig.NoArchive ||
                xRobotsConfig.NoFollow ||
                xRobotsConfig.NoImageIndex ||
                xRobotsConfig.NoIndex ||
                xRobotsConfig.NoOdp ||
                xRobotsConfig.NoSnippet ||
                xRobotsConfig.NoTranslate) return;
            throw new Exception(
                "One or more directives must be enabled when header is enabled. Enable directives or disable header.");
        }
    }
}