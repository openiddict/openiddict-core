// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using System;

namespace NWebsec.Core.HttpHeaders.Configuration.Validation
{
    public class HstsConfigurationValidator
    {
        public void Validate(IHstsConfiguration hstsConfig)
        {
            if (!hstsConfig.Preload) return;

            if (hstsConfig.UpgradeInsecureRequests)
            {
                throw new Exception("The Preload setting cannot be combined with the UpgradeInsecureRequests setting. Use one or the other.");
            }

            if (hstsConfig.MaxAge.TotalSeconds < 10886400 || !hstsConfig.IncludeSubdomains)
            {
                throw new Exception("HSTS max age must be at least 18 weeks and includesubdomains must be enabled to use the preload directive.");
            }
        }
    }
}