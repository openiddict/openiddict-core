// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

namespace NWebsec.Core.HttpHeaders.Configuration
{
    /// <summary>
    ///     Defines the properties required for CSP sandbox directive configuration.
    /// </summary>
    public interface ICspUpgradeDirectiveConfiguration
    {
        bool Enabled { get; set; }

        int HttpsPort { get; set; }
    }
}