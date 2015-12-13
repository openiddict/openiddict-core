// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

namespace NWebsec.Core.HttpHeaders.Configuration
{
    public interface ISameHostHttpsRedirectConfiguration
    {
        bool Enabled { get; set; }
        int[] Ports { get; set; }
    }
}