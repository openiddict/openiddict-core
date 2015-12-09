// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

namespace NWebsec.Core.HttpHeaders.Configuration
{
    public class XFrameOptionsConfiguration : IXFrameOptionsConfiguration
    {
        public XfoPolicy Policy { get; set; }
    }
}