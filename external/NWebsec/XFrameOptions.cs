// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using NWebsec.Core.HttpHeaders;
using NWebsec.Core.HttpHeaders.Configuration;

namespace NWebsec.Middleware
{
    public class XFrameOptions : IXFrameOptionsConfiguration, IFluentXFrameOptions
    {
        internal XFrameOptions()
        {
            Policy = XfoPolicy.Disabled;
        }

        public XfoPolicy Policy { get; set; }

        public void Deny()
        {
            Policy = XfoPolicy.Deny;
        }

        public void SameOrigin()
        {
            Policy = XfoPolicy.SameOrigin;
        }
    }
}