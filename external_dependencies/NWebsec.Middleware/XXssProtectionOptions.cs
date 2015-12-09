// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using System.ComponentModel;
using NWebsec.Core.HttpHeaders;
using NWebsec.Core.HttpHeaders.Configuration;

namespace NWebsec.Middleware
{
    public class XXssProtectionOptions : IXXssProtectionConfiguration, IFluentXXssProtectionOptions
    {
        internal XXssProtectionOptions()
        {
            Policy = XXssPolicy.Disabled;
        }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public XXssPolicy Policy { get; set; }

        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool BlockMode { get; set; }

        public void Disabled()
        {
            Policy = XXssPolicy.FilterDisabled;
        }

        public void Enabled()
        {
            Policy = XXssPolicy.FilterEnabled;
        }

        public void EnabledWithBlockMode()
        {
            Policy = XXssPolicy.FilterEnabled;
            BlockMode = true;
        }
    }
}