// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using System.Collections.Generic;

namespace NWebsec.Core.HttpHeaders.Configuration
{
    public class CspDirectiveConfiguration : ICspDirectiveConfiguration
    {
        private static readonly string[] EmptySources = new string[0];

        public CspDirectiveConfiguration()
        {
            Enabled = true;
            CustomSources = EmptySources;
        }

        public bool Enabled { get; set; }
        public bool NoneSrc { get; set; }
        public bool SelfSrc { get; set; }
        public bool UnsafeInlineSrc { get; set; }
        public bool UnsafeEvalSrc { get; set; }
        public IEnumerable<string> CustomSources { get; set; }
        public string Nonce { get; set; }

    }
}