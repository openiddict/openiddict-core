// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

namespace NWebsec.Core.HttpHeaders.Csp
{
    internal class CspSourceParseResult
    {
        public string Scheme { get; set; }
        public string Host { get; set; }
        public string Port { get; set; }
        public string PathAndQuery { get; set; }
    }
}