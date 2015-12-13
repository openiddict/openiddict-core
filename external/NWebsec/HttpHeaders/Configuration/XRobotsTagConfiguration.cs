// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

namespace NWebsec.Core.HttpHeaders.Configuration
{
    public class XRobotsTagConfiguration : IXRobotsTagConfiguration
    {
        public bool Enabled { get; set; }
        public bool NoIndex { get; set; }
        public bool NoFollow { get; set; }
        public bool NoSnippet { get; set; }
        public bool NoArchive { get; set; }
        public bool NoOdp { get; set; }
        public bool NoTranslate { get; set; }
        public bool NoImageIndex { get; set; }
    }
}