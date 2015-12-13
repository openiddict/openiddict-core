// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

namespace NWebsec.Core.HttpHeaders.Configuration
{
    public interface IXRobotsTagConfiguration
    {
        bool Enabled { get; set; }

        bool NoIndex { get; set; }

        bool NoFollow { get; set; }

        bool NoSnippet { get; set; }

        bool NoArchive { get; set; }

        bool NoOdp { get; set; }

        bool NoTranslate { get; set; }

        bool NoImageIndex { get; set; }
    }
}