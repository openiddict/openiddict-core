// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

namespace NWebsec.Core.HttpHeaders
{
    public class HeaderConstants
    {
        public static readonly string XFrameOptionsHeader = "X-Frame-Options";
        public static readonly string XRobotsTagHeader = "X-Robots-Tag";
        public static readonly string StrictTransportSecurityHeader = "Strict-Transport-Security";
        public static readonly string XContentTypeOptionsHeader = "X-Content-Type-Options";
        public static readonly string XDownloadOptionsHeader = "X-Download-Options";
        public static readonly string XXssProtectionHeader = "X-XSS-Protection";
        public static readonly string ContentSecurityPolicyHeader = "Content-Security-Policy";
        public static readonly string ContentSecurityPolicyReportOnlyHeader = "Content-Security-Policy-Report-Only";
        public static readonly string HpkpHeader = "Public-Key-Pins";
        public static readonly string HpkpReportOnlyHeader = "Public-Key-Pins-Report-Only";

        public static readonly string[] CspSourceList =
        {
            "'none'",
            "'self'",
            "'unsafe-inline'",
            "'unsafe-eval'"
        };

        public static readonly string[] CspDirectives =
        {
            "default-src",
            "script-src",
            "object-src",
            "style-src",
            "img-src",
            "media-src",
            "frame-src",
            "font-src",
            "connect-src",
            "report-uri"
        };

        public static readonly string[] CspSchemes =
        {
            "data:",
            "https:",
            "http:"
        };
    }
}