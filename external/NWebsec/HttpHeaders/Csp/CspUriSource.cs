// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using System;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace NWebsec.Core.HttpHeaders.Csp
{
    public class CspUriSource
    {
        private const string HostRegex = @"^(\*\.)?([\p{Ll}\p{Lu}0-9\-]+)(\.[\p{Ll}\p{Lu}0-9\-]+)*$";
        private static readonly string SchemeOnlyRegex = "^[a-zA-Z]*[a-zA-Z0-9" + Regex.Escape("+.-") + "]:$";
        private static readonly string[] KnownSchemes = { "http", "https", "ws", "wss" };
        private readonly string _source;

        private CspUriSource(string source)
        {
            _source = source;
        }

        // Returns the source as a string encoded according to the CSP spec.
        public override string ToString()
        {
            return _source;

        }

        public static string EncodeUri(Uri uri)
        {

            if (!uri.IsAbsoluteUri)
            {
                var uriString = uri.IsWellFormedOriginalString() ? uri.ToString() : Uri.EscapeUriString(uri.ToString());
                return EscapeReservedCspChars(uriString);
            }

            var host = uri.Host;
            var encodedHost = EncodeHostname(host);

            var needsReplacement = !host.Equals(encodedHost);

            var authority = uri.GetComponents(UriComponents.SchemeAndServer, UriFormat.SafeUnescaped);

            if (needsReplacement)
            {
                authority = authority.Replace(host, encodedHost);
            }

            if (uri.PathAndQuery.Equals("/"))
            {
                return authority;
            }

            return authority + EscapeReservedCspChars(uri.PathAndQuery);
        }

        public static CspUriSource Parse(string source)
        {
            if (String.IsNullOrEmpty(source)) throw new ArgumentException("Value was null or empty", "source");

            if (source.Equals("*")) return new CspUriSource(source);

            Uri uriResult; //TODO figure out what happened to known schemes.
            if (Uri.TryCreate(source, UriKind.Absolute, out uriResult) && KnownSchemes.Contains(uriResult.Scheme))
            {
                return new CspUriSource(EncodeUri(uriResult));
            }

            //Scheme only source
            if (Regex.IsMatch(source, SchemeOnlyRegex)) return new CspUriSource(source.ToLower());

            var parseResult = ParseSourceComponents(source);
            var sb = new StringBuilder();

            if (!String.IsNullOrEmpty(parseResult.Scheme))
            {
                if (!Regex.IsMatch(parseResult.Scheme, SchemeOnlyRegex))
                {
                    throw new InvalidCspSourceException("Invalid scheme in CSP source: " + source);
                }
                sb.Append(parseResult.Scheme.ToLower()).Append("//");
            }

            if (String.IsNullOrEmpty(parseResult.Host))
            {
                throw new InvalidCspSourceException("Could not parse host in CSP source: " + source);
            }

            if (!Regex.IsMatch(parseResult.Host, HostRegex))
            {
                throw new InvalidCspSourceException("Invalid host in CSP source: " + source);

            }

            sb.Append(EncodeHostname(parseResult.Host.ToLower()));

            if (!String.IsNullOrEmpty(parseResult.Port))
            {
                if (!ValidatePort(parseResult.Port))
                {
                    throw new InvalidCspSourceException("Invalid port in CSP source: " + source);
                }
                sb.Append(":").Append(parseResult.Port);
            }

            if (!String.IsNullOrEmpty(parseResult.PathAndQuery))
            {
                sb.Append(EscapeReservedCspChars(Uri.EscapeUriString(parseResult.PathAndQuery)));
            }

            return new CspUriSource(sb.ToString());
        }

        private static CspSourceParseResult ParseSourceComponents(string uri)
        {
            const string regex = @"^((?<scheme>.*?:)\/\/)?" + // match anything up to ://
                                 @"(?<host>.*?[^:\/])" + //then match anything up to a : or /
                                 @"(:(?<port>(.*?[^\/])))?" + //then match port if exists up to a /
                                 @"(?<pathAndQuery>\/.*)?$"; //grab the rest

            var re = new Regex(regex, RegexOptions.ExplicitCapture);
            var result = re.Match(uri);

            if (!result.Success)
            {
                throw new InvalidCspSourceException("Malformed CSP source: " + uri);
            }

            return new CspSourceParseResult
            {
                Scheme = result.Groups["scheme"].Value,
                Host = result.Groups["host"].Value,
                Port = result.Groups["port"].Value,
                PathAndQuery = result.Groups["pathAndQuery"].Value
            };
        }

        private static string EncodeHostname(string hostname)
        {
            var idn = new IdnMapping();

            return idn.GetAscii(hostname);
        }

        private static string EscapeReservedCspChars(string pathAndQuery)
        {
            char[] encodeChars = { ';', ',' };

            if (pathAndQuery.IndexOfAny(encodeChars) == -1)
            {
                return pathAndQuery;
            }

            var sb = new StringBuilder(pathAndQuery);
            sb.Replace(";", "%3B");
            sb.Replace(",", "%2C");

            return sb.ToString();
        }

        private static bool ValidatePort(string port)
        {
            if (port.Equals("*")) return true;

            int portNumber;
            var isInt = Int32.TryParse(port, out portNumber);
            return isInt && portNumber > 0 && portNumber <= 65535;
        }
    }
}