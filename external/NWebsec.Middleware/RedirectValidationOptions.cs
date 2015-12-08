// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using NWebsec.Core.HttpHeaders.Configuration;

namespace NWebsec.Middleware
{
    public class RedirectValidationOptions : IRedirectValidationConfiguration, IFluentRedirectValidationOptions
    {
        public RedirectValidationOptions()
        {
            Enabled = true;
            AllowedUris = new string[0];
            SameHostRedirectConfiguration = new SameHostHttpsRedirectConfiguration();
        }

        public bool Enabled { get; set; }
        public IEnumerable<string> AllowedUris { get; set; }
        public ISameHostHttpsRedirectConfiguration SameHostRedirectConfiguration { get; set; }

        public IFluentRedirectValidationOptions AllowedDestinations(params string[] uris)
        {
            if (uris.Length == 0) throw new ArgumentException("You must supply at least one redirect URI.");

            var validatedUris = new List<string>();

            foreach (var uri in uris)
            {
                Uri result;
                if (!Uri.TryCreate(uri, UriKind.Absolute, out result))
                {
                    throw new ArgumentException("Redirect URIs must be well formed absolute URIs. Offending URI: " + uri);
                }
                validatedUris.Add(result.AbsoluteUri);
            }

            AllowedUris = validatedUris.ToArray();
            return this;
        }

        public IFluentRedirectValidationOptions AllowSameHostRedirectsToHttps(params int[] httpsPorts)
        {
            var invalidPorts = httpsPorts.Where(p => p < 1 || p > 65535).ToArray();

            if (invalidPorts.Length > 0)
            {
                var ports = String.Join(" ", invalidPorts.Select(p => p.ToString(CultureInfo.InvariantCulture)).ToArray());
                var invalidPortNumberMessage = "Invalid ports configured. Port number(s) must be in the range 1-65535. Offending ports: " + ports;
                throw new ArgumentOutOfRangeException(invalidPortNumberMessage);
            }

            SameHostRedirectConfiguration.Enabled = true;
            SameHostRedirectConfiguration.Ports = httpsPorts;

            return this;
        }
    }
}