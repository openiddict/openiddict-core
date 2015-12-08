// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using NWebsec.Core.Helpers.X509;
using NWebsec.Core.HttpHeaders.Configuration.Validation;

namespace NWebsec.Middleware
{
    public class HpkpOptions : IFluentHpkpOptions
    {
        private readonly List<string> _pins;
        private readonly HpkpConfigurationValidator _validator;

        internal HpkpOptionsConfiguration Config { get; set; }

        public HpkpOptions()
        {
            _pins = new List<string>();
            Config = new HpkpOptionsConfiguration { Pins = _pins };
            _validator = new HpkpConfigurationValidator();
        }

        // ReSharper disable once CSharpWarnings::CS0109
        public IFluentHpkpOptions MaxAge(int days = 0, int hours = 0, int minutes = 0, int seconds = 0)
        {
            if (days < 0) throw new ArgumentOutOfRangeException("days", "Value must be equal to or larger than 0.");
            if (hours < 0) throw new ArgumentOutOfRangeException("hours", "Value must be equal to or larger than 0.");
            if (minutes < 0) throw new ArgumentOutOfRangeException("minutes", "Value must be equal to or larger than 0.");
            if (seconds < 0) throw new ArgumentOutOfRangeException("seconds", "Value must be equal to or larger than 0.");

            Config.MaxAge = new TimeSpan(days, hours, minutes, seconds);
            return this;
        }

        public IFluentHpkpOptions IncludeSubdomains()
        {
            Config.IncludeSubdomains = true;
            return this;
        }

        public IFluentHpkpOptions ReportUri(string reportUri)
        {
            try
            {
                _validator.ValidateReportUri(reportUri);
            }
            catch (Exception e)
            {
                throw new ArgumentException(e.Message, "reportUri");
            }

            Config.ReportUri = reportUri;
            return this;
        }

        public IFluentHpkpOptions AllResponses()
        {
            Config.HttpsOnly = false;
            return this;
        }

        public IFluentHpkpOptions Sha256Pins(params string[] pins)
        {
            foreach (var pin in pins)
            {
                try
                {
                    _validator.ValidateRawPin(pin);
                }
                catch (Exception e)
                {
                    throw new ArgumentException(e.Message, "pins");
                }

                var formattedPin = "sha256=\"" + pin + "\"";
                if (!_pins.Contains(formattedPin))
                {
                    _pins.Add(formattedPin);
                }
            }
            return this;
        }

        public IFluentHpkpOptions PinCertificate(string thumbprint, StoreLocation storeLocation = StoreLocation.LocalMachine,
            StoreName storeName = StoreName.My)
        {

            try
            {
                _validator.ValidateThumbprint(thumbprint);
            }
            catch (Exception e)
            {
                throw new ArgumentException(e.Message, thumbprint);
            }

            var helper = new X509Helper();
            var cert = helper.GetCertByThumbprint(thumbprint, storeLocation, storeName);
            var pin = helper.GetSubjectPublicKeyInfoPinValue(cert);

#if DNX451
            cert.Reset();
#elif NET451
            cert.Reset();
#else
            cert.Dispose();
#endif
            if (!_pins.Contains(pin))
            {
                _pins.Add(pin);
            }

            return this;
        }

        public IFluentHpkpOptions HttpsOnly()
        {
            Config.HttpsOnly = true;
            return this;
        }
    }
}