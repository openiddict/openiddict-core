// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using System;
using System.Security.Cryptography.X509Certificates;
using NWebsec.Core.Fluent;

namespace NWebsec.Middleware
{
    /// <summary>
    /// Fluent interface to configure options for Http Strict Transport Security.
    /// </summary>
    public interface IFluentHpkpOptions : IFluentInterface
    {
        /// <summary>
        /// Specifies the max age for the HPKP header.
        /// </summary>
        /// <param name="days">The number of days added to max age.</param>
        /// <param name="hours">The number of hours added to max age.</param>
        /// <param name="minutes">The number of minutes added to max age.</param>
        /// <param name="seconds">The number of seconds added to max age.</param>
        /// <returns>The current instance.</returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown if a negative value was supplied in any of the parameters.</exception>
        IFluentHpkpOptions MaxAge(int days = 0, int hours = 0, int minutes = 0, int seconds = 0);

        /// <summary>
        /// Enables the IncludeSubdomains directive in the HPKP header.
        /// </summary>
        /// <returns>The current instance.</returns>
        IFluentHpkpOptions IncludeSubdomains();

        /// <summary>
        /// Specifies a report URI where the browser can send HPKP violations.
        /// </summary>
        /// <param name="reportUri">The report URI, which is an absolute URI with scheme http or https.</param>
        /// <returns>The current instance.</returns>
        IFluentHpkpOptions ReportUri(string reportUri);

        /// <summary>
        /// Specifies that the HPKP header should also be set for HTTP responses. The header is always set for HTTPS responses.
        /// </summary>
        /// <remarks>The HPKP standard specifies that the header should only be set over secure connections, which is the default behavior.
        /// This configuration option exists to accomodate websites running behind an SSL terminator.</remarks>
        /// <returns>The current instance.</returns>
        IFluentHpkpOptions AllResponses();

        /// <summary>
        /// Specifies one or more certificate pins to include in the HPKP header. A certificate pin is the Base64 encoded SHA-256 hash value of a certficate's SPKI.
        /// </summary>
        /// <param name="pins">One or more certficate pin values.</param>
        /// <returns>The current instance.</returns>
        IFluentHpkpOptions Sha256Pins(params string[] pins);

        /// <summary>
        /// Specifies a certificate that should be pinned in the HPKP header.
        /// </summary>
        /// <param name="thumbprint">The certificate thumbprint.</param>
        /// <param name="storeLocation">The <see cref="StoreLocation"/> for the certificate. The default is <see cref="StoreLocation.LocalMachine"/>.</param>
        /// <param name="storeName">The <see cref="StoreName"/> for the certificate. The default is <see cref="StoreName.My"/>.</param>
        /// <returns>The current instance.</returns>
        IFluentHpkpOptions PinCertificate(string thumbprint, StoreLocation storeLocation = StoreLocation.LocalMachine, StoreName storeName = StoreName.My);
    }
}