// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

namespace NWebsec.Core.HttpHeaders
{
    public enum XfoPolicy
    {
        /// <summary>Specifies that the X-Frame-Options header should not be set in the HTTP response.</summary>
        Disabled,

        /// <summary>
        ///     Specifies that the X-Frame-Options header should be set in the HTTP response, instructing the browser to not
        ///     display the page when it is loaded in an iframe.
        /// </summary>
        Deny,

        /// <summary>
        ///     Specifies that the X-Frame-Options header should be set in the HTTP response, instructing the browser to
        ///     display the page when it is loaded in an iframe - but only if the iframe is from the same origin as the page.
        /// </summary>
        SameOrigin
    }
}