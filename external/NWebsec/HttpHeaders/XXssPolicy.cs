// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

namespace NWebsec.Core.HttpHeaders
{
    public enum XXssPolicy
    {
        /// <summary>Specifies that the X-Xss-Protection header should not be set in the HTTP response.</summary>
        Disabled,

        /// <summary>
        ///     Specifies that the X-Xss-Protection header should be set in the HTTP response, explicitly disabling the IE XSS
        ///     filter.
        /// </summary>
        FilterDisabled,

        /// <summary>
        ///     Specifies that the X-Xss-Protection header should be set in the HTTP response, explicitly enabling the IE XSS
        ///     filter.
        /// </summary>
        FilterEnabled
    }
}