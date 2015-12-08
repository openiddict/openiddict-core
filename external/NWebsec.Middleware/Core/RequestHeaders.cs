// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;

namespace NWebsec.Middleware.Core
{
    internal class RequestHeaders
    {
        private readonly IDictionary<string, string[]> _headers;

        internal RequestHeaders(IDictionary<string, string[]> headers)
        {
            _headers = headers;
        }

        public string Host
        {
            get
            {
                try
                {
                    return _headers.ContainsKey("Host") ? _headers["Host"].Single() : null;
                }
                catch (Exception)
                {
                    throw new Exception("Multiple Host headers detected: " + String.Join(" ", _headers["Host"]));
                }
            }
        }

        /// <summary>
        /// Gets the value of a header
        /// </summary>
        /// <param name="headername"></param>
        /// <returns>The header's values as a comma separated list, null if the header is not set.</returns>
        public string GetHeaderValue(string headername)
        {
            string[] values;
            return _headers.TryGetValue(headername, out values) ? String.Join(",", values) : null;
        }
    }
}