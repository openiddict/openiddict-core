// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;

namespace NWebsec.Middleware.Core
{
    internal class ResponseHeaders
    {
        private readonly IDictionary<string, string[]> _headers;

        internal ResponseHeaders(IDictionary<string, string[]> headers)
        {
            _headers = headers;
        }

        /// <summary>
        /// Gets the value of the Location header if present. Otherwise returns null.
        /// </summary>
        public string Location
        {
            get
            {
                try
                {
                    return _headers.ContainsKey("Location") ? _headers["Location"].Single() : null;
                }
                catch (Exception)
                {
                    throw new Exception("Multiple Location headers detected: " + String.Join(" ", _headers["Location"]));
                }
            }
            set { _headers["Location"] = new[] { value }; }
        }

        internal void SetHeader(string name, string value)
        {
            _headers[name] = new[] { value };
        }

        internal void RemoveHeader(string name)
        {
            _headers.Remove(name);
        }
    }
}