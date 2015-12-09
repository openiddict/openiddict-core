// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Http;
using NWebsec.Core.Extensions;
using NWebsec.Core.HttpHeaders;
using NWebsec.Core.HttpHeaders.Configuration;

namespace NWebsec.Middleware.Middleware
{
    public class XContentTypeOptionsMiddleware : MiddlewareBase
    {
        private readonly ISimpleBooleanConfiguration _config;
        private readonly HeaderResult _headerResult;

        public XContentTypeOptionsMiddleware(RequestDelegate next)
            : base(next)
        {
            _config = new SimpleBooleanConfiguration { Enabled = true };
            var headerGenerator = new HeaderGenerator();
            _headerResult = headerGenerator.CreateXContentTypeOptionsResult(_config);
        }

        internal override void PreInvokeNext(HttpContext owinEnvironment)
        {
            owinEnvironment.GetNWebsecContext().XContentTypeOptions = _config;

            if (_headerResult.Action == HeaderResult.ResponseAction.Set)
            {
                owinEnvironment.Response.Headers[_headerResult.Name] = _headerResult.Value;
            }
        }
    }
}