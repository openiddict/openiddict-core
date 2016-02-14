// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace NWebsec.Middleware.Middleware
{
    public class MiddlewareBase
    {
        private readonly RequestDelegate _next;

        public MiddlewareBase(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext context)
        {

            PreInvokeNext(context);

            if (_next != null)
            {
                await _next(context);
            }

            PostInvokeNext(context);
        }

        internal virtual void PreInvokeNext(HttpContext context)
        {
        }

        internal virtual void PostInvokeNext(HttpContext context)
        {
        }
    }
}