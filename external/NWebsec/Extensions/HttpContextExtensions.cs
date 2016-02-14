// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using Microsoft.AspNetCore.Http;

namespace NWebsec.Core.Extensions
{
    public static class HttpContextExtensions
    {
        public static NWebsecContext GetNWebsecContext(this HttpContext context)
        {
            if (!context.Items.ContainsKey(NWebsecContext.ContextKey))
            {
                context.Items[NWebsecContext.ContextKey] = new NWebsecContext();
            }

            return context.Items[NWebsecContext.ContextKey] as NWebsecContext;
        }
    }
}