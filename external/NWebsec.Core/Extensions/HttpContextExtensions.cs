// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using Microsoft.AspNet.Http;
using NWebsec.Annotations;

namespace NWebsec.Core.Extensions
{
    public static class HttpContextExtensions
    {
        [NotNull]
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