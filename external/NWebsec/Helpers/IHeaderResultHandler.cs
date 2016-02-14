// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using Microsoft.AspNetCore.Http;
using NWebsec.Core.HttpHeaders;

namespace NWebsec.Core.Helpers
{
    public interface IHeaderResultHandler
    {
        void HandleHeaderResult(HttpResponse response, HeaderResult result);
    }
}