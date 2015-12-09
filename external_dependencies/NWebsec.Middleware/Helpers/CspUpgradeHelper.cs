// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using System;
using System.Linq;
using Microsoft.AspNet.Http;

namespace NWebsec.Middleware.Helpers
{
    //Tested indirectly by CSP Middleware
    internal class CspUpgradeHelper
    {
        internal static bool UaSupportsUpgradeInsecureRequests(HttpContext env)
        {
            var upgradeHeader = env.Request.Headers["Upgrade-Insecure-Requests"];
            
            return upgradeHeader.Any(h => h.Equals("1", StringComparison.Ordinal));
        }
    }
}