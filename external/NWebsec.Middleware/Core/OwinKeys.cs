// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

namespace NWebsec.Middleware.Core
{
    internal static class OwinKeys
    {
        //Request
        internal static string RequestBody = "owin.RequestBody";
        internal static string RequestHeaders = "owin.RequestHeaders";
        internal static string RequestMethod = "owin.RequestMethod";
        internal static string RequestPath = "owin.RequestPath";
        internal static string RequestPathBase = "owin.RequestPathBase";
        internal static string RequestProtocol = "owin.RequestProtocol";
        internal static string RequestQueryString = "owin.RequestQueryString";
        internal static string RequestScheme = "owin.RequestScheme";

        //Response
        internal static string ResponseBody = "owin.ResponseBody";
        internal static string ResponseHeaders = "owin.ResponseHeaders";
        internal static string ResponseStatusCode = "owin.ResponseStatusCode";
        internal static string ResponseReasonPhrase = "owin.ResponseReasonPhrase";
        internal static string ResponseProtocol = "owin.ResponseProtocol";

        //Other
        internal static string CallCancelled = "owin.CallCancelled";
        internal static string Version = "owin.Version";
    }
}