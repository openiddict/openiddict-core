﻿using System;
using System.Collections.Generic;
using System.Net.Http;
using AspNet.Security.OpenIdConnect.Extensions;

namespace OpenIddict.Tests.Infrastructure.Serializers
{
    internal class PasswordOpenIdConnectRequestSerializer : IOpenIdConnectRequestSerializer
    {
        private const string DefaultRequestUri = "connect/token";

        public HttpRequestMessage Serialize(OpenIdConnectRequest request)
        {
            if (request == null) throw new ArgumentNullException(nameof(request));

            return new HttpRequestMessage(HttpMethod.Post, request.RequestUri ?? DefaultRequestUri)
            {
                Content = new FormUrlEncodedContent(GetParameters(request))
            };
        }

        public static IEnumerable<KeyValuePair<string, string>> GetParameters(OpenIdConnectRequest request)
        {
            foreach (var parameterPair in request)
            {
                yield return new KeyValuePair<string, string>(parameterPair.Key, parameterPair.Value.ToString());
            }
        }
    }
}