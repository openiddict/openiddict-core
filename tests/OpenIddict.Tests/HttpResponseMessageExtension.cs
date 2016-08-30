using System;
using System.Net.Http;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace OpenIddict.Tests
{
    public static class HttpResponseMessageExtension
    {
        public static async Task<OpenIdConnectResponse> ToOpenIdConnectResponseAsync(this HttpResponseMessage response)
        {
            if (response == null) throw new ArgumentNullException(nameof(response));

            var responseString = await response.Content.ReadAsStringAsync();
            if (string.IsNullOrEmpty(responseString))
            {
                throw new InvalidOperationException();
            }

            var openIdConnectResponse = new OpenIdConnectResponse();
            foreach (var property in JsonConvert.DeserializeObject<JObject>(responseString).Properties())
            {
                openIdConnectResponse.SetParameter(property.Name, property.Value.ToString());
            }

            return openIdConnectResponse;
        }
    }
}