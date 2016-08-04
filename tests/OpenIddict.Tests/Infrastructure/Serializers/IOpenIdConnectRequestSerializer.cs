using System.Net.Http;
using AspNet.Security.OpenIdConnect.Extensions;

namespace OpenIddict.Tests.Infrastructure.Serializers
{
    public interface IOpenIdConnectRequestSerializer
    {
        HttpRequestMessage Serialize(OpenIdConnectRequest request);
    }
}