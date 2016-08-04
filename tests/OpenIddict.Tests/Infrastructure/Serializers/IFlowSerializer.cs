using System.Net.Http;
using AspNet.Security.OpenIdConnect.Extensions;

namespace OpenIddict.Tests.Infrastructure.Serializers
{
    public interface IFlowSerializer
    {
        HttpRequestMessage Serialize(OpenIdConnectRequest request);
    }
}