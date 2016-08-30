using System;
using System.Net.Http;
using AspNet.Security.OpenIdConnect.Extensions;
using OpenIddict.Tests.Infrastructure.Serializers;

namespace OpenIddict.Tests.Infrastructure
{
    public class OpenIdConnectRequestBuilder
    {
        private readonly OpenIdConnectRequest _request;

        public OpenIdConnectRequestBuilder()
        {
            _request = new OpenIdConnectRequest();
        }

        public OpenIdConnectRequestBuilder WithClientId(string clientId) =>
            With((r, p) => r.ClientId = p, clientId, nameof(clientId));

        public OpenIdConnectRequestBuilder WithClientSecret(string clientSecret) =>
            With((r, p) => r.ClientSecret = p, clientSecret, nameof(clientSecret));

        public OpenIdConnectRequestBuilder WithUsername(string username) =>
            With((r, p) => r.Username = p, username, nameof(username));

        public OpenIdConnectRequestBuilder WithPassword(string password) =>
            With((r, p) => r.Password = p, password, nameof(password));

        public OpenIdConnectRequestBuilder WithGrantType(string grantType) =>
            With((r, p) => r.GrantType = p, grantType, nameof(grantType));

        public HttpRequestMessage BuildRequestMessage() =>
            Build(GuessSerializer());

        private HttpRequestMessage Build(IOpenIdConnectRequestSerializer serializer) =>
            serializer.Serialize(_request);

        private IOpenIdConnectRequestSerializer GuessSerializer()
        {
            if (_request.IsPasswordGrantType())
                return new PasswordOpenIdConnectRequestSerializer();

            throw new NotImplementedException();
        }

        private OpenIdConnectRequestBuilder With(Action<OpenIdConnectRequest, string> setParameter, string parameter, string parameterName)
        {
            if (string.IsNullOrEmpty(parameter)) throw new ArgumentException("Value cannot be null or empty.", parameterName);

            setParameter.Invoke(_request, parameter);

            return this;
        }
    }
}