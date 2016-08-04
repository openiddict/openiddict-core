using System.Net;
using Xunit;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using OpenIddict.Tests.Infrastructure;

namespace OpenIddict.Tests
{
    public class ResourceOriginGrantTests
    {
        [Fact]
        public async Task Should_Return200Ok_When_SendingRopcRequest()
        {
            // Arrange
            var webHostBuilder = new WebHostBuilder()
                .UseStartup<Startup>();

            using (var host = new TestServer(webHostBuilder))
            {
                using (var client = host.CreateClient())
                {
                    var request = new OpenIdConnectRequestBuilder()
                        .WithClientId("myClient")
                        .WithClientSecret("secret_secret_secret")
                        .WithUsername("Me")
                        .WithPassword("Pwd")
                        .WithGrantType("password")
                        .BuildRequestMessage();

                    // Act
                    var response = await client.SendAsync(request);

                    // Assert
                    Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                    Assert.NotNull(response.Content);
                }
            }
        }
    }
}
