/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Threading.Tasks;
using OpenIddict.Abstractions;
using OpenIddict.Server.FunctionalTests;
using Owin;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Server.Owin.FunctionalTests
{
    public partial class OpenIddictServerOwinIntegrationTests : OpenIddictServerIntegrationTests
    {
        [Fact]
        public async Task ExtractRevocationRequest_MultipleClientCredentialsCauseAnError()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ExtractRevocationRequestContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        var request = context.Transaction.GetOwinRequest();
                        request.Headers["Authorization"] = "Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW";

                        return default;
                    });

                    builder.SetOrder(int.MinValue);
                });
            });

            // Act
            var response = await client.PostAsync("/connect/revoke", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("Multiple client credentials cannot be specified.", response.ErrorDescription);
        }
    }
}
