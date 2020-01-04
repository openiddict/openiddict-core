/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Threading.Tasks;
using Microsoft.AspNetCore;
using Microsoft.Net.Http.Headers;
using OpenIddict.Abstractions;
using OpenIddict.Server.FunctionalTests;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Server.AspNetCore.FunctionalTests
{
    public partial class OpenIddictServerAspNetCoreIntegrationTests : OpenIddictServerIntegrationTests
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
                        var request = context.Transaction.GetHttpRequest();
                        request.Headers[HeaderNames.Authorization] = "Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW";

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
