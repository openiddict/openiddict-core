/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Threading.Tasks;
using Microsoft.AspNetCore;
using Microsoft.Net.Http.Headers;
using OpenIddict.Abstractions;
using OpenIddict.Server.IntegrationTests;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.Server.AspNetCore.IntegrationTests
{
    public partial class OpenIddictServerAspNetCoreIntegrationTests : OpenIddictServerIntegrationTests
    {
        [Fact]
        public async Task ExtractRevocationRequest_MultipleClientCredentialsCauseAnError()
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
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

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/revoke", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal(SR.GetResourceString(SR.ID3087), response.ErrorDescription);
        }
    }
}
