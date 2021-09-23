/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using OpenIddict.Server.IntegrationTests;
using Owin;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Server.Owin.IntegrationTests;

public partial class OpenIddictServerOwinIntegrationTests : OpenIddictServerIntegrationTests
{
    [Fact]
    public async Task ExtractIntrospectionRequest_MultipleClientCredentialsCauseAnError()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ExtractIntrospectionRequestContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    var request = context.Transaction.GetOwinRequest()!;
                    request.Headers["Authorization"] = "Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW";

                    return default;
                });

                builder.SetOrder(int.MinValue);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
            Token = "2YotnFZFEjr1zCsicMWpAA"
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2087), response.ErrorDescription);
    }
}
