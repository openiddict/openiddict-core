﻿/*
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
    public async Task ExtractTokenRequest_ClientSecretFromRequestCausesAnErrorWhenClientSecretPostIsDisabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.Configure(options => options.ClientAuthenticationMethods.Remove(ClientAuthenticationMethods.ClientSecretPost));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
            GrantType = GrantTypes.Password,
            Username = "johndoe",
            Password = "A3ddj3w"
        });

        // Assert
        Assert.Equal(Errors.InvalidClient, response.Error);
        Assert.Equal(SR.FormatID2174(ClientAuthenticationMethods.ClientSecretPost), response.ErrorDescription);
    }

    [Fact]
    public async Task ExtractTokenRequest_ClientSecretFromHeaderCausesAnErrorWhenClientSecretBasicIsDisabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.Configure(options => options.ClientAuthenticationMethods.Remove(ClientAuthenticationMethods.ClientSecretBasic));

            options.AddEventHandler<ExtractTokenRequestContext>(builder =>
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
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            GrantType = GrantTypes.Password,
            Username = "johndoe",
            Password = "A3ddj3w"
        });

        // Assert
        Assert.Equal(Errors.InvalidClient, response.Error);
        Assert.Equal(SR.FormatID2174(ClientAuthenticationMethods.ClientSecretBasic), response.ErrorDescription);
    }

    [Fact]
    public async Task ExtractTokenRequest_MultipleClientCredentialsCauseAnError()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ExtractTokenRequestContext>(builder =>
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
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
            GrantType = GrantTypes.Password,
            Username = "johndoe",
            Password = "A3ddj3w"
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2087), response.ErrorDescription);
    }
}
