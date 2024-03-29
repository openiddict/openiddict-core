﻿/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.AspNetCore;
using Microsoft.Net.Http.Headers;
using OpenIddict.Server.IntegrationTests;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Server.AspNetCore.IntegrationTests;

public partial class OpenIddictServerAspNetCoreIntegrationTests : OpenIddictServerIntegrationTests
{
    [Fact]
    public async Task ExtractIntrospectionRequest_ClientSecretFromRequestCausesAnErrorWhenClientSecretPostIsDisabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.Configure(options => options.ClientAuthenticationMethods.Remove(ClientAuthenticationMethods.ClientSecretPost));
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
        Assert.Equal(Errors.InvalidClient, response.Error);
        Assert.Equal(SR.FormatID2174(ClientAuthenticationMethods.ClientSecretPost), response.ErrorDescription);
    }

    [Fact]
    public async Task ExtractIntrospectionRequest_ClientSecretFromHeaderCausesAnErrorWhenClientSecretBasicIsDisabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.Configure(options => options.ClientAuthenticationMethods.Remove(ClientAuthenticationMethods.ClientSecretBasic));

            options.AddEventHandler<ExtractIntrospectionRequestContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    var request = context.Transaction.GetHttpRequest()!;
                    request.Headers[HeaderNames.Authorization] = "Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW";

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
            Token = "2YotnFZFEjr1zCsicMWpAA"
        });

        // Assert
        Assert.Equal(Errors.InvalidClient, response.Error);
        Assert.Equal(SR.FormatID2174(ClientAuthenticationMethods.ClientSecretBasic), response.ErrorDescription);
    }

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
                    var request = context.Transaction.GetHttpRequest()!;
                    request.Headers[HeaderNames.Authorization] = "Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW";

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
