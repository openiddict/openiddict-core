
/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using Xunit;

namespace OpenIddict.Abstractions.Tests.Primitives;

public class OpenIddictResponseTests
{
    public static IEnumerable<object[]> Properties
    {
        get
        {
            yield return new object[]
            {
                /* property: */ nameof(OpenIddictResponse.AccessToken),
                /* name: */ Parameters.AccessToken,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictResponse.Code),
                /* name: */ Parameters.Code,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictResponse.DeviceCode),
                /* name: */ Parameters.DeviceCode,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictResponse.Error),
                /* name: */ Parameters.Error,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictResponse.ErrorDescription),
                /* name: */ Parameters.ErrorDescription,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictResponse.ErrorUri),
                /* name: */ Parameters.ErrorUri,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictResponse.ExpiresIn),
                /* name: */ Parameters.ExpiresIn,
                /* value: */ new OpenIddictParameter((long?) 42)
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictResponse.IdToken),
                /* name: */ Parameters.IdToken,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictResponse.Iss),
                /* name: */ Parameters.Iss,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictResponse.RefreshToken),
                /* name: */ Parameters.RefreshToken,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictResponse.RequestUri),
                /* name: */ Parameters.RequestUri,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictResponse.Scope),
                /* name: */ Parameters.Scope,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictResponse.State),
                /* name: */ Parameters.State,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictResponse.TokenType),
                /* name: */ Parameters.TokenType,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictResponse.UserCode),
                /* name: */ Parameters.UserCode,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictResponse.VerificationUri),
                /* name: */ Parameters.VerificationUri,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictResponse.VerificationUriComplete),
                /* name: */ Parameters.VerificationUriComplete,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };
        }
    }

    [Theory]
    [MemberData(nameof(Properties))]
    public void PropertyGetter_ReturnsExpectedParameter(string property, string name, OpenIddictParameter value)
    {
        // Arrange
        var response = new OpenIddictResponse();
        response.SetParameter(name, value);

        // Act and assert
        var info = typeof(OpenIddictResponse).GetProperty(property)!;
        if (typeof(JsonNode).IsAssignableFrom(info.PropertyType))
        {
            Assert.True(JsonNode.DeepEquals((JsonNode?) value.GetRawValue(), (JsonNode?) info.GetValue(response)));
        }

        else
        {
            Assert.Equal(value.GetRawValue(), info.GetValue(response));
        }
    }

    [Theory]
    [MemberData(nameof(Properties))]
    public void PropertySetter_AddsExpectedParameter(string property, string name, OpenIddictParameter value)
    {
        // Arrange
        var response = new OpenIddictResponse();

        // Act
        var info = typeof(OpenIddictResponse).GetProperty(property)!;
        if (typeof(ImmutableArray<string?>).IsAssignableFrom(info.PropertyType))
        {
            info.SetValue(response, ImmutableCollectionsMarshal.AsImmutableArray((string?[]?) value.GetRawValue()));
        }

        else
        {
            info.SetValue(response, value.GetRawValue());
        }

        // Assert
        Assert.Equal(value, response.GetParameter(name));
    }
}
