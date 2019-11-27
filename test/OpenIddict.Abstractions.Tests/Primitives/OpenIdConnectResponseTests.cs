/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using System.Reflection;
using Xunit;

namespace AspNet.Security.OpenIdConnect.Primitives.Tests
{
    public class OpenIdConnectResponseTests
    {
        public static IEnumerable<object[]> Properties
        {
            get
            {
                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectResponse.AccessToken),
                    /* name: */ OpenIdConnectConstants.Parameters.AccessToken,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectResponse.Code),
                    /* name: */ OpenIdConnectConstants.Parameters.Code,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectResponse.Error),
                    /* name: */ OpenIdConnectConstants.Parameters.Error,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectResponse.ErrorDescription),
                    /* name: */ OpenIdConnectConstants.Parameters.ErrorDescription,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectResponse.ErrorUri),
                    /* name: */ OpenIdConnectConstants.Parameters.ErrorUri,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectResponse.ExpiresIn),
                    /* name: */ OpenIdConnectConstants.Parameters.ExpiresIn,
                    /* value: */ new OpenIdConnectParameter((long?) 42)
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectResponse.IdToken),
                    /* name: */ OpenIdConnectConstants.Parameters.IdToken,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectResponse.RefreshToken),
                    /* name: */ OpenIdConnectConstants.Parameters.RefreshToken,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectResponse.Scope),
                    /* name: */ OpenIdConnectConstants.Parameters.Scope,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectResponse.State),
                    /* name: */ OpenIdConnectConstants.Parameters.State,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectResponse.TokenType),
                    /* name: */ OpenIdConnectConstants.Parameters.TokenType,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };
            }
        }

        [Theory]
        [MemberData(nameof(Properties))]
        public void PropertyGetter_ReturnsExpectedParameter(string property, string name, OpenIdConnectParameter value)
        {
            // Arrange
            var response = new OpenIdConnectResponse();
            response.SetParameter(name, value);

            // Act and assert
            Assert.Equal(value.Value, typeof(OpenIdConnectResponse).GetProperty(property).GetValue(response));
        }

        [Theory]
        [MemberData(nameof(Properties))]
        public void PropertySetter_AddsExpectedParameter(string property, string name, OpenIdConnectParameter value)
        {
            // Arrange
            var response = new OpenIdConnectResponse();

            // Act
            typeof(OpenIdConnectResponse).GetProperty(property).SetValue(response, value.Value);

            // Assert
            Assert.Equal(value, response.GetParameter(name));
        }
    }
}
