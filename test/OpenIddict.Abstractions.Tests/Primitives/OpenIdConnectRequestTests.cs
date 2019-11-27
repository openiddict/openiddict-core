/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using System.Reflection;
using Newtonsoft.Json.Linq;
using Xunit;

namespace AspNet.Security.OpenIdConnect.Primitives.Tests
{
    public class OpenIdConnectRequestTests
    {
        public static IEnumerable<object[]> Properties
        {
            get
            {
                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.AccessToken),
                    /* name: */ OpenIdConnectConstants.Parameters.AccessToken,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.AcrValues),
                    /* name: */ OpenIdConnectConstants.Parameters.AcrValues,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.Assertion),
                    /* name: */ OpenIdConnectConstants.Parameters.Assertion,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.Audiences),
                    /* name: */ OpenIdConnectConstants.Parameters.Audience,
                    /* value: */ new OpenIdConnectParameter(new[] { "Fabrikam", "Contoso" })
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.Claims),
                    /* name: */ OpenIdConnectConstants.Parameters.Claims,
                    /* value: */ new OpenIdConnectParameter(new JObject { ["userinfo"] = new JObject() })
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.ClaimsLocales),
                    /* name: */ OpenIdConnectConstants.Parameters.ClaimsLocales,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.ClientAssertion),
                    /* name: */ OpenIdConnectConstants.Parameters.ClientAssertion,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.ClientAssertionType),
                    /* name: */ OpenIdConnectConstants.Parameters.ClientAssertionType,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.ClientId),
                    /* name: */ OpenIdConnectConstants.Parameters.ClientId,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.ClientSecret),
                    /* name: */ OpenIdConnectConstants.Parameters.ClientSecret,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.Code),
                    /* name: */ OpenIdConnectConstants.Parameters.Code,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.CodeChallenge),
                    /* name: */ OpenIdConnectConstants.Parameters.CodeChallenge,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.CodeChallengeMethod),
                    /* name: */ OpenIdConnectConstants.Parameters.CodeChallengeMethod,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.CodeVerifier),
                    /* name: */ OpenIdConnectConstants.Parameters.CodeVerifier,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.Display),
                    /* name: */ OpenIdConnectConstants.Parameters.Display,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.GrantType),
                    /* name: */ OpenIdConnectConstants.Parameters.GrantType,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.IdentityProvider),
                    /* name: */ OpenIdConnectConstants.Parameters.IdentityProvider,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.IdTokenHint),
                    /* name: */ OpenIdConnectConstants.Parameters.IdTokenHint,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.LoginHint),
                    /* name: */ OpenIdConnectConstants.Parameters.LoginHint,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.Nonce),
                    /* name: */ OpenIdConnectConstants.Parameters.Nonce,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.MaxAge),
                    /* name: */ OpenIdConnectConstants.Parameters.MaxAge,
                    /* value: */ new OpenIdConnectParameter((long?) 42)
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.Password),
                    /* name: */ OpenIdConnectConstants.Parameters.Password,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.PostLogoutRedirectUri),
                    /* name: */ OpenIdConnectConstants.Parameters.PostLogoutRedirectUri,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.Prompt),
                    /* name: */ OpenIdConnectConstants.Parameters.Prompt,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.RedirectUri),
                    /* name: */ OpenIdConnectConstants.Parameters.RedirectUri,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.RefreshToken),
                    /* name: */ OpenIdConnectConstants.Parameters.RefreshToken,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.Registration),
                    /* name: */ OpenIdConnectConstants.Parameters.Registration,
                    /* value: */ new OpenIdConnectParameter(new JObject { ["policy_uri"] = "http://www.fabrikam.com/policy" })
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.Request),
                    /* name: */ OpenIdConnectConstants.Parameters.Request,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.RequestId),
                    /* name: */ OpenIdConnectConstants.Parameters.RequestId,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.RequestUri),
                    /* name: */ OpenIdConnectConstants.Parameters.RequestUri,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.Resources),
                    /* name: */ OpenIdConnectConstants.Parameters.Resource,
                    /* value: */ new OpenIdConnectParameter(new[] { "https://fabrikam.com/", "https://contoso.com/" })
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.ResponseMode),
                    /* name: */ OpenIdConnectConstants.Parameters.ResponseMode,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.ResponseType),
                    /* name: */ OpenIdConnectConstants.Parameters.ResponseType,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.Scope),
                    /* name: */ OpenIdConnectConstants.Parameters.Scope,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.State),
                    /* name: */ OpenIdConnectConstants.Parameters.State,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.Token),
                    /* name: */ OpenIdConnectConstants.Parameters.Token,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.TokenTypeHint),
                    /* name: */ OpenIdConnectConstants.Parameters.TokenTypeHint,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.UiLocales),
                    /* name: */ OpenIdConnectConstants.Parameters.UiLocales,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIdConnectRequest.Username),
                    /* name: */ OpenIdConnectConstants.Parameters.Username,
                    /* value: */ new OpenIdConnectParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };
            }
        }

        [Theory]
        [MemberData(nameof(Properties))]
        public void PropertyGetter_ReturnsExpectedParameter(string property, string name, OpenIdConnectParameter value)
        {
            // Arrange
            var request = new OpenIdConnectRequest();
            request.SetParameter(name, value);

            // Act and assert
            Assert.Equal(value.Value, typeof(OpenIdConnectRequest).GetProperty(property).GetValue(request));
        }

        [Theory]
        [MemberData(nameof(Properties))]
        public void PropertySetter_AddsExpectedParameter(string property, string name, OpenIdConnectParameter value)
        {
            // Arrange
            var request = new OpenIdConnectRequest();

            // Act
            typeof(OpenIdConnectRequest).GetProperty(property).SetValue(request, value.Value);

            // Assert
            Assert.Equal(value, request.GetParameter(name));
        }
    }
}
