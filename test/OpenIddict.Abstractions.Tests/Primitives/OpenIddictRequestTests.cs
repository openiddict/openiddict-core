/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using System.Text.Json;
using Xunit;

namespace OpenIddict.Abstractions.Tests.Primitives
{
    public class OpenIddictRequestTests
    {
        public static IEnumerable<object[]> Properties
        {
            get
            {
                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.AccessToken),
                    /* name: */ OpenIddictConstants.Parameters.AccessToken,
                    /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.AcrValues),
                    /* name: */ OpenIddictConstants.Parameters.AcrValues,
                    /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.Assertion),
                    /* name: */ OpenIddictConstants.Parameters.Assertion,
                    /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.Audiences),
                    /* name: */ OpenIddictConstants.Parameters.Audience,
                    /* value: */ new OpenIddictParameter(new[] { "Fabrikam", "Contoso" })
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.Claims),
                    /* name: */ OpenIddictConstants.Parameters.Claims,
                    /* value: */ new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(@"{""userinfo"": {}}"))
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.ClaimsLocales),
                    /* name: */ OpenIddictConstants.Parameters.ClaimsLocales,
                    /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.ClientAssertion),
                    /* name: */ OpenIddictConstants.Parameters.ClientAssertion,
                    /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.ClientAssertionType),
                    /* name: */ OpenIddictConstants.Parameters.ClientAssertionType,
                    /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.ClientId),
                    /* name: */ OpenIddictConstants.Parameters.ClientId,
                    /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.ClientSecret),
                    /* name: */ OpenIddictConstants.Parameters.ClientSecret,
                    /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.Code),
                    /* name: */ OpenIddictConstants.Parameters.Code,
                    /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.CodeChallenge),
                    /* name: */ OpenIddictConstants.Parameters.CodeChallenge,
                    /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.CodeChallengeMethod),
                    /* name: */ OpenIddictConstants.Parameters.CodeChallengeMethod,
                    /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.CodeVerifier),
                    /* name: */ OpenIddictConstants.Parameters.CodeVerifier,
                    /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.DeviceCode),
                    /* name: */ OpenIddictConstants.Parameters.DeviceCode,
                    /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.Display),
                    /* name: */ OpenIddictConstants.Parameters.Display,
                    /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.GrantType),
                    /* name: */ OpenIddictConstants.Parameters.GrantType,
                    /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.IdentityProvider),
                    /* name: */ OpenIddictConstants.Parameters.IdentityProvider,
                    /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.IdTokenHint),
                    /* name: */ OpenIddictConstants.Parameters.IdTokenHint,
                    /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.LoginHint),
                    /* name: */ OpenIddictConstants.Parameters.LoginHint,
                    /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.Nonce),
                    /* name: */ OpenIddictConstants.Parameters.Nonce,
                    /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.MaxAge),
                    /* name: */ OpenIddictConstants.Parameters.MaxAge,
                    /* value: */ new OpenIddictParameter((long?) 42)
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.Password),
                    /* name: */ OpenIddictConstants.Parameters.Password,
                    /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.PostLogoutRedirectUri),
                    /* name: */ OpenIddictConstants.Parameters.PostLogoutRedirectUri,
                    /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.Prompt),
                    /* name: */ OpenIddictConstants.Parameters.Prompt,
                    /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.RedirectUri),
                    /* name: */ OpenIddictConstants.Parameters.RedirectUri,
                    /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.RefreshToken),
                    /* name: */ OpenIddictConstants.Parameters.RefreshToken,
                    /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.Registration),
                    /* name: */ OpenIddictConstants.Parameters.Registration,
                    /* value: */ new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(@"{""policy_uri"": ""http://www.fabrikam.com/policy""}"))
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.Request),
                    /* name: */ OpenIddictConstants.Parameters.Request,
                    /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.RequestId),
                    /* name: */ OpenIddictConstants.Parameters.RequestId,
                    /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.RequestUri),
                    /* name: */ OpenIddictConstants.Parameters.RequestUri,
                    /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.Resources),
                    /* name: */ OpenIddictConstants.Parameters.Resource,
                    /* value: */ new OpenIddictParameter(new[] { "https://fabrikam.com/", "https://contoso.com/" })
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.ResponseMode),
                    /* name: */ OpenIddictConstants.Parameters.ResponseMode,
                    /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.ResponseType),
                    /* name: */ OpenIddictConstants.Parameters.ResponseType,
                    /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.Scope),
                    /* name: */ OpenIddictConstants.Parameters.Scope,
                    /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.State),
                    /* name: */ OpenIddictConstants.Parameters.State,
                    /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.Token),
                    /* name: */ OpenIddictConstants.Parameters.Token,
                    /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.TokenTypeHint),
                    /* name: */ OpenIddictConstants.Parameters.TokenTypeHint,
                    /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.UiLocales),
                    /* name: */ OpenIddictConstants.Parameters.UiLocales,
                    /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.UserCode),
                    /* name: */ OpenIddictConstants.Parameters.UserCode,
                    /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };

                yield return new object[]
                {
                    /* property: */ nameof(OpenIddictRequest.Username),
                    /* name: */ OpenIddictConstants.Parameters.Username,
                    /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
                };
            }
        }

        [Theory]
        [MemberData(nameof(Properties))]
        public void PropertyGetter_ReturnsExpectedParameter(string property, string name, OpenIddictParameter value)
        {
            // Arrange
            var request = new OpenIddictRequest();
            request.SetParameter(name, value);

            // Act and assert
            Assert.Equal(value.Value, typeof(OpenIddictRequest).GetProperty(property).GetValue(request));
        }

        [Theory]
        [MemberData(nameof(Properties))]
        public void PropertySetter_AddsExpectedParameter(string property, string name, OpenIddictParameter value)
        {
            // Arrange
            var request = new OpenIddictRequest();

            // Act
            typeof(OpenIddictRequest).GetProperty(property).SetValue(request, value.Value);

            // Assert
            Assert.Equal(value, request.GetParameter(name));
        }
    }
}
