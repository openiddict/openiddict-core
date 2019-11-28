/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using Xunit;

namespace OpenIddict.Abstractions.Tests.Primitives
{
    public class OpenIdConnectExtensionsTests
    {
        [Fact]
        public void GetAcrValues_ThrowsAnExceptionForNullRequest()
        {
            // Arrange
            var request = (OpenIddictRequest) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => request.GetAcrValues());

            Assert.Equal("request", exception.ParamName);
        }

        [Theory]
        [InlineData(null, new string[0])]
        [InlineData("mod-pr", new[] { "mod-pr" })]
        [InlineData("mod-pr ", new[] { "mod-pr" })]
        [InlineData(" mod-pr ", new[] { "mod-pr" })]
        [InlineData("mod-pr mod-mf", new[] { "mod-pr", "mod-mf" })]
        [InlineData("mod-pr     mod-mf", new[] { "mod-pr", "mod-mf" })]
        [InlineData("mod-pr mod-mf ", new[] { "mod-pr", "mod-mf" })]
        [InlineData(" mod-pr mod-mf", new[] { "mod-pr", "mod-mf" })]
        [InlineData("mod-pr mod-pr mod-mf", new[] { "mod-pr", "mod-mf" })]
        [InlineData("mod-pr MOD-PR mod-mf", new[] { "mod-pr", "MOD-PR", "mod-mf" })]
        public void GetAcrValues_ReturnsExpectedAcrValues(string value, string[] values)
        {
            // Arrange
            var request = new OpenIddictRequest
            {
                AcrValues = value
            };

            // Act
            var actualValues = request.GetAcrValues();

            // Assert
            Assert.Equal(values.Length, actualValues.Count);
            foreach (var val in actualValues)
            {
                Assert.Contains(val, values);
            }
        }

        [Fact]
        public void GetResponseTypes_ThrowsAnExceptionForNullRequest()
        {
            // Arrange
            var request = (OpenIddictRequest)null;

            // Act
            var exception = Assert.Throws<ArgumentNullException>(() => request.GetResponseTypes());

            // Assert
            Assert.Equal("request", exception.ParamName);
        }

        [Theory]
        [InlineData(null, new string[0])]
        [InlineData("code", new[] { "code" })]
        [InlineData("code ", new[] { "code" })]
        [InlineData(" code ", new[] { "code" })]
        [InlineData("code id_token", new[] { "code", "id_token" })]
        [InlineData("code     id_token", new[] { "code", "id_token" })]
        [InlineData("code id_token ", new[] { "code", "id_token" })]
        [InlineData(" code id_token", new[] { "code", "id_token" })]
        [InlineData("code code id_token", new[] { "code", "id_token" })]
        [InlineData("code CODE id_token", new[] { "code", "CODE", "id_token" })]
        public void GetResponseTypes_ReturnsExpectedResponseTypes(string value, string[] responseTypes)
        {
            // Arrange
            var request = new OpenIddictRequest
            {
                ResponseType = value
            };

            // Act
            var actualResponseTypes = request.GetResponseTypes();

            // Assert
            Assert.Equal(responseTypes.Length, actualResponseTypes.Count);
            foreach (var rt in actualResponseTypes)
            {
                Assert.Contains(rt, responseTypes);
            }
        }

        [Fact]
        public void GetScopes_ThrowsAnExceptionForNullRequest()
        {
            // Arrange
            var request = (OpenIddictRequest) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => request.GetScopes());

            Assert.Equal("request", exception.ParamName);
        }

        [Theory]
        [InlineData(null, new string[0])]
        [InlineData("openid", new[] { "openid" })]
        [InlineData("openid ", new[] { "openid" })]
        [InlineData(" openid ", new[] { "openid" })]
        [InlineData("openid profile", new[] { "openid", "profile" })]
        [InlineData("openid     profile", new[] { "openid", "profile" })]
        [InlineData("openid profile ", new[] { "openid", "profile" })]
        [InlineData(" openid profile", new[] { "openid", "profile" })]
        [InlineData("openid openid profile", new[] { "openid", "profile" })]
        [InlineData("openid OPENID profile", new[] { "openid", "OPENID", "profile" })]
        public void GetScopes_ReturnsExpectedScopes(string scope, string[] scopes)
        {
            // Arrange
            var request = new OpenIddictRequest
            {
                Scope = scope
            };

            // Act
            var actualScopes = request.GetScopes();

            // Assert
            Assert.Equal(scopes.Length, actualScopes.Count);
            foreach (var scp in actualScopes)
            {
                Assert.Contains(scp, scopes);
            }
        }

        [Fact]
        public void HasAcrValue_ThrowsAnExceptionForNullRequest()
        {
            // Arrange
            var request = (OpenIddictRequest) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => request.HasAcrValue("mod-mf"));

            Assert.Equal("request", exception.ParamName);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void HasAcrValue_ThrowsAnExceptionForNullOrEmptyAcrValue(string value)
        {
            // Arrange
            var request = new OpenIddictRequest();

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(() => request.HasAcrValue(value));

            Assert.Equal("value", exception.ParamName);
            Assert.StartsWith("The value cannot be null or empty.", exception.Message);
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("mod-mf", true)]
        [InlineData("mod-mf mod-pr", true)]
        [InlineData(" mod-mf mod-pr", true)]
        [InlineData("mod-pr mod-mf", true)]
        [InlineData("mod-pr mod-mf ", true)]
        [InlineData("mod-pr mod-mf mod-cstm", true)]
        [InlineData("mod-pr mod-mf mod-cstm ", true)]
        [InlineData("mod-pr    mod-mf   mod-cstm ", true)]
        [InlineData("mod-pr", false)]
        [InlineData("mod-pr mod-cstm", false)]
        [InlineData("MOD-MF", false)]
        [InlineData("MOD-MF MOD-PR", false)]
        [InlineData(" MOD-MF MOD-PR", false)]
        [InlineData("MOD-PR MOD-MF", false)]
        [InlineData("MOD-PR MOD-MF ", false)]
        [InlineData("MOD-PR MOD-MF MOD-CSTM", false)]
        [InlineData("MOD-PR MOD-MF MOD-CSTM ", false)]
        [InlineData("MOD-PR    MOD-MF   MOD-CSTM ", false)]
        [InlineData("MOD-PR", false)]
        [InlineData("MOD-PR MOD-CSTM", false)]
        public void HasAcrValue_ReturnsExpectedResult(string value, bool result)
        {
            // Arrange
            var request = new OpenIddictRequest
            {
                AcrValues = value
            };

            // Act and assert
            Assert.Equal(result, request.HasAcrValue("mod-mf"));
        }

        [Fact]
        public void HasPrompt_ThrowsAnExceptionForNullRequest()
        {
            // Arrange
            var request = (OpenIddictRequest) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() =>
            {
                request.HasPrompt(OpenIddictConstants.Prompts.Consent);
            });

            Assert.Equal("request", exception.ParamName);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void HasPrompt_ThrowsAnExceptionForNullOrEmptyPrompt(string prompt)
        {
            // Arrange
            var request = new OpenIddictRequest();

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(() => request.HasPrompt(prompt));

            Assert.Equal("prompt", exception.ParamName);
            Assert.StartsWith("The prompt cannot be null or empty.", exception.Message);
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("consent", true)]
        [InlineData("consent login", true)]
        [InlineData(" consent login", true)]
        [InlineData("login consent", true)]
        [InlineData("login consent ", true)]
        [InlineData("login consent select_account", true)]
        [InlineData("login consent select_account ", true)]
        [InlineData("login    consent   select_account ", true)]
        [InlineData("login", false)]
        [InlineData("login select_account", false)]
        [InlineData("CONSENT", false)]
        [InlineData("CONSENT LOGIN", false)]
        [InlineData(" CONSENT LOGIN", false)]
        [InlineData("LOGIN CONSENT", false)]
        [InlineData("LOGIN CONSENT ", false)]
        [InlineData("LOGIN CONSENT SELECT_ACCOUNT", false)]
        [InlineData("LOGIN CONSENT SELECT_ACCOUNT ", false)]
        [InlineData("LOGIN    CONSENT   SELECT_ACCOUNT ", false)]
        [InlineData("LOGIN", false)]
        [InlineData("LOGIN SELECT_ACCOUNT", false)]
        public void HasPrompt_ReturnsExpectedResult(string prompt, bool result)
        {
            // Arrange
            var request = new OpenIddictRequest
            {
                Prompt = prompt
            };

            // Act and assert
            Assert.Equal(result, request.HasPrompt(OpenIddictConstants.Prompts.Consent));
        }

        [Fact]
        public void HasResponseType_ThrowsAnExceptionForNullRequest()
        {
            // Arrange
            var request = (OpenIddictRequest) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() =>
            {
                request.HasResponseType(OpenIddictConstants.ResponseTypes.Code);
            });

            Assert.Equal("request", exception.ParamName);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void HasResponseType_ThrowsAnExceptionForNullOrEmptyResponseType(string type)
        {
            // Arrange
            var request = new OpenIddictRequest();

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(() => request.HasResponseType(type));

            Assert.Equal("type", exception.ParamName);
            Assert.StartsWith("The response type cannot be null or empty.", exception.Message);
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("code", true)]
        [InlineData("code id_token", true)]
        [InlineData(" code id_token", true)]
        [InlineData("id_token code", true)]
        [InlineData("id_token code ", true)]
        [InlineData("id_token code token", true)]
        [InlineData("id_token code token ", true)]
        [InlineData("id_token    code   token ", true)]
        [InlineData("id_token", false)]
        [InlineData("id_token token", false)]
        [InlineData("CODE", false)]
        [InlineData("CODE ID_TOKEN", false)]
        [InlineData(" CODE ID_TOKEN", false)]
        [InlineData("ID_TOKEN CODE", false)]
        [InlineData("ID_TOKEN CODE ", false)]
        [InlineData("ID_TOKEN CODE TOKEN", false)]
        [InlineData("ID_TOKEN CODE TOKEN ", false)]
        [InlineData("ID_TOKEN    CODE   TOKEN ", false)]
        [InlineData("ID_TOKEN", false)]
        [InlineData("ID_TOKEN TOKEN", false)]
        public void HasResponseType_ReturnsExpectedResult(string type, bool result)
        {
            // Arrange
            var request = new OpenIddictRequest
            {
                ResponseType = type
            };

            // Act and assert
            Assert.Equal(result, request.HasResponseType(OpenIddictConstants.ResponseTypes.Code));
        }

        [Fact]
        public void HasScope_ThrowsAnExceptionForNullRequest()
        {
            // Arrange
            var request = (OpenIddictRequest) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() =>
            {
                request.HasScope(OpenIddictConstants.Scopes.OpenId);
            });

            Assert.Equal("request", exception.ParamName);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void HasScope_ThrowsAnExceptionForNullOrEmptyScope(string scope)
        {
            // Arrange
            var request = new OpenIddictRequest();

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(() => request.HasScope(scope));

            Assert.Equal("scope", exception.ParamName);
            Assert.StartsWith("The scope cannot be null or empty.", exception.Message);
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("openid", true)]
        [InlineData("openid ", true)]
        [InlineData(" openid ", true)]
        [InlineData("openid profile", true)]
        [InlineData("openid     profile", true)]
        [InlineData("openid profile ", true)]
        [InlineData(" openid profile", true)]
        [InlineData("profile", false)]
        [InlineData("profile email", false)]
        [InlineData("OPENID", false)]
        [InlineData("OPENID ", false)]
        [InlineData(" OPENID ", false)]
        [InlineData("OPENID PROFILE", false)]
        [InlineData("OPENID     PROFILE", false)]
        [InlineData("OPENID PROFILE ", false)]
        [InlineData(" OPENID PROFILE", false)]
        [InlineData("PROFILE", false)]
        [InlineData("PROFILE EMAIL", false)]
        public void HasScope_ReturnsExpectedResult(string scope, bool result)
        {
            // Arrange
            var request = new OpenIddictRequest
            {
                Scope = scope
            };

            // Act and assert
            Assert.Equal(result, request.HasScope(OpenIddictConstants.Scopes.OpenId));
        }

        [Fact]
        public void IsNoneFlow_ThrowsAnExceptionForNullRequest()
        {
            // Arrange
            var request = (OpenIddictRequest) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => request.IsNoneFlow());

            Assert.Equal("request", exception.ParamName);
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData("none", true)]
        [InlineData("none ", true)]
        [InlineData(" none", true)]
        [InlineData("none id_token", false)]
        [InlineData(" none id_token", false)]
        [InlineData("none id_token ", false)]
        [InlineData(" none id_token ", false)]
        [InlineData("NONE", false)]
        [InlineData("NONE ", false)]
        [InlineData(" NONE", false)]
        [InlineData("NONE ID_TOKEN", false)]
        [InlineData(" NONE ID_TOKEN", false)]
        [InlineData("NONE ID_TOKEN ", false)]
        [InlineData(" NONE ID_TOKEN ", false)]
        public void IsNoneFlow_ReturnsExpectedResult(string type, bool result)
        {
            // Arrange
            var request = new OpenIddictRequest
            {
                ResponseType = type
            };

            // Act and assert
            Assert.Equal(result, request.IsNoneFlow());
        }

        [Fact]
        public void IsAuthorizationCodeFlow_ThrowsAnExceptionForNullRequest()
        {
            // Arrange
            var request = (OpenIddictRequest) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => request.IsAuthorizationCodeFlow());

            Assert.Equal("request", exception.ParamName);
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData("code", true)]
        [InlineData("code ", true)]
        [InlineData(" code", true)]
        [InlineData("code id_token", false)]
        [InlineData(" code id_token", false)]
        [InlineData("code id_token ", false)]
        [InlineData(" code id_token ", false)]
        [InlineData("CODE", false)]
        [InlineData("CODE ", false)]
        [InlineData(" CODE", false)]
        [InlineData("CODE ID_TOKEN", false)]
        [InlineData(" CODE ID_TOKEN", false)]
        [InlineData("CODE ID_TOKEN ", false)]
        [InlineData(" CODE ID_TOKEN ", false)]
        public void IsAuthorizationCodeFlow_ReturnsExpectedResult(string type, bool result)
        {
            // Arrange
            var request = new OpenIddictRequest
            {
                ResponseType = type
            };

            // Act and assert
            Assert.Equal(result, request.IsAuthorizationCodeFlow());
        }

        [Fact]
        public void IsImplicitFlow_ThrowsAnExceptionForNullRequest()
        {
            // Arrange
            var request = (OpenIddictRequest) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => request.IsImplicitFlow());

            Assert.Equal("request", exception.ParamName);
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData("id_token", true)]
        [InlineData("id_token ", true)]
        [InlineData(" id_token", true)]
        [InlineData("id_token token", true)]
        [InlineData(" id_token token", true)]
        [InlineData("id_token token ", true)]
        [InlineData(" id_token token ", true)]
        [InlineData("token", true)]
        [InlineData("token ", true)]
        [InlineData(" token", true)]
        [InlineData("code id_token", false)]
        [InlineData("code id_token token", false)]
        [InlineData("code token", false)]
        [InlineData("ID_TOKEN", false)]
        [InlineData("ID_TOKEN ", false)]
        [InlineData(" ID_TOKEN", false)]
        [InlineData("ID_TOKEN TOKEN", false)]
        [InlineData(" ID_TOKEN TOKEN", false)]
        [InlineData("ID_TOKEN TOKEN ", false)]
        [InlineData(" ID_TOKEN TOKEN ", false)]
        [InlineData("TOKEN", false)]
        [InlineData("TOKEN ", false)]
        [InlineData(" TOKEN", false)]
        [InlineData("CODE ID_TOKEN", false)]
        [InlineData("CODE ID_TOKEN TOKEN", false)]
        [InlineData("CODE TOKEN", false)]
        public void IsImplicitFlow_ReturnsExpectedResult(string type, bool result)
        {
            // Arrange
            var request = new OpenIddictRequest
            {
                ResponseType = type
            };

            // Act and assert
            Assert.Equal(result, request.IsImplicitFlow());
        }

        [Fact]
        public void IsHybridFlow_ThrowsAnExceptionForNullRequest()
        {
            // Arrange
            var request = (OpenIddictRequest) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => request.IsHybridFlow());

            Assert.Equal("request", exception.ParamName);
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData("code id_token", true)]
        [InlineData("code id_token ", true)]
        [InlineData(" code id_token", true)]
        [InlineData("code id_token token", true)]
        [InlineData(" code id_token token", true)]
        [InlineData("code id_token token ", true)]
        [InlineData(" code id_token token ", true)]
        [InlineData(" code  id_token  token ", true)]
        [InlineData("code token", true)]
        [InlineData("code token ", true)]
        [InlineData(" code token", true)]
        [InlineData("id_token", false)]
        [InlineData("id_token token", false)]
        [InlineData("token", false)]
        [InlineData("CODE ID_TOKEN", false)]
        [InlineData("CODE ID_TOKEN ", false)]
        [InlineData(" CODE ID_TOKEN", false)]
        [InlineData("CODE ID_TOKEN TOKEN", false)]
        [InlineData(" CODE ID_TOKEN TOKEN", false)]
        [InlineData("CODE ID_TOKEN TOKEN ", false)]
        [InlineData(" CODE ID_TOKEN TOKEN ", false)]
        [InlineData(" CODE  ID_TOKEN  TOKEN ", false)]
        [InlineData("CODE TOKEN", false)]
        [InlineData("CODE TOKEN ", false)]
        [InlineData(" CODE TOKEN", false)]
        [InlineData("ID_TOKEN", false)]
        [InlineData("ID_TOKEN TOKEN", false)]
        [InlineData("TOKEN", false)]
        public void IsHybridFlow_ReturnsExpectedResult(string type, bool result)
        {
            // Arrange
            var request = new OpenIddictRequest
            {
                ResponseType = type
            };

            // Act and assert
            Assert.Equal(result, request.IsHybridFlow());
        }

        [Fact]
        public void IsFragmentResponseMode_ThrowsAnExceptionForNullRequest()
        {
            // Arrange
            var request = (OpenIddictRequest) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => request.IsFragmentResponseMode());

            Assert.Equal("request", exception.ParamName);
        }

        [Theory]
        [InlineData(null, null, false)]
        [InlineData("unknown", null, false)]
        [InlineData("query", null, false)]
        [InlineData("form_post", null, false)]
        [InlineData("fragment", null, true)]
        [InlineData("fragment ", null, false)]
        [InlineData(" fragment", null, false)]
        [InlineData(" fragment ", null, false)]
        [InlineData(null, "code", false)]
        [InlineData(null, "code id_token", true)]
        [InlineData(null, "code id_token token", true)]
        [InlineData(null, "code token", true)]
        [InlineData(null, "id_token", true)]
        [InlineData(null, "id_token token", true)]
        [InlineData(null, "token", true)]
        [InlineData("QUERY", null, false)]
        [InlineData("FRAGMENT", null, false)]
        [InlineData("FORM_POST", null, false)]
        [InlineData(null, "CODE", false)]
        [InlineData(null, "CODE ID_TOKEN", false)]
        [InlineData(null, "CODE ID_TOKEN TOKEN", false)]
        [InlineData(null, "CODE TOKEN", false)]
        [InlineData(null, "ID_TOKEN", false)]
        [InlineData(null, "ID_TOKEN TOKEN", false)]
        [InlineData(null, "TOKEN", false)]
        public void IsFragmentResponseMode_ReturnsExpectedResult(string mode, string type, bool result)
        {
            // Arrange
            var request = new OpenIddictRequest
            {
                ResponseMode = mode,
                ResponseType = type
            };

            // Act and assert
            Assert.Equal(result, request.IsFragmentResponseMode());
        }

        [Fact]
        public void IsQueryResponseMode_ThrowsAnExceptionForNullRequest()
        {
            // Arrange
            var request = (OpenIddictRequest) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => request.IsQueryResponseMode());

            Assert.Equal("request", exception.ParamName);
        }

        [Theory]
        [InlineData(null, null, false)]
        [InlineData("unknown", null, false)]
        [InlineData("query", null, true)]
        [InlineData("query ", null, false)]
        [InlineData(" query", null, false)]
        [InlineData(" query ", null, false)]
        [InlineData("fragment", null, false)]
        [InlineData("form_post", null, false)]
        [InlineData(null, "none", true)]
        [InlineData(null, "code", true)]
        [InlineData(null, "code id_token token", false)]
        [InlineData(null, "code token", false)]
        [InlineData(null, "id_token", false)]
        [InlineData(null, "id_token token", false)]
        [InlineData(null, "token", false)]
        [InlineData("QUERY", null, false)]
        [InlineData("FRAGMENT", null, false)]
        [InlineData("FORM_POST", null, false)]
        [InlineData(null, "CODE", false)]
        [InlineData(null, "CODE ID_TOKEN", false)]
        [InlineData(null, "CODE ID_TOKEN TOKEN", false)]
        [InlineData(null, "CODE TOKEN", false)]
        [InlineData(null, "ID_TOKEN", false)]
        [InlineData(null, "ID_TOKEN TOKEN", false)]
        [InlineData(null, "TOKEN", false)]
        public void IsQueryResponseMode_ReturnsExpectedResult(string mode, string type, bool result)
        {
            // Arrange
            var request = new OpenIddictRequest
            {
                ResponseMode = mode,
                ResponseType = type
            };

            // Act and assert
            Assert.Equal(result, request.IsQueryResponseMode());
        }

        [Fact]
        public void IsFormPostResponseMode_ThrowsAnExceptionForNullRequest()
        {
            // Arrange
            var request = (OpenIddictRequest) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => request.IsFormPostResponseMode());

            Assert.Equal("request", exception.ParamName);
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData("query", false)]
        [InlineData("fragment", false)]
        [InlineData("form_post", true)]
        [InlineData("form_post ", false)]
        [InlineData(" form_post", false)]
        [InlineData(" form_post ", false)]
        [InlineData("QUERY", false)]
        [InlineData("FRAGMENT", false)]
        [InlineData("FORM_POST", false)]
        public void IsFormPostResponseMode_ReturnsExpectedResult(string mode, bool result)
        {
            // Arrange
            var request = new OpenIddictRequest
            {
                ResponseMode = mode
            };

            // Act and assert
            Assert.Equal(result, request.IsFormPostResponseMode());
        }

        [Fact]
        public void IsAuthorizationCodeGrantType_ThrowsAnExceptionForNullRequest()
        {
            // Arrange
            var request = (OpenIddictRequest) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => request.IsAuthorizationCodeGrantType());

            Assert.Equal("request", exception.ParamName);
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData("authorization_code", true)]
        [InlineData("authorization_code ", false)]
        [InlineData(" authorization_code", false)]
        [InlineData(" authorization_code ", false)]
        [InlineData("client_credentials", false)]
        [InlineData("password", false)]
        [InlineData("refresh_token", false)]
        [InlineData("AUTHORIZATION_CODE", false)]
        [InlineData("CLIENT_CREDENTIALS", false)]
        [InlineData("PASSWORD", false)]
        [InlineData("REFRESH_TOKEN", false)]
        [InlineData("urn:ietf:params:oauth:grant-type:device_code", false)]
        public void IsAuthorizationCodeGrantType_ReturnsExpectedResult(string type, bool result)
        {
            // Arrange
            var request = new OpenIddictRequest
            {
                GrantType = type
            };

            // Act and assert
            Assert.Equal(result, request.IsAuthorizationCodeGrantType());
        }

        [Fact]
        public void IsClientCredentialsGrantType_ThrowsAnExceptionForNullRequest()
        {
            // Arrange
            var request = (OpenIddictRequest) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => request.IsClientCredentialsGrantType());

            Assert.Equal("request", exception.ParamName);
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData("authorization_code", false)]
        [InlineData("client_credentials", true)]
        [InlineData("client_credentials ", false)]
        [InlineData(" client_credentials", false)]
        [InlineData(" client_credentials ", false)]
        [InlineData("password", false)]
        [InlineData("refresh_token", false)]
        [InlineData("AUTHORIZATION_CODE", false)]
        [InlineData("CLIENT_CREDENTIALS", false)]
        [InlineData("PASSWORD", false)]
        [InlineData("REFRESH_TOKEN", false)]
        [InlineData("urn:ietf:params:oauth:grant-type:device_code", false)]
        public void IsClientCredentialsGrantType_ReturnsExpectedResult(string type, bool result)
        {
            // Arrange
            var request = new OpenIddictRequest
            {
                GrantType = type
            };

            // Act and assert
            Assert.Equal(result, request.IsClientCredentialsGrantType());
        }

        [Fact]
        public void IsDeviceCodeGrantType_ThrowsAnExceptionForNullRequest()
        {
            // Arrange
            var request = (OpenIddictRequest)null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => request.IsDeviceCodeGrantType());

            Assert.Equal("request", exception.ParamName);
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData("authorization_code", false)]
        [InlineData("client_credentials", false)]
        [InlineData("password", false)]
        [InlineData("refresh_token", false)]
        [InlineData("AUTHORIZATION_CODE", false)]
        [InlineData("CLIENT_CREDENTIALS", false)]
        [InlineData("PASSWORD", false)]
        [InlineData("REFRESH_TOKEN", false)]
        [InlineData("urn:ietf:params:oauth:grant-type:device_code", true)]
        [InlineData("urn:ietf:params:oauth:grant-type:device_code ", false)]
        [InlineData(" urn:ietf:params:oauth:grant-type:device_code", false)]
        [InlineData(" urn:ietf:params:oauth:grant-type:device_code ", false)]
        public void IsDeviceCodeGrantType_ReturnsExpectedResult(string type, bool result)
        {
            // Arrange
            var request = new OpenIddictRequest
            {
                GrantType = type
            };

            // Act and assert
            Assert.Equal(result, request.IsDeviceCodeGrantType());
        }

        [Fact]
        public void IsPasswordGrantType_ThrowsAnExceptionForNullRequest()
        {
            // Arrange
            var request = (OpenIddictRequest) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => request.IsPasswordGrantType());

            Assert.Equal("request", exception.ParamName);
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData("authorization_code", false)]
        [InlineData("client_credentials", false)]
        [InlineData("password", true)]
        [InlineData("password ", false)]
        [InlineData(" password", false)]
        [InlineData(" password ", false)]
        [InlineData("refresh_token", false)]
        [InlineData("AUTHORIZATION_CODE", false)]
        [InlineData("CLIENT_CREDENTIALS", false)]
        [InlineData("PASSWORD", false)]
        [InlineData("REFRESH_TOKEN", false)]
        [InlineData("urn:ietf:params:oauth:grant-type:device_code", false)]
        public void IsPasswordGrantType_ReturnsExpectedResult(string type, bool result)
        {
            // Arrange
            var request = new OpenIddictRequest
            {
                GrantType = type
            };

            // Act and assert
            Assert.Equal(result, request.IsPasswordGrantType());
        }

        [Fact]
        public void IsRefreshTokenGrantType_ThrowsAnExceptionForNullRequest()
        {
            // Arrange
            var request = (OpenIddictRequest) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => request.IsRefreshTokenGrantType());

            Assert.Equal("request", exception.ParamName);
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("unknown", false)]
        [InlineData("authorization_code", false)]
        [InlineData("client_credentials", false)]
        [InlineData("password", false)]
        [InlineData("refresh_token", true)]
        [InlineData("refresh_token ", false)]
        [InlineData(" refresh_token", false)]
        [InlineData(" refresh_token ", false)]
        [InlineData("AUTHORIZATION_CODE", false)]
        [InlineData("CLIENT_CREDENTIALS", false)]
        [InlineData("PASSWORD", false)]
        [InlineData("REFRESH_TOKEN", false)]
        [InlineData("urn:ietf:params:oauth:grant-type:device_code", false)]
        public void IsRefreshTokenGrantType_ReturnsExpectedResult(string type, bool result)
        {
            // Arrange
            var request = new OpenIddictRequest
            {
                GrantType = type
            };

            // Act and assert
            Assert.Equal(result, request.IsRefreshTokenGrantType());
        }
    }
}
