/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Security.Claims;
using System.Text.Json;
using Xunit;

namespace OpenIddict.Abstractions.Tests.Primitives;

public class OpenIddictExtensionsTests
{
    [Fact]
    public void GetAcrValues_ThrowsAnExceptionForNullRequest()
    {
        // Arrange
        var request = (OpenIddictRequest) null!;

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

        // Act and assert
        Assert.Equal(values, request.GetAcrValues());
    }

    [Fact]
    public void GetPrompts_ThrowsAnExceptionForNullRequest()
    {
        // Arrange
        var request = (OpenIddictRequest) null!;

        // Act
        var exception = Assert.Throws<ArgumentNullException>(() => request.GetPrompts());

        // Assert
        Assert.Equal("request", exception.ParamName);
    }

    [Theory]
    [InlineData(null, new string[0])]
    [InlineData("login", new[] { "login" })]
    [InlineData("login ", new[] { "login" })]
    [InlineData(" login ", new[] { "login" })]
    [InlineData("login consent", new[] { "login", "consent" })]
    [InlineData("login     consent", new[] { "login", "consent" })]
    [InlineData("login consent ", new[] { "login", "consent" })]
    [InlineData(" login consent", new[] { "login", "consent" })]
    [InlineData("login login consent", new[] { "login", "consent" })]
    [InlineData("login LOGIN consent", new[] { "login", "LOGIN", "consent" })]
    public void GetPrompts_ReturnsExpectedPrompts(string value, string[] values)
    {
        // Arrange
        var request = new OpenIddictRequest
        {
            Prompt = value
        };

        // Act and assert
        Assert.Equal(values, request.GetPrompts());
    }

    [Fact]
    public void GetResponseTypes_ThrowsAnExceptionForNullRequest()
    {
        // Arrange
        var request = (OpenIddictRequest) null!;

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
    public void GetResponseTypes_ReturnsExpectedResponseTypes(string value, string[] values)
    {
        // Arrange
        var request = new OpenIddictRequest
        {
            ResponseType = value
        };

        // Act and assert
        Assert.Equal(values, request.GetResponseTypes());
    }

    [Fact]
    public void GetScopes_ThrowsAnExceptionForNullRequest()
    {
        // Arrange
        var request = (OpenIddictRequest) null!;

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

        // Act and assert
        Assert.Equal(scopes, request.GetScopes());
    }

    [Fact]
    public void HasAcrValue_ThrowsAnExceptionForNullRequest()
    {
        // Arrange
        var request = (OpenIddictRequest) null!;

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
        Assert.StartsWith(SR.GetResourceString(SR.ID0177), exception.Message);
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
        var request = (OpenIddictRequest) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() =>
        {
            request.HasPrompt(Prompts.Consent);
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
        Assert.StartsWith(SR.GetResourceString(SR.ID0178), exception.Message);
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
        Assert.Equal(result, request.HasPrompt(Prompts.Consent));
    }

    [Fact]
    public void HasResponseType_ThrowsAnExceptionForNullRequest()
    {
        // Arrange
        var request = (OpenIddictRequest) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() =>
        {
            request.HasResponseType(ResponseTypes.Code);
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
        Assert.StartsWith(SR.GetResourceString(SR.ID0179), exception.Message);
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
        Assert.Equal(result, request.HasResponseType(ResponseTypes.Code));
    }

    [Fact]
    public void HasScope_ThrowsAnExceptionForNullRequest()
    {
        // Arrange
        var request = (OpenIddictRequest) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() =>
        {
            request.HasScope(Scopes.OpenId);
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
        Assert.StartsWith(SR.GetResourceString(SR.ID0180), exception.Message);
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
        Assert.Equal(result, request.HasScope(Scopes.OpenId));
    }

    [Fact]
    public void IsNoneFlow_ThrowsAnExceptionForNullRequest()
    {
        // Arrange
        var request = (OpenIddictRequest) null!;

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
        var request = (OpenIddictRequest) null!;

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
        var request = (OpenIddictRequest) null!;

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
        var request = (OpenIddictRequest) null!;

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
        var request = (OpenIddictRequest) null!;

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
        var request = (OpenIddictRequest) null!;

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
        var request = (OpenIddictRequest) null!;

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
        var request = (OpenIddictRequest) null!;

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
        var request = (OpenIddictRequest) null!;

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
        var request = (OpenIddictRequest) null!;

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
        var request = (OpenIddictRequest) null!;

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
        var request = (OpenIddictRequest) null!;

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

    [Fact]
    public void Claim_GetDestinations_ThrowsAnExceptionForNullClaim()
    {
        // Arrange
        var claim = (Claim) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => claim.GetDestinations());

        Assert.Equal("claim", exception.ParamName);
    }

    [Theory]
    [InlineData(null, new string[0])]
    [InlineData("", new string[0])]
    [InlineData("[]", new string[0])]
    [InlineData(@"[""id_token""]", new[] { "id_token" })]
    [InlineData(@"[""access_token"",""id_token""]", new[] { "access_token", "id_token" })]
    [InlineData(@"[""access_token"",""access_token"",""id_token""]", new[] { "access_token", "id_token" })]
    [InlineData(@"[""access_token"",""ACCESS_TOKEN"",""id_token""]", new[] { "access_token", "id_token" })]
    public void Claim_GetDestinations_ReturnsExpectedDestinations(string destination, string[] destinations)
    {
        // Arrange
        var claim = new Claim(Claims.Name, "Bob le Bricoleur");
        claim.Properties[Properties.Destinations] = destination;

        // Act and assert
        Assert.Equal(destinations, claim.GetDestinations());
    }

    [Fact]
    public void Claim_HasDestination_ThrowsAnExceptionForNullClaim()
    {
        // Arrange
        var claim = (Claim) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => claim.HasDestination("destination"));

        Assert.Equal("claim", exception.ParamName);
    }

    [Fact]
    public void Claim_HasDestination_ThrowsAnExceptionForNullOrEmptyDestination()
    {
        // Arrange
        var claim = new Claim(Claims.Name, "Bob le Bricoleur");

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => claim.HasDestination(null!));

        Assert.Equal("destination", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0181), exception.Message);
    }

    [Fact]
    public void Claim_HasDestination_ReturnFalseForNullOrEmptyDestinations()
    {
        // Arrange
        var claim = new Claim(Claims.Name, "Bob le Bricoleur");

        // Act
        var hasDestination = claim.HasDestination("destination");

        // Assert
        Assert.False(hasDestination);
    }

    [Fact]
    public void Claim_HasDestination_ReturnTrueForExistingDestination()
    {
        // Arrange
        var claim = new Claim(Claims.Name, "Bob le Bricoleur");
        claim.SetDestinations(new[] { "destination1", "destination2", "destination3" });

        // Act
        var hasDestination = claim.HasDestination("destination2");

        // Assert
        Assert.True(hasDestination);
    }


    [Fact]
    public void Claim_SetDestinations_ThrowsAnExceptionForNullClaim()
    {
        // Arrange
        var claim = (Claim) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => claim.SetDestinations());

        Assert.Equal("claim", exception.ParamName);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(new object[] { new string[0] })]
    public void Claim_SetDestinations_RemovesPropertyForEmptyArray(string[] destinations)
    {
        // Arrange
        var claim = new Claim(Claims.Name, "Bob le Bricoleur");

        // Act
        claim.SetDestinations(destinations);

        // Assert
        Assert.Equal(0, claim.Properties.Count);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Claim_SetDestinations_ThrowsAnExceptionForNullOrEmptyDestinations(string destination)
    {
        // Arrange
        var claim = new Claim(Claims.Name, "Bob le Bricoleur");

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => claim.SetDestinations(destination));

        Assert.Equal("destinations", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0182), exception.Message);
    }

    [Theory]
    [InlineData(new[] { "access_token" }, @"[""access_token""]")]
    [InlineData(new[] { "access_token", "id_token" }, @"[""access_token"",""id_token""]")]
    [InlineData(new[] { "access_token", "access_token", "id_token" }, @"[""access_token"",""id_token""]")]
    [InlineData(new[] { "access_token", "ACCESS_TOKEN", "id_token" }, @"[""access_token"",""id_token""]")]
    public void Claim_SetDestinations_SetsAppropriateDestinations(string[] destinations, string destination)
    {
        // Arrange
        var claim = new Claim(Claims.Name, "Bob le Bricoleur");

        // Act
        claim.SetDestinations(destinations);

        // Assert
        Assert.Equal(destination, claim.Properties[Properties.Destinations]);
    }

    [Fact]
    public void ClaimsIdentity_GetDestinations_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(identity.GetDestinations);

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_GetDestinations_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(principal.GetDestinations);

        Assert.Equal("principal", exception.ParamName);
    }

    [Fact]
    public void ClaimsIdentity_GetDestinations_ReturnsExpectedDestinations()
    {
        // Arrange
        var claims = new[]
        {
            new Claim(Claims.Name, "Bob le Bricoleur")
            {
                Properties =
                {
                    [Properties.Destinations] = @"[""access_token"",""id_token""]"
                }
            },
            new Claim(Claims.Email, "bob@bricoleur.com")
            {
                Properties =
                {
                    [Properties.Destinations] = @"[""id_token""]"
                }
            },
            new Claim(Claims.Nonce, "OkjjKJkjkHJJHhgFsd")
        };

        var identity = new ClaimsIdentity(claims);

        // Act
        var destinations = identity.GetDestinations();

        // Assert
        Assert.Equal(2, destinations.Count);
        Assert.Equal(new[] { Destinations.AccessToken, Destinations.IdentityToken }, destinations[Claims.Name]);
        Assert.Equal(new[] { Destinations.IdentityToken }, destinations[Claims.Email]);
    }

    [Fact]
    public void ClaimsPrincipal_GetDestinations_ReturnsExpectedDestinations()
    {
        // Arrange
        var claims = new[]
        {
            new Claim(Claims.Name, "Bob le Bricoleur")
            {
                Properties =
                {
                    [Properties.Destinations] = @"[""access_token"",""id_token""]"
                }
            },
            new Claim(Claims.Email, "bob@bricoleur.com")
            {
                Properties =
                {
                    [Properties.Destinations] = @"[""id_token""]"
                }
            },
            new Claim(Claims.Nonce, "OkjjKJkjkHJJHhgFsd")
        };

        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims));

        // Act
        var destinations = principal.GetDestinations();

        // Assert
        Assert.Equal(2, destinations.Count);
        Assert.Equal(new[] { Destinations.AccessToken, Destinations.IdentityToken }, destinations[Claims.Name]);
        Assert.Equal(new[] { Destinations.IdentityToken }, destinations[Claims.Email]);
    }

    [Fact]
    public void ClaimsIdentity_SetDestinationsWithDictionary_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.SetDestinations(destinations: null!));

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_SetDestinationsWithDictionary_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.SetDestinations(destinations: null!));

        Assert.Equal("principal", exception.ParamName);
    }

    [Fact]
    public void ClaimsIdentity_SetDestinationsWithDictionary_ThrowsAnExceptionForNullDestinations()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        var destinations = (ImmutableDictionary<string, string[]>) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.SetDestinations(destinations));

        Assert.Equal("destinations", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_SetDestinationsWithDictionary_ThrowsAnExceptionForNullDestinations()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        var destinations = (ImmutableDictionary<string, string[]>) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.SetDestinations(destinations));

        Assert.Equal("destinations", exception.ParamName);
    }

    [Fact]
    public void ClaimsIdentity_SetDestinationsWithDictionary_SetsAppropriateDestinations()
    {
        // Arrange
        var claims = new[]
        {
            new Claim(Claims.Name, "Bob le Bricoleur"),
            new Claim(Claims.Email, "bob@bricoleur.com"),
            new Claim(Claims.Nonce, "OkjjKJkjkHJJHhgFsd")
        };

        var identity = new ClaimsIdentity(claims);

        var destinations = ImmutableDictionary.CreateBuilder<string, string[]>(StringComparer.Ordinal);
        destinations.Add(Claims.Name, new[] { Destinations.AccessToken, Destinations.IdentityToken });
        destinations.Add(Claims.Email, new[] { Destinations.IdentityToken });
        destinations.Add(Claims.Nonce, Array.Empty<string>());

        // Act
        identity.SetDestinations(destinations.ToImmutable());

        // Assert
        Assert.Equal(@"[""access_token"",""id_token""]", identity.FindFirst(Claims.Name)!.Properties[Properties.Destinations]);
        Assert.Equal(@"[""id_token""]", identity.FindFirst(Claims.Email)!.Properties[Properties.Destinations]);
        Assert.DoesNotContain(Properties.Destinations, identity.FindFirst(Claims.Nonce)!.Properties);
    }

    [Fact]
    public void ClaimsPrincipal_SetDestinationsWithDictionary_SetsAppropriateDestinations()
    {
        // Arrange
        var claims = new[]
        {
            new Claim(Claims.Name, "Bob le Bricoleur"),
            new Claim(Claims.Email, "bob@bricoleur.com"),
            new Claim(Claims.Nonce, "OkjjKJkjkHJJHhgFsd")
        };

        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims));

        var destinations = ImmutableDictionary.CreateBuilder<string, string[]>(StringComparer.Ordinal);
        destinations.Add(Claims.Name, new[] { Destinations.AccessToken, Destinations.IdentityToken });
        destinations.Add(Claims.Email, new[] { Destinations.IdentityToken });
        destinations.Add(Claims.Nonce, Array.Empty<string>());

        // Act
        principal.SetDestinations(destinations.ToImmutable());

        // Assert
        Assert.Equal(@"[""access_token"",""id_token""]", principal.FindFirst(Claims.Name)!.Properties[Properties.Destinations]);
        Assert.Equal(@"[""id_token""]", principal.FindFirst(Claims.Email)!.Properties[Properties.Destinations]);
        Assert.DoesNotContain(Properties.Destinations, principal.FindFirst(Claims.Nonce)!.Properties);
    }

    [Fact]
    public void ClaimsIdentity_SetDestinationsWithDelegate_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.SetDestinations(selector: null!));

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_SetDestinationsWithDelegate_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.SetDestinations(selector: null!));

        Assert.Equal("principal", exception.ParamName);
    }

    [Fact]
    public void ClaimsIdentity_SetDestinationsWithDelegate_ThrowsAnExceptionForNullSelector()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        var selector = (Func<Claim, IEnumerable<string>>) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.SetDestinations(selector));

        Assert.Equal("selector", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_SetDestinationsWithDelegate_ThrowsAnExceptionForNullSelector()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        var selector = (Func<Claim, IEnumerable<string>>) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.SetDestinations(selector));

        Assert.Equal("selector", exception.ParamName);
    }

    [Fact]
    public void ClaimsIdentity_SetDestinationsWithDelegate_SetsAppropriateDestinations()
    {
        // Arrange
        var claims = new[]
        {
            new Claim(Claims.Name, "Bob le Bricoleur"),
            new Claim(Claims.Email, "bob@bricoleur.com"),
            new Claim(Claims.Nonce, "OkjjKJkjkHJJHhgFsd")
        };

        var identity = new ClaimsIdentity(claims);

        // Act
        identity.SetDestinations(claim => claim.Type switch
        {
            Claims.Name  => new[] { Destinations.AccessToken, Destinations.IdentityToken },
            Claims.Email => new[] { Destinations.IdentityToken },

            _ => Array.Empty<string>()
        });

        // Assert
        Assert.Equal(@"[""access_token"",""id_token""]", identity.FindFirst(Claims.Name)!.Properties[Properties.Destinations]);
        Assert.Equal(@"[""id_token""]", identity.FindFirst(Claims.Email)!.Properties[Properties.Destinations]);
        Assert.DoesNotContain(Properties.Destinations, identity.FindFirst(Claims.Nonce)!.Properties);
    }

    [Fact]
    public void ClaimsPrincipal_SetDestinationsWithDelegate_SetsAppropriateDestinations()
    {
        // Arrange
        var claims = new[]
        {
            new Claim(Claims.Name, "Bob le Bricoleur"),
            new Claim(Claims.Email, "bob@bricoleur.com"),
            new Claim(Claims.Nonce, "OkjjKJkjkHJJHhgFsd")
        };

        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims));

        // Act
        principal.SetDestinations(claim => claim.Type switch
        {
            Claims.Name => new[] { Destinations.AccessToken, Destinations.IdentityToken },
            Claims.Email => new[] { Destinations.IdentityToken },

            _ => Array.Empty<string>()
        });

        // Assert
        Assert.Equal(@"[""access_token"",""id_token""]", principal.FindFirst(Claims.Name)!.Properties[Properties.Destinations]);
        Assert.Equal(@"[""id_token""]", principal.FindFirst(Claims.Email)!.Properties[Properties.Destinations]);
        Assert.DoesNotContain(Properties.Destinations, principal.FindFirst(Claims.Nonce)!.Properties);
    }

    [Fact]
    public void ClaimsIdentity_Clone_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.Clone(claim => true));

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_Clone_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.Clone(claim => true));

        Assert.Equal("principal", exception.ParamName);
    }

    [Fact]
    public void ClaimsIdentity_Clone_ReturnsIdenticalIdentity()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.AddClaim("type", "value");

        // Act
        var copy = identity.Clone(claim => true);

        // Assert
        Assert.Equal("value", copy.GetClaim("type"));
        Assert.Equal(identity.Claims.Count(), copy.Claims.Count());
    }

    [Fact]
    public void ClaimsPrincipal_Clone_ReturnsIdenticalPrincipal()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.AddClaim(new Claim(Claims.Name, "Bob le Bricoleur"));

        var principal = new ClaimsPrincipal(identity);

        // Act
        var copy = principal.Clone(claim => true);

        // Assert
        Assert.Equal("Bob le Bricoleur", copy.GetClaim(Claims.Name));
        Assert.Equal(principal.Claims.Count(), copy.Claims.Count());
    }

    [Fact]
    public void ClaimsIdentity_Clone_ReturnsDifferentIdentityInstance()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.AddClaim("type", "value");

        // Act
        var copy = identity.Clone(claim => true);
        copy.AddClaim("clone_type", "value");

        // Assert
        Assert.NotSame(identity, copy);
        Assert.Null(identity.FindFirst("clone_type"));
    }

    [Fact]
    public void ClaimsPrincipal_Clone_ReturnsDifferentPrincipalInstance()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.AddClaim(new Claim(Claims.Name, "Bob le Bricoleur"));

        var principal = new ClaimsPrincipal(identity);

        // Act
        var copy = principal.Clone(claim => true);
        copy.SetClaim("clone_claim", "value");

        // Assert
        Assert.NotSame(principal, copy);
        Assert.Null(principal.FindFirst("clone_claim"));
    }

    [Fact]
    public void ClaimsIdentity_Clone_ReturnsDifferentInstanceWithFilteredClaims()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.AddClaim(new Claim(Claims.Name, "Bob le Bricoleur"));
        identity.AddClaim(new Claim(Claims.ClientId, "B56BF6CE-8D8C-4290-A0E7-A4F8EE0A9FC4"));

        // Act
        var clone = identity.Clone(claim => claim.Type == Claims.Name);
        clone.AddClaim(new Claim("clone_claim", "value"));

        // Assert
        Assert.NotSame(identity, clone);
        Assert.Null(identity.FindFirst("clone_claim"));
        Assert.NotNull(clone.FindFirst(Claims.Name));
        Assert.Null(clone.FindFirst(Claims.ClientId));
    }

    [Fact]
    public void ClaimsPrincipal_Clone_ReturnsDifferentInstanceWithFilteredClaims()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.AddClaim(new Claim(Claims.Name, "Bob le Bricoleur"));
        identity.AddClaim(new Claim(Claims.ClientId, "B56BF6CE-8D8C-4290-A0E7-A4F8EE0A9FC4"));
        var principal = new ClaimsPrincipal(identity);

        // Act
        var clone = principal.Clone(claim => claim.Type == Claims.Name);
        ((ClaimsIdentity) clone.Identity!).AddClaim(new Claim("clone_claim", "value"));

        // Assert
        Assert.NotSame(identity, clone);
        Assert.Null(identity.FindFirst("clone_claim"));
        Assert.NotNull(clone.FindFirst(Claims.Name));
        Assert.Null(clone.FindFirst(Claims.ClientId));
    }

    [Fact]
    public void ClaimsIdentity_Clone_ExcludesUnwantedClaims()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.AddClaim(new Claim(Claims.Name, "Bob le Bricoleur"));
        identity.AddClaim(new Claim(Claims.Subject, "D8F1A010-BD46-4F8F-AD4E-05582307F8F4"));

        // Act
        var clone = identity.Clone(claim => claim.Type == Claims.Name);

        // Assert
        Assert.Single(clone.Claims);
        Assert.Null(clone.FindFirst(Claims.Subject));
        Assert.Equal("Bob le Bricoleur", clone.FindFirst(Claims.Name)!.Value);
    }

    [Fact]
    public void ClaimsPrincipal_Clone_ExcludesUnwantedClaims()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.AddClaim(new Claim(Claims.Name, "Bob le Bricoleur"));
        identity.AddClaim(new Claim(Claims.Subject, "D8F1A010-BD46-4F8F-AD4E-05582307F8F4"));
        var principal = new ClaimsPrincipal(identity);

        // Act
        var clone = principal.Clone(claim => claim.Type == Claims.Name);

        // Assert
        Assert.Single(clone.Claims);
        Assert.Null(clone.FindFirst(Claims.Subject));
        Assert.Equal("Bob le Bricoleur", clone.FindFirst(Claims.Name)!.Value);
    }

    [Fact]
    public void ClaimsIdentity_Clone_ExcludesUnwantedClaimsFromActor()
    {
        // Arrange
        var identity = new ClaimsIdentity
        {
            Actor = new ClaimsIdentity()
        };
        identity.Actor.AddClaim(new Claim(Claims.Name, "Bob le Bricoleur"));
        identity.Actor.AddClaim(new Claim(Claims.Subject, "D8F1A010-BD46-4F8F-AD4E-05582307F8F4"));

        // Act
        var clone = identity.Clone(claim => claim.Type == Claims.Name);

        // Assert
        Assert.Single(clone.Actor!.Claims);
        Assert.Null(clone.Actor.FindFirst(Claims.Subject));
        Assert.Equal("Bob le Bricoleur", clone.Actor.FindFirst(Claims.Name)!.Value);
    }

    [Fact]
    public void ClaimsPrincipal_Clone_ExcludesUnwantedClaimsFromActor()
    {
        // Arrange
        var identity = new ClaimsIdentity
        {
            Actor = new ClaimsIdentity()
        };
        identity.Actor.AddClaim(new Claim(Claims.Name, "Bob le Bricoleur"));
        identity.Actor.AddClaim(new Claim(Claims.Subject, "D8F1A010-BD46-4F8F-AD4E-05582307F8F4"));
        var principal = new ClaimsPrincipal(identity);

        // Act
        var clone = principal.Clone(claim => claim.Type == Claims.Name);

        // Assert
        Assert.Single(((ClaimsIdentity) clone.Identity!).Actor!.Claims);
        Assert.Null(((ClaimsIdentity) clone.Identity!).FindFirst(Claims.Subject));
        Assert.Equal("Bob le Bricoleur", ((ClaimsIdentity) clone.Identity!).Actor!.FindFirst(Claims.Name)!.Value);
    }

    [Fact]
    public void ClaimsIdentity_AddClaimWithString_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.AddClaim(Claims.Name, "Bob le Bricoleur"));

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_AddClaimWithString_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.AddClaim(Claims.Name, "Bob le Bricoleur"));

        Assert.Equal("principal", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_AddClaimWithString_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var principal = new ClaimsPrincipal();

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => principal.AddClaim(Claims.Name, "Bob le Bricoleur"));

        Assert.Equal("principal", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0286), exception.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsIdentity_AddClaimWithString_ThrowsAnExceptionForNullOrEmptyType(string type)
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => identity.AddClaim(type, "value"));

        Assert.Equal("type", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0184), exception.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsPrincipal_AddClaimWithString_ThrowsAnExceptionForNullOrEmptyType(string type)
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => principal.AddClaim(type, "value"));

        Assert.Equal("type", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0184), exception.Message);
    }

    [Fact]
    public void ClaimsIdentity_AddClaimWithString_AddsExpectedClaim()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act
        identity.AddClaim(Claims.Name, "Bob le Bricoleur");

        // Assert
        Assert.Equal("Bob le Bricoleur", identity.FindFirst(Claims.Name)!.Value);
    }

    [Fact]
    public void ClaimsPrincipal_AddClaimWithString_AddsExpectedClaim()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act
        principal.AddClaim(Claims.Name, "Bob le Bricoleur");

        // Assert
        Assert.Equal("Bob le Bricoleur", principal.FindFirst(Claims.Name)!.Value);
    }

    [Fact]
    public void ClaimsIdentity_AddClaimWithDictionary_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.AddClaim(Claims.Name, new Dictionary<string, string?>()));

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_AddClaimWithDictionary_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.AddClaim(Claims.Name, new Dictionary<string, string?>()));

        Assert.Equal("principal", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_AddClaimWithDictionary_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var principal = new ClaimsPrincipal();

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => principal.AddClaim(Claims.Name, new Dictionary<string, string?>()));

        Assert.Equal("principal", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0286), exception.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsIdentity_AddClaimWithDictionary_ThrowsAnExceptionForNullOrEmptyType(string type)
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => identity.AddClaim(type, new Dictionary<string, string?>()));

        Assert.Equal("type", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0184), exception.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsPrincipal_AddClaimWithDictionary_ThrowsAnExceptionForNullOrEmptyType(string type)
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => principal.AddClaim(type, new Dictionary<string, string?>()));

        Assert.Equal("type", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0184), exception.Message);
    }

    [Fact]
    public void ClaimsIdentity_AddClaimWithDictionary_AddsExpectedClaim()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act
        identity.AddClaim("type", new Dictionary<string, string?>
        {
            ["parameter"] = "value"
        });

        // Assert
        Assert.Equal(@"{""parameter"":""value""}", identity.FindFirst("type")!.Value);
    }

    [Fact]
    public void ClaimsPrincipal_AddClaimWithDictionary_AddsExpectedClaim()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act
        principal.AddClaim("type", new Dictionary<string, string?>
        {
            ["parameter"] = "value"
        });

        // Assert
        Assert.Equal(@"{""parameter"":""value""}", principal.FindFirst("type")!.Value);
    }

    [Fact]
    public void ClaimsIdentity_AddClaimWithJsonElement_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.AddClaim(Claims.Name, default(JsonElement)));

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_AddClaimWithJsonElement_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.AddClaim(Claims.Name, default(JsonElement)));

        Assert.Equal("principal", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_AddClaimWithJsonElement_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var principal = new ClaimsPrincipal();

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => principal.AddClaim(Claims.Name, default(JsonElement)));

        Assert.Equal("principal", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0286), exception.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsIdentity_AddClaimWithJsonElement_ThrowsAnExceptionForNullOrEmptyType(string type)
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => identity.AddClaim(type, default(JsonElement)));

        Assert.Equal("type", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0184), exception.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsPrincipal_AddClaimWithJsonElement_ThrowsAnExceptionForNullOrEmptyType(string type)
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => principal.AddClaim(type, default(JsonElement)));

        Assert.Equal("type", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0184), exception.Message);
    }

    [Fact]
    public void ClaimsIdentity_AddClaimWithJsonElement_ThrowsAnExceptionForIncompatibleJsonElement()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => identity.AddClaim("type",
            JsonSerializer.Deserialize<JsonElement>(@"[""Fabrikam"",""Contoso""]")));

        Assert.Equal("value", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0185), exception.Message);
    }

    [Fact]
    public void ClaimsPrincipal_AddClaimWithJsonElement_ThrowsAnExceptionForIncompatibleJsonElement()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => principal.AddClaim("type",
            JsonSerializer.Deserialize<JsonElement>(@"[""Fabrikam"",""Contoso""]")));

        Assert.Equal("value", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0185), exception.Message);
    }

    [Fact]
    public void ClaimsIdentity_AddClaimWithJsonElement_AddsExpectedClaim()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act
        identity.AddClaim("type", JsonSerializer.Deserialize<JsonElement>(@"{""parameter"":""value""}"));

        // Assert
        Assert.Equal(@"{""parameter"":""value""}", identity.FindFirst("type")!.Value);
    }

    [Fact]
    public void ClaimsPrincipal_AddClaimWithJsonElement_AddsExpectedClaim()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act
        principal.AddClaim("type", JsonSerializer.Deserialize<JsonElement>(@"{""parameter"":""value""}"));

        // Assert
        Assert.Equal(@"{""parameter"":""value""}", principal.FindFirst("type")!.Value);
    }

    [Fact]
    public void ClaimsIdentity_AddClaimsWithArray_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.AddClaims("type", ImmutableArray.Create<string>()));

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_AddClaimsWithArray_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.AddClaims("type", ImmutableArray.Create<string>()));

        Assert.Equal("principal", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_AddClaimsWithArray_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var principal = new ClaimsPrincipal();

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => principal.AddClaims("type", ImmutableArray.Create("value1", "value2")));

        Assert.Equal("principal", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0286), exception.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsIdentity_AddClaimsWithArray_ThrowsAnExceptionForNullOrEmptyType(string type)
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => identity.AddClaims(type, ImmutableArray.Create<string>()));

        Assert.Equal("type", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0184), exception.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsPrincipal_AddClaimsWithArray_ThrowsAnExceptionForNullOrEmptyType(string type)
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => principal.AddClaims(type, ImmutableArray.Create<string>()));

        Assert.Equal("type", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0184), exception.Message);
    }

    [Fact]
    public void ClaimsIdentity_AddClaimsWithArray_AddsExpectedClaims()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act
        identity.AddClaims("type", ImmutableArray.Create("value1", "value2"), "issuer");

        // Assert
        var claims = identity.FindAll("type").ToArray();
        Assert.Equal(2, claims.Length);
        Assert.Equal("value1", claims[0].Value);
        Assert.Equal(ClaimValueTypes.String, claims[0].ValueType);
        Assert.Equal("issuer", claims[0].Issuer);
        Assert.Equal("value2", claims[1].Value);
        Assert.Equal(ClaimValueTypes.String, claims[1].ValueType);
        Assert.Equal("issuer", claims[1].Issuer);
    }

    [Fact]
    public void ClaimsPrincipal_AddClaimsWithArray_AddsExpectedClaims()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act
        principal.AddClaims("type", ImmutableArray.Create("value1", "value2"), "issuer");

        // Assert
        var claims = principal.FindAll("type").ToArray();
        Assert.Equal(2, claims.Length);
        Assert.Equal("value1", claims[0].Value);
        Assert.Equal(ClaimValueTypes.String, claims[0].ValueType);
        Assert.Equal("issuer", claims[0].Issuer);
        Assert.Equal("value2", claims[1].Value);
        Assert.Equal(ClaimValueTypes.String, claims[1].ValueType);
        Assert.Equal("issuer", claims[1].Issuer);
    }

    [Fact]
    public void ClaimsIdentity_AddClaimsWithArray_IsCaseInsensitive()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act
        identity.AddClaims("TYPE", ImmutableArray.Create("value1", "value2"));

        // Assert
        Assert.Equal<string>(ImmutableArray.Create("value1", "value2"), identity.GetClaims("type"));
    }

    [Fact]
    public void ClaimsPrincipal_AddClaimsWithArray_IsCaseInsensitive()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act
        principal.AddClaims("TYPE", ImmutableArray.Create("value1", "value2"));

        // Assert
        Assert.Equal<string>(ImmutableArray.Create("value1", "value2"), principal.GetClaims("type"));
    }

    [Fact]
    public void ClaimsIdentity_AddClaimsWithJsonElement_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.AddClaims("type", default(JsonElement)));

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_AddClaimsWithJsonElement_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.AddClaims("type", default(JsonElement)));

        Assert.Equal("principal", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_AddClaimsWithJsonElement_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var principal = new ClaimsPrincipal();

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => principal.AddClaims("type", default(JsonElement)));

        Assert.Equal("principal", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0286), exception.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsIdentity_AddClaimsWithJsonElement_ThrowsAnExceptionForNullOrEmptyType(string type)
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => identity.AddClaims(type, default(JsonElement)));

        Assert.Equal("type", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0184), exception.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsPrincipal_AddClaimsWithJsonElement_ThrowsAnExceptionForNullOrEmptyType(string type)
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => principal.AddClaims(type, default(JsonElement)));

        Assert.Equal("type", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0184), exception.Message);
    }

    [Fact]
    public void ClaimsIdentity_AddClaimsWithJsonElement_ThrowsAnExceptionForIncompatibleJsonElement()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => identity.AddClaims("type",
            JsonSerializer.Deserialize<JsonElement>(@"{""parameter"":""value""}")));

        Assert.Equal("value", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0185), exception.Message);
    }

    [Fact]
    public void ClaimsPrincipal_AddClaimsWithJsonElement_ThrowsAnExceptionForIncompatibleJsonElement()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => principal.AddClaims("type",
            JsonSerializer.Deserialize<JsonElement>(@"{""parameter"":""value""}")));

        Assert.Equal("value", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0185), exception.Message);
    }

    [Fact]
    public void ClaimsIdentity_AddClaimsWithJsonElement_AddsExpectedClaims()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act
        identity.AddClaims("type", JsonSerializer.Deserialize<JsonElement>(@"[""Fabrikam"",""Contoso""]"), "issuer");

        // Assert
        var claims = identity.FindAll("type").ToArray();
        Assert.Equal("Fabrikam", claims[0].Value);
        Assert.Equal(ClaimValueTypes.String, claims[0].ValueType);
        Assert.Equal("issuer", claims[0].Issuer);
        Assert.Equal("Contoso", claims[1].Value);
        Assert.Equal(ClaimValueTypes.String, claims[1].ValueType);
        Assert.Equal("issuer", claims[1].Issuer);
    }

    [Fact]
    public void ClaimsPrincipal_AddClaimsWithJsonElement_AddsExpectedClaims()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act
        principal.AddClaims("type", JsonSerializer.Deserialize<JsonElement>(@"[""Fabrikam"",""Contoso""]"), "issuer");

        // Assert
        var claims = principal.FindAll("type").ToArray();
        Assert.Equal(2, claims.Length);
        Assert.Equal("Fabrikam", claims[0].Value);
        Assert.Equal(ClaimValueTypes.String, claims[0].ValueType);
        Assert.Equal("issuer", claims[0].Issuer);
        Assert.Equal("Contoso", claims[1].Value);
        Assert.Equal(ClaimValueTypes.String, claims[1].ValueType);
        Assert.Equal("issuer", claims[1].Issuer);
    }

    [Fact]
    public void ClaimsIdentity_AddClaimsWithJsonElement_IsCaseInsensitive()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act
        identity.AddClaims("TYPE", JsonSerializer.Deserialize<JsonElement>(@"[""Fabrikam"",""Contoso""]"));

        // Assert
        Assert.Equal<string>(ImmutableArray.Create("Fabrikam", "Contoso"), identity.GetClaims("type"));
    }

    [Fact]
    public void ClaimsPrincipal_AddClaimsWithJsonElement_IsCaseInsensitive()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act
        principal.AddClaims("TYPE", JsonSerializer.Deserialize<JsonElement>(@"[""Fabrikam"",""Contoso""]"));

        // Assert
        Assert.Equal<string>(ImmutableArray.Create("Fabrikam", "Contoso"), principal.GetClaims("type"));
    }

    [Fact]
    public void ClaimsIdentity_GetClaim_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() =>
        {
            identity.GetClaim(Claims.Name);
        });

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_GetClaim_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() =>
        {
            principal.GetClaim(Claims.Name);
        });

        Assert.Equal("principal", exception.ParamName);
    }

    [Fact]
    public void ClaimsIdentity_GetClaim_ReturnsNullForMissingClaims()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act and assert
        Assert.Null(identity.GetClaim(Claims.Name));
    }

    [Fact]
    public void ClaimsPrincipal_GetClaim_ReturnsNullForMissingClaims()
    {
        // Arrange
        var principal = new ClaimsPrincipal();

        // Act and assert
        Assert.Null(principal.GetClaim(Claims.Name));
    }

    [Fact]
    public void ClaimsIdentity_GetClaim_ReturnsAppropriateResult()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.AddClaim(Claims.Name, "Bob le Bricoleur");

        // Act and assert
        Assert.Equal("Bob le Bricoleur", identity.GetClaim(Claims.Name));
    }

    [Fact]
    public void ClaimsPrincipal_GetClaim_ReturnsAppropriateResult()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.AddClaim(Claims.Name, "Bob le Bricoleur");

        // Act and assert
        Assert.Equal("Bob le Bricoleur", principal.GetClaim(Claims.Name));
    }

    [Fact]
    public void ClaimsIdentity_GetClaim_IsCaseInsensitive()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.SetClaim("type", "value");

        // Act and assert
        Assert.Equal("value", identity.GetClaim("TYPE"));
    }

    [Fact]
    public void ClaimsPrincipal_GetClaim_IsCaseInsensitive()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.SetClaim("type", "value");

        // Act and assert
        Assert.Equal("value", principal.GetClaim("TYPE"));
    }

    [Fact]
    public void ClaimsIdentity_GetClaims_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.GetClaims("type"));

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_GetClaims_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.GetClaims("type"));

        Assert.Equal("principal", exception.ParamName);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsIdentity_GetClaims_ThrowsAnExceptionForNullOrEmptyClaimType(string type)
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => identity.GetClaims(type));

        Assert.Equal("type", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0184), exception.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsPrincipal_GetClaims_ThrowsAnExceptionForNullOrEmptyClaimType(string type)
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => principal.GetClaims(type));

        Assert.Equal("type", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0184), exception.Message);
    }

    [Fact]
    public void ClaimsIdentity_GetClaims_ReturnsExpectedResult()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.AddClaim(new Claim(Claims.Name, "Bob le Bricoleur"));
        identity.AddClaim(new Claim(Claims.Scope, Scopes.OpenId));
        identity.AddClaim(new Claim(Claims.Scope, Scopes.Profile));

        // Act and assert
        Assert.Equal(new[] { Scopes.OpenId, Scopes.Profile }, identity.GetClaims(Claims.Scope));
    }

    [Fact]
    public void ClaimsPrincipal_GetClaims_ReturnsExpectedResult()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.AddClaim(new Claim(Claims.Name, "Bob le Bricoleur"));
        identity.AddClaim(new Claim(Claims.Scope, Scopes.OpenId));
        identity.AddClaim(new Claim(Claims.Scope, Scopes.Profile));

        var principal = new ClaimsPrincipal(identity);

        // Act and assert
        Assert.Equal(new[] { Scopes.OpenId, Scopes.Profile }, principal.GetClaims(Claims.Scope));
    }

    [Fact]
    public void ClaimsIdentity_HasClaim_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.HasClaim("type"));

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_HasClaim_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.HasClaim("type"));

        Assert.Equal("principal", exception.ParamName);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsIdentity_HasClaim_ThrowsAnExceptionForNullOrEmptyClaimType(string type)
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => identity.HasClaim(type));

        Assert.Equal("type", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0184), exception.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsPrincipal_HasClaim_ThrowsAnExceptionForNullOrEmptyClaimType(string type)
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => principal.HasClaim(type));

        Assert.Equal("type", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0184), exception.Message);
    }

    [Fact]
    public void ClaimsIdentity_HasClaim_ReturnsExpectedResult()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.AddClaim(new Claim(Claims.Name, "Bob le Bricoleur"));
        identity.AddClaim(new Claim(Claims.Scope, Scopes.OpenId));
        identity.AddClaim(new Claim(Claims.Scope, Scopes.Profile));

        // Act and assert
        Assert.True(identity.HasClaim(Claims.Name));
        Assert.True(identity.HasClaim(Claims.Scope));
        Assert.False(identity.HasClaim(Claims.Nickname));
    }

    [Fact]
    public void ClaimsPrincipal_HasClaim_ReturnsExpectedResult()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.AddClaim(new Claim(Claims.Name, "Bob le Bricoleur"));
        identity.AddClaim(new Claim(Claims.Scope, Scopes.OpenId));
        identity.AddClaim(new Claim(Claims.Scope, Scopes.Profile));

        var principal = new ClaimsPrincipal(identity);

        // Act and assert
        Assert.True(principal.HasClaim(Claims.Name));
        Assert.True(principal.HasClaim(Claims.Scope));
        Assert.False(principal.HasClaim(Claims.Nickname));
    }

    [Fact]
    public void ClaimsIdentity_RemoveClaims_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.RemoveClaims("type"));

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_RemoveClaims_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.RemoveClaims("type"));

        Assert.Equal("principal", exception.ParamName);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsIdentity_RemoveClaims_ThrowsAnExceptionForNullOrEmptyClaimType(string type)
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => identity.RemoveClaims(type));

        Assert.Equal("type", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0184), exception.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsPrincipal_RemoveClaims_ThrowsAnExceptionForNullOrEmptyClaimType(string type)
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => principal.RemoveClaims(type));

        Assert.Equal("type", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0184), exception.Message);
    }

    [Fact]
    public void ClaimsIdentity_RemoveClaims_RemoveClaims()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.SetClaim("type", "value");

        // Act
        identity.RemoveClaims("type");

        // Assert
        Assert.Null(identity.GetClaim("type"));
    }

    [Fact]
    public void ClaimsPrincipal_RemoveClaims_RemoveClaims()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.SetClaim("type", "value");

        // Act
        principal.RemoveClaims("type");

        // Assert
        Assert.Null(principal.GetClaim("type"));
    }

    [Fact]
    public void ClaimsIdentity_SetClaimWithString_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.SetClaim("type", "value"));

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_SetClaimWithString_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.SetClaim("type", "value"));

        Assert.Equal("principal", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_SetClaimWithString_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var principal = new ClaimsPrincipal();

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => principal.SetClaim("type", "value"));

        Assert.Equal("principal", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0286), exception.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsIdentity_SetClaimWithString_ThrowsAnExceptionForNullOrEmptyType(string type)
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => identity.SetClaim(type, "value"));

        Assert.Equal("type", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0184), exception.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsPrincipal_SetClaimWithString_ThrowsAnExceptionForNullOrEmptyType(string type)
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => principal.SetClaim(type, "value"));

        Assert.Equal("type", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0184), exception.Message);
    }

    [Fact]
    public void ClaimsIdentity_SetClaimWithString_AddsExpectedClaim()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.AddClaim("type", "value1");

        // Act
        identity.SetClaim("type", "value2", "issuer");

        // Assert
        var claim = Assert.Single(identity.FindAll("type"));
        Assert.Equal("value2", claim.Value);
        Assert.Equal(ClaimValueTypes.String, claim.ValueType);
        Assert.Equal("issuer", claim.Issuer);
    }

    [Fact]
    public void ClaimsPrincipal_SetClaimWithString_AddsExpectedClaim()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.AddClaim("type", "value1");

        // Act
        principal.SetClaim("type", "value2", "issuer");

        // Assert
        var claim = Assert.Single(principal.FindAll("type"));
        Assert.Equal("value2", claim.Value);
        Assert.Equal(ClaimValueTypes.String, claim.ValueType);
        Assert.Equal("issuer", claim.Issuer);
    }

    [Fact]
    public void ClaimsIdentity_SetClaimWithString_IsCaseInsensitive()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act
        identity.SetClaim("TYPE", "value");

        // Assert
        Assert.Equal("value", identity.GetClaim("type"));
    }

    [Fact]
    public void ClaimsPrincipal_SetClaimWithString_IsCaseInsensitive()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act
        principal.SetClaim("TYPE", "value");

        // Assert
        Assert.Equal("value", principal.GetClaim("type"));
    }

    [Fact]
    public void ClaimsIdentity_SetClaimWithString_RemovesEmptyClaim()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.AddClaim("type", "value");

        // Act
        identity.SetClaim("type", string.Empty);

        // Assert
        Assert.Null(identity.GetClaim("type"));
    }

    [Fact]
    public void ClaimsPrincipal_SetClaimWithString_RemovesEmptyClaim()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.AddClaim("type", "value");

        // Act
        principal.SetClaim("type", string.Empty);

        // Assert
        Assert.Null(principal.GetClaim("type"));
    }

    [Fact]
    public void ClaimsIdentity_SetClaimWithDictionary_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.SetClaim("type", new Dictionary<string, string?>()));

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_SetClaimWithDictionary_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.SetClaim("type", new Dictionary<string, string?>()));

        Assert.Equal("principal", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_SetClaimWithDictionary_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var principal = new ClaimsPrincipal();

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => principal.SetClaim("type", new Dictionary<string, string?>
        {
            ["parameter"] = "value"
        }));

        Assert.Equal("principal", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0286), exception.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsIdentity_SetClaimWithDictionary_ThrowsAnExceptionForNullOrEmptyType(string type)
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => identity.SetClaim(type, new Dictionary<string, string?>()));

        Assert.Equal("type", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0184), exception.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsPrincipal_SetClaimWithDictionary_ThrowsAnExceptionForNullOrEmptyType(string type)
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => principal.SetClaim(type, new Dictionary<string, string?>()));

        Assert.Equal("type", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0184), exception.Message);
    }

    [Fact]
    public void ClaimsIdentity_SetClaimWithDictionary_AddsExpectedClaim()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.AddClaim("type", "value1");

        // Act
        identity.SetClaim("type", new Dictionary<string, string?>
        {
            ["parameter"] = "value"
        }, "issuer");

        // Assert
        var claim = Assert.Single(identity.FindAll("type"));
        Assert.Equal(@"{""parameter"":""value""}", claim.Value);
        Assert.Equal("JSON", claim.ValueType);
        Assert.Equal("issuer", claim.Issuer);
    }

    [Fact]
    public void ClaimsPrincipal_SetClaimWithDictionary_AddsExpectedClaim()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.AddClaim("type", "value1");

        // Act
        principal.SetClaim("type", new Dictionary<string, string?>
        {
            ["parameter"] = "value"
        }, "issuer");

        // Assert
        var claim = Assert.Single(principal.FindAll("type"));
        Assert.Equal(@"{""parameter"":""value""}", claim.Value);
        Assert.Equal("JSON", claim.ValueType);
        Assert.Equal("issuer", claim.Issuer);
    }

    [Fact]
    public void ClaimsIdentity_SetClaimWithDictionary_IsCaseInsensitive()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act
        identity.SetClaim("TYPE", new Dictionary<string, string?>
        {
            ["parameter"] = "value"
        });

        // Assert
        Assert.Equal(@"{""parameter"":""value""}", identity.FindFirst("type")!.Value);
    }

    [Fact]
    public void ClaimsPrincipal_SetClaimWithDictionary_IsCaseInsensitive()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act
        principal.SetClaim("TYPE", new Dictionary<string, string?>
        {
            ["parameter"] = "value"
        });

        // Assert
        Assert.Equal(@"{""parameter"":""value""}", principal.FindFirst("type")!.Value);
    }

    [Fact]
    public void ClaimsIdentity_SetClaimWithDictionary_RemovesEmptyClaim()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.AddClaim("type", "value");

        // Act
        identity.SetClaim("type", new Dictionary<string, string?>());

        // Assert
        Assert.Null(identity.GetClaim("type"));
    }

    [Fact]
    public void ClaimsPrincipal_SetClaimWithDictionary_RemovesEmptyClaim()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.AddClaim("type", "value");

        // Act
        principal.SetClaim("type", new Dictionary<string, string?>());

        // Assert
        Assert.Null(principal.GetClaim("type"));
    }

    [Fact]
    public void ClaimsIdentity_SetClaimWithJsonElement_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.SetClaim("type", default(JsonElement)));

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_SetClaimWithJsonElement_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.SetClaim("type", default(JsonElement)));

        Assert.Equal("principal", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_SetClaimWithJsonElement_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var principal = new ClaimsPrincipal();

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => principal.SetClaim("type",
            JsonSerializer.Deserialize<JsonElement>(@"{""parameter"":""value""}")));

        Assert.Equal("principal", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0286), exception.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsIdentity_SetClaimWithJsonElement_ThrowsAnExceptionForNullOrEmptyType(string type)
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => identity.SetClaim(type, default(JsonElement)));

        Assert.Equal("type", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0184), exception.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsPrincipal_SetClaimWithJsonElement_ThrowsAnExceptionForNullOrEmptyType(string type)
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => principal.SetClaim(type, default(JsonElement)));

        Assert.Equal("type", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0184), exception.Message);
    }

    [Fact]
    public void ClaimsIdentity_SetClaimWithJsonElement_AddsExpectedClaim()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.AddClaim("type", "value1");

        // Act
        identity.SetClaim("type", JsonSerializer.Deserialize<JsonElement>(@"{""parameter"":""value""}"), "issuer");

        // Assert
        var claim = Assert.Single(identity.FindAll("type"));
        Assert.Equal(@"{""parameter"":""value""}", claim.Value);
        Assert.Equal("JSON", claim.ValueType);
        Assert.Equal("issuer", claim.Issuer);
    }

    [Fact]
    public void ClaimsPrincipal_SetClaimWithJsonElement_AddsExpectedClaim()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.AddClaim("type", "value1");

        // Act
        principal.SetClaim("type", JsonSerializer.Deserialize<JsonElement>(@"{""parameter"":""value""}"), "issuer");

        // Assert
        var claim = Assert.Single(principal.FindAll("type"));
        Assert.Equal(@"{""parameter"":""value""}", claim.Value);
        Assert.Equal("JSON", claim.ValueType);
        Assert.Equal("issuer", claim.Issuer);
    }

    [Fact]
    public void ClaimsIdentity_SetClaimWithJsonElement_IsCaseInsensitive()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act
        identity.SetClaim("TYPE", JsonSerializer.Deserialize<JsonElement>(@"{""parameter"":""value""}"));

        // Assert
        Assert.Equal(@"{""parameter"":""value""}", identity.FindFirst("type")!.Value);
    }

    [Fact]
    public void ClaimsPrincipal_SetClaimWithJsonElement_IsCaseInsensitive()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act
        principal.SetClaim("TYPE", JsonSerializer.Deserialize<JsonElement>(@"{""parameter"":""value""}"));

        // Assert
        Assert.Equal(@"{""parameter"":""value""}", principal.FindFirst("type")!.Value);
    }

    [Fact]
    public void ClaimsIdentity_SetClaimWithJsonElement_RemovesEmptyClaim()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.AddClaim("type", "value");

        // Act
        identity.SetClaim("type", JsonSerializer.Deserialize<JsonElement>("{}"));

        // Assert
        Assert.Null(identity.GetClaim("type"));
    }

    [Fact]
    public void ClaimsPrincipal_SetClaimWithJsonElement_RemovesEmptyClaim()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.AddClaim("type", "value");

        // Act
        principal.SetClaim("type", JsonSerializer.Deserialize<JsonElement>("{}"));

        // Assert
        Assert.Null(principal.GetClaim("type"));
    }

    [Fact]
    public void ClaimsIdentity_SetClaimWithJsonElement_Undefined()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act
        identity.SetClaim("type", default(JsonElement));

        // Assert
        Assert.Null(identity.GetClaim("type"));
    }

    [Fact]
    public void ClaimsPrincipal_SetClaimWithJsonElement_Undefined()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.AddClaim("type", "value");

        // Act
        principal.SetClaim("type", default(JsonElement));

        // Assert
        Assert.Null(principal.GetClaim("type"));
    }

    [Fact]
    public void ClaimsIdentity_SetClaimWithJsonElement_Null()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act
        identity.SetClaim("type", JsonSerializer.Deserialize<JsonElement>("null"));

        // Assert
        Assert.Null(identity.GetClaim("type"));
    }

    [Fact]
    public void ClaimsPrincipal_SetClaimWithJsonElement_Null()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.AddClaim("type", "value");

        // Act
        principal.SetClaim("type", JsonSerializer.Deserialize<JsonElement>("null"));

        // Assert
        Assert.Null(principal.GetClaim("type"));
    }

    [Fact]
    public void ClaimsIdentity_SetClaimsWithArray_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.SetClaims("type", ImmutableArray.Create<string>()));

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_SetClaimsWithArray_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.SetClaims("type", ImmutableArray.Create<string>()));

        Assert.Equal("principal", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_SetClaimsWithArray_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var principal = new ClaimsPrincipal();

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => principal.SetClaims("type", ImmutableArray.Create("value1", "value2")));

        Assert.Equal("principal", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0286), exception.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsIdentity_SetClaimsWithArray_ThrowsAnExceptionForNullOrEmptyType(string type)
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => identity.SetClaims(type, ImmutableArray.Create<string>()));

        Assert.Equal("type", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0184), exception.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsPrincipal_SetClaimsWithArray_ThrowsAnExceptionForNullOrEmptyType(string type)
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => principal.SetClaims(type, ImmutableArray.Create<string>()));

        Assert.Equal("type", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0184), exception.Message);
    }

    [Fact]
    public void ClaimsIdentity_SetClaimsWithArray_AddsExpectedClaims()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act
        identity.SetClaims("type", ImmutableArray.Create("value1", "value2"), "issuer");

        // Assert
        var claims = identity.FindAll("type").ToArray();
        Assert.Equal(2, claims.Length);
        Assert.Equal("value1", claims[0].Value);
        Assert.Equal(ClaimValueTypes.String, claims[0].ValueType);
        Assert.Equal("issuer", claims[0].Issuer);
        Assert.Equal("value2", claims[1].Value);
        Assert.Equal(ClaimValueTypes.String, claims[1].ValueType);
        Assert.Equal("issuer", claims[1].Issuer);
    }

    [Fact]
    public void ClaimsPrincipal_SetClaimsWithArray_AddsExpectedClaims()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act
        principal.SetClaims("type", ImmutableArray.Create("value1", "value2"), "issuer");

        // Assert
        var claims = principal.FindAll("type").ToArray();
        Assert.Equal("value1", claims[0].Value);
        Assert.Equal(ClaimValueTypes.String, claims[0].ValueType);
        Assert.Equal("issuer", claims[0].Issuer);
        Assert.Equal("value2", claims[1].Value);
        Assert.Equal(ClaimValueTypes.String, claims[1].ValueType);
        Assert.Equal("issuer", claims[1].Issuer);
    }

    [Fact]
    public void ClaimsIdentity_SetClaimsWithArray_IsCaseInsensitive()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act
        identity.SetClaims("TYPE", ImmutableArray.Create("value1", "value2"));

        // Assert
        Assert.Equal<string>(ImmutableArray.Create("value1", "value2"), identity.GetClaims("type"));
    }

    [Fact]
    public void ClaimsPrincipal_SetClaimsWithArray_IsCaseInsensitive()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act
        principal.SetClaims("TYPE", ImmutableArray.Create("value1", "value2"));

        // Assert
        Assert.Equal<string>(ImmutableArray.Create("value1", "value2"), principal.GetClaims("type"));
    }

    [Fact]
    public void ClaimsIdentity_SetClaimsWithArray_RemovesEmptyClaim()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.AddClaim("type", "value");

        // Act
        identity.SetClaims("type", ImmutableArray.Create<string>());

        // Assert
        Assert.Empty(identity.GetClaims("type"));
    }

    [Fact]
    public void ClaimsPrincipal_SetClaimsWithArray_RemovesEmptyClaim()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.AddClaim("type", "value");

        // Act
        principal.SetClaims("type", ImmutableArray.Create<string>());

        // Assert
        Assert.Empty(principal.GetClaims("type"));
    }

    [Fact]
    public void ClaimsIdentity_SetClaimsWithJsonElement_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.SetClaims("type", default(JsonElement)));

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_SetClaimsWithJsonElement_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.SetClaims("type", default(JsonElement)));

        Assert.Equal("principal", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_SetClaimsWithJsonElement_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var principal = new ClaimsPrincipal();

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => principal.SetClaims("type",
            JsonSerializer.Deserialize<JsonElement>(@"[""Fabrikam"",""Contoso""]")));

        Assert.Equal("principal", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0286), exception.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsIdentity_SetClaimsWithJsonElement_ThrowsAnExceptionForNullOrEmptyType(string type)
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => identity.SetClaims(type, default(JsonElement)));

        Assert.Equal("type", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0184), exception.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsPrincipal_SetClaimsWithJsonElement_ThrowsAnExceptionForNullOrEmptyType(string type)
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => principal.SetClaims(type, default(JsonElement)));

        Assert.Equal("type", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0184), exception.Message);
    }

    [Fact]
    public void ClaimsIdentity_SetClaimsWithJsonElement_AddsExpectedClaims()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act
        identity.SetClaims("type", JsonSerializer.Deserialize<JsonElement>(@"[""Fabrikam"",""Contoso""]"), "issuer");

        // Assert
        var claims = identity.FindAll("type").ToArray();
        Assert.Equal("Fabrikam", claims[0].Value);
        Assert.Equal(ClaimValueTypes.String, claims[0].ValueType);
        Assert.Equal("issuer", claims[0].Issuer);
        Assert.Equal("Contoso", claims[1].Value);
        Assert.Equal(ClaimValueTypes.String, claims[1].ValueType);
        Assert.Equal("issuer", claims[1].Issuer);
    }

    [Fact]
    public void ClaimsPrincipal_SetClaimsWithJsonElement_AddsExpectedClaims()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act
        principal.SetClaims("type", JsonSerializer.Deserialize<JsonElement>(@"[""Fabrikam"",""Contoso""]"), "issuer");

        // Assert
        var claims = principal.FindAll("type").ToArray();
        Assert.Equal(2, claims.Length);
        Assert.Equal("Fabrikam", claims[0].Value);
        Assert.Equal(ClaimValueTypes.String, claims[0].ValueType);
        Assert.Equal("issuer", claims[0].Issuer);
        Assert.Equal("Contoso", claims[1].Value);
        Assert.Equal(ClaimValueTypes.String, claims[1].ValueType);
        Assert.Equal("issuer", claims[1].Issuer);
    }

    [Fact]
    public void ClaimsIdentity_SetClaimsWithJsonElement_IsCaseInsensitive()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act
        identity.SetClaims("TYPE", JsonSerializer.Deserialize<JsonElement>(@"[""Fabrikam"",""Contoso""]"));

        // Assert
        Assert.Equal<string>(ImmutableArray.Create("Fabrikam", "Contoso"), identity.GetClaims("type"));
    }

    [Fact]
    public void ClaimsPrincipal_SetClaimsWithJsonElement_IsCaseInsensitive()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act
        principal.SetClaims("TYPE", JsonSerializer.Deserialize<JsonElement>(@"[""Fabrikam"",""Contoso""]"));

        // Assert
        Assert.Equal<string>(ImmutableArray.Create("Fabrikam", "Contoso"), principal.GetClaims("type"));
    }

    [Fact]
    public void ClaimsIdentity_SetClaimsWithJsonElement_RemovesEmptyClaim()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.AddClaim("type", "value");

        // Act
        identity.SetClaims("type", JsonSerializer.Deserialize<JsonElement>("[]"));

        // Assert
        Assert.Empty(identity.GetClaims("type"));
    }

    [Fact]
    public void ClaimsPrincipal_SetClaimsWithJsonElement_RemovesEmptyClaim()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.AddClaim("type", "value");

        // Act
        principal.SetClaims("type", JsonSerializer.Deserialize<JsonElement>("[]"));

        // Assert
        Assert.Empty(principal.GetClaims("type"));
    }

    [Fact]
    public void ClaimsIdentity_SetClaimsWithJsonElement_Undefined()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act
        identity.SetClaims("type", default(JsonElement));

        // Assert
        Assert.Null(identity.GetClaim("type"));
    }

    [Fact]
    public void ClaimsPrincipal_SetClaimsWithJsonElement_Undefined()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.AddClaim("type", "value");

        // Act
        principal.SetClaims("type", default(JsonElement));

        // Assert
        Assert.Null(principal.GetClaim("type"));
    }

    [Fact]
    public void ClaimsIdentity_SetClaimsWithJsonElement_Null()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act
        identity.SetClaims("type", JsonSerializer.Deserialize<JsonElement>("null"));

        // Assert
        Assert.Null(identity.GetClaim("type"));
    }

    [Fact]
    public void ClaimsPrincipal_SetClaimsWithJsonElement_Null()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.AddClaim("type", "value");

        // Act
        principal.SetClaims("type", JsonSerializer.Deserialize<JsonElement>("null"));

        // Assert
        Assert.Null(principal.GetClaim("type"));
    }

    [Fact]
    public void ClaimsIdentity_GetCreationDate_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.GetCreationDate());

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_GetCreationDate_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.GetCreationDate());

        Assert.Equal("principal", exception.ParamName);
    }

    [Fact]
    public void ClaimsIdentity_GetCreationDate_ReturnsNullIfNoClaim()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act and assert
        Assert.Null(identity.GetCreationDate());
    }

    [Fact]
    public void ClaimsPrincipal_GetCreationDate_ReturnsNullIfNoClaim()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act and assert
        Assert.Null(principal.GetCreationDate());
    }

    [Fact]
    public void ClaimsIdentity_GetCreationDate_ReturnsCreationDate()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.SetClaim(Claims.Private.CreationDate, "Wed, 01 Jan 2020 04:30:30 GMT");

        // Act
        var date = identity.GetCreationDate();

        // Assert
        Assert.Equal(new DateTimeOffset(2020, 01, 01, 05, 30, 30, TimeSpan.FromHours(1)), date);
    }

    [Fact]
    public void ClaimsPrincipal_GetCreationDate_ReturnsCreationDate()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.SetClaim(Claims.Private.CreationDate, "Wed, 01 Jan 2020 04:30:30 GMT");

        // Act
        var date = principal.GetCreationDate();

        // Assert
        Assert.Equal(new DateTimeOffset(2020, 01, 01, 05, 30, 30, TimeSpan.FromHours(1)), date);
    }

    [Fact]
    public void ClaimsIdentity_GetExpirationDate_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.GetExpirationDate());

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_GetExpirationDate_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.GetExpirationDate());

        Assert.Equal("principal", exception.ParamName);
    }

    [Fact]
    public void ClaimsIdentity_GetExpirationDate_ReturnsNullIfNoClaim()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act and assert
        Assert.Null(identity.GetExpirationDate());
    }

    [Fact]
    public void ClaimsPrincipal_GetExpirationDate_ReturnsNullIfNoClaim()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act and assert
        Assert.Null(principal.GetExpirationDate());
    }

    [Fact]
    public void ClaimsIdentity_GetExpirationDate_ReturnsExpirationDate()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.SetClaim(Claims.Private.ExpirationDate, "Wed, 01 Jan 2020 04:30:30 GMT");

        // Act
        var date = identity.GetExpirationDate();

        // Assert
        Assert.Equal(new DateTimeOffset(2020, 01, 01, 05, 30, 30, TimeSpan.FromHours(1)), date);
    }

    [Fact]
    public void ClaimsPrincipal_GetExpirationDate_ReturnsExpirationDate()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.SetClaim(Claims.Private.ExpirationDate, "Wed, 01 Jan 2020 04:30:30 GMT");

        // Act
        var date = principal.GetExpirationDate();

        // Assert
        Assert.Equal(new DateTimeOffset(2020, 01, 01, 05, 30, 30, TimeSpan.FromHours(1)), date);
    }

    [Fact]
    public void ClaimsIdentity_GetAudiences_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.GetAudiences());

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsIdentity_GetAudiences_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.GetAudiences());

        Assert.Equal("principal", exception.ParamName);
    }

    [Theory]
    [InlineData(new string[0], new string[0])]
    [InlineData(new[] { "fabrikam" }, new[] { "fabrikam" })]
    [InlineData(new[] { "fabrikam", "contoso" }, new[] { "fabrikam", "contoso" })]
    [InlineData(new[] { "fabrikam", "fabrikam", "contoso" }, new[] { "fabrikam", "contoso" })]
    [InlineData(new[] { "fabrikam", "FABRIKAM", "contoso" }, new[] { "fabrikam", "FABRIKAM", "contoso" })]
    public void ClaimsIdentity_GetAudiences_ReturnsExpectedAudiences(string[] audience, string[] audiences)
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.SetClaims(Claims.Private.Audience, audience.ToImmutableArray());

        // Act and assert
        Assert.Equal(audiences, identity.GetAudiences());
    }

    [Theory]
    [InlineData(new string[0], new string[0])]
    [InlineData(new[] { "fabrikam" }, new[] { "fabrikam" })]
    [InlineData(new[] { "fabrikam", "contoso" }, new[] { "fabrikam", "contoso" })]
    [InlineData(new[] { "fabrikam", "fabrikam", "contoso" }, new[] { "fabrikam", "contoso" })]
    [InlineData(new[] { "fabrikam", "FABRIKAM", "contoso" }, new[] { "fabrikam", "FABRIKAM", "contoso" })]
    public void ClaimsPrincipal_GetAudiences_ReturnsExpectedAudiences(string[] audience, string[] audiences)
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.SetClaims(Claims.Private.Audience, audience.ToImmutableArray());

        // Act and assert
        Assert.Equal(audiences, principal.GetAudiences());
    }

    [Fact]
    public void ClaimsIdentity_GetPresenters_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.GetPresenters());

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_GetPresenters_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.GetPresenters());

        Assert.Equal("principal", exception.ParamName);
    }

    [Theory]
    [InlineData(new string[0], new string[0])]
    [InlineData(new[] { "fabrikam" }, new[] { "fabrikam" })]
    [InlineData(new[] { "fabrikam", "contoso" }, new[] { "fabrikam", "contoso" })]
    [InlineData(new[] { "fabrikam", "fabrikam", "contoso" }, new[] { "fabrikam", "contoso" })]
    [InlineData(new[] { "fabrikam", "FABRIKAM", "contoso" }, new[] { "fabrikam", "FABRIKAM", "contoso" })]
    public void ClaimsIdentity_GetPresenters_ReturnsExpectedPresenters(string[] presenter, string[] presenters)
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.SetClaims(Claims.Private.Presenter, presenter.ToImmutableArray());

        // Act and assert
        Assert.Equal(presenters, identity.GetPresenters());
    }

    [Theory]
    [InlineData(new string[0], new string[0])]
    [InlineData(new[] { "fabrikam" }, new[] { "fabrikam" })]
    [InlineData(new[] { "fabrikam", "contoso" }, new[] { "fabrikam", "contoso" })]
    [InlineData(new[] { "fabrikam", "fabrikam", "contoso" }, new[] { "fabrikam", "contoso" })]
    [InlineData(new[] { "fabrikam", "FABRIKAM", "contoso" }, new[] { "fabrikam", "FABRIKAM", "contoso" })]
    public void ClaimsPrincipal_GetPresenters_ReturnsExpectedPresenters(string[] presenter, string[] presenters)
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.SetClaims(Claims.Private.Presenter, presenter.ToImmutableArray());

        // Act and assert
        Assert.Equal(presenters, principal.GetPresenters());
    }

    [Fact]
    public void ClaimsIdentity_GetResources_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.GetResources());

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_GetResources_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.GetResources());

        Assert.Equal("principal", exception.ParamName);
    }

    [Theory]
    [InlineData(new string[0], new string[0])]
    [InlineData(new[] { "fabrikam" }, new[] { "fabrikam" })]
    [InlineData(new[] { "fabrikam", "contoso" }, new[] { "fabrikam", "contoso" })]
    [InlineData(new[] { "fabrikam", "fabrikam", "contoso" }, new[] { "fabrikam", "contoso" })]
    [InlineData(new[] { "fabrikam", "FABRIKAM", "contoso" }, new[] { "fabrikam", "FABRIKAM", "contoso" })]
    public void ClaimsIdentity_GetResources_ReturnsExpectedResources(string[] resource, string[] resources)
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.SetClaims(Claims.Private.Resource, resource.ToImmutableArray());

        // Act and assert
        Assert.Equal(resources, identity.GetResources());
    }

    [Theory]
    [InlineData(new string[0], new string[0])]
    [InlineData(new[] { "fabrikam" }, new[] { "fabrikam" })]
    [InlineData(new[] { "fabrikam", "contoso" }, new[] { "fabrikam", "contoso" })]
    [InlineData(new[] { "fabrikam", "fabrikam", "contoso" }, new[] { "fabrikam", "contoso" })]
    [InlineData(new[] { "fabrikam", "FABRIKAM", "contoso" }, new[] { "fabrikam", "FABRIKAM", "contoso" })]
    public void ClaimsPrincipal_GetResources_ReturnsExpectedResources(string[] resource, string[] resources)
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.SetClaims(Claims.Private.Resource, resource.ToImmutableArray());

        // Act and assert
        Assert.Equal(resources, principal.GetResources());
    }

    [Fact]
    public void ClaimsIdentity_GetScopes_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.GetScopes());

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_GetScopes_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.GetScopes());

        Assert.Equal("principal", exception.ParamName);
    }

    [Theory]
    [InlineData(new string[0], new string[0])]
    [InlineData(new[] { "openid" }, new[] { "openid" })]
    [InlineData(new[] { "openid", "profile" }, new[] { "openid", "profile" })]
    [InlineData(new[] { "openid", "openid", "profile" }, new[] { "openid", "profile" })]
    [InlineData(new[] { "openid", "OPENID", "profile" }, new[] { "openid", "OPENID", "profile" })]
    public void ClaimsIdentity_GetScopes_ReturnsExpectedScopes(string[] scope, string[] scopes)
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.SetClaims(Claims.Private.Scope, scope.ToImmutableArray());

        // Act and assert
        Assert.Equal(scopes, identity.GetScopes());
    }

    [Theory]
    [InlineData(new string[0], new string[0])]
    [InlineData(new[] { "openid" }, new[] { "openid" })]
    [InlineData(new[] { "openid", "profile" }, new[] { "openid", "profile" })]
    [InlineData(new[] { "openid", "openid", "profile" }, new[] { "openid", "profile" })]
    [InlineData(new[] { "openid", "OPENID", "profile" }, new[] { "openid", "OPENID", "profile" })]
    public void ClaimsPrincipal_GetScopes_ReturnsExpectedScopes(string[] scope, string[] scopes)
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.SetClaims(Claims.Private.Scope, scope.ToImmutableArray());

        // Act and assert
        Assert.Equal(scopes, principal.GetScopes());
    }

    [Fact]
    public void ClaimsIdentity_GetAccessTokenLifetime_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.GetAccessTokenLifetime());

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_GetAccessTokenLifetime_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.GetAccessTokenLifetime());

        Assert.Equal("principal", exception.ParamName);
    }

    [Fact]
    public void ClaimsIdentity_GetAccessTokenLifetime_ReturnsNullForMissingClaim()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act and assert
        Assert.Null(identity.GetAccessTokenLifetime());
    }

    [Fact]
    public void ClaimsPrincipal_GetAccessTokenLifetime_ReturnsNullForMissingClaim()
    {
        // Arrange
        var principal = new ClaimsIdentity(new ClaimsIdentity());

        // Act and assert
        Assert.Null(principal.GetAccessTokenLifetime());
    }

    [Fact]
    public void ClaimsIdentity_GetAccessTokenLifetime_ReturnsExpectedResult()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.SetClaim(Claims.Private.AccessTokenLifetime, "2520");

        // Act and assert
        Assert.Equal(TimeSpan.FromMinutes(42), identity.GetAccessTokenLifetime());
    }

    [Fact]
    public void ClaimsPrincipal_GetAccessTokenLifetime_ReturnsExpectedResult()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.SetClaim(Claims.Private.AccessTokenLifetime, "2520");

        // Act and assert
        Assert.Equal(TimeSpan.FromMinutes(42), principal.GetAccessTokenLifetime());
    }

    [Fact]
    public void ClaimsIdentity_GetAuthorizationCodeLifetime_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.GetAuthorizationCodeLifetime());

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_GetAuthorizationCodeLifetime_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.GetAuthorizationCodeLifetime());

        Assert.Equal("principal", exception.ParamName);
    }

    [Fact]
    public void ClaimsIdentity_GetAuthorizationCodeLifetime_ReturnsNullForMissingClaim()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act and assert
        Assert.Null(identity.GetAuthorizationCodeLifetime());
    }

    [Fact]
    public void ClaimsPrincipal_GetAuthorizationCodeLifetime_ReturnsNullForMissingClaim()
    {
        // Arrange
        var principal = new ClaimsIdentity(new ClaimsIdentity());

        // Act and assert
        Assert.Null(principal.GetAuthorizationCodeLifetime());
    }

    [Fact]
    public void ClaimsIdentity_GetAuthorizationCodeLifetime_ReturnsExpectedResult()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.SetClaim(Claims.Private.AuthorizationCodeLifetime, "2520");

        // Act and assert
        Assert.Equal(TimeSpan.FromMinutes(42), identity.GetAuthorizationCodeLifetime());
    }

    [Fact]
    public void ClaimsPrincipal_GetAuthorizationCodeLifetime_ReturnsExpectedResult()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.SetClaim(Claims.Private.AuthorizationCodeLifetime, "2520");

        // Act and assert
        Assert.Equal(TimeSpan.FromMinutes(42), principal.GetAuthorizationCodeLifetime());
    }

    [Fact]
    public void ClaimsIdentity_GetDeviceCodeLifetime_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.GetDeviceCodeLifetime());

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_GetDeviceCodeLifetime_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.GetDeviceCodeLifetime());

        Assert.Equal("principal", exception.ParamName);
    }

    [Fact]
    public void ClaimsIdentity_GetDeviceCodeLifetime_ReturnsNullForMissingClaim()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act and assert
        Assert.Null(identity.GetDeviceCodeLifetime());
    }

    [Fact]
    public void ClaimsPrincipal_GetDeviceCodeLifetime_ReturnsNullForMissingClaim()
    {
        // Arrange
        var principal = new ClaimsIdentity(new ClaimsIdentity());

        // Act and assert
        Assert.Null(principal.GetDeviceCodeLifetime());
    }

    [Fact]
    public void ClaimsIdentity_GetDeviceCodeLifetime_ReturnsExpectedResult()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.SetClaim(Claims.Private.DeviceCodeLifetime, "2520");

        // Act and assert
        Assert.Equal(TimeSpan.FromMinutes(42), identity.GetDeviceCodeLifetime());
    }

    [Fact]
    public void ClaimsPrincipal_GetDeviceCodeLifetime_ReturnsExpectedResult()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.SetClaim(Claims.Private.DeviceCodeLifetime, "2520");

        // Act and assert
        Assert.Equal(TimeSpan.FromMinutes(42), principal.GetDeviceCodeLifetime());
    }

    [Fact]
    public void ClaimsIdentity_GetIdentityTokenLifetime_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.GetIdentityTokenLifetime());

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_GetIdentityTokenLifetime_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.GetIdentityTokenLifetime());

        Assert.Equal("principal", exception.ParamName);
    }

    [Fact]
    public void ClaimsIdentity_GetIdentityTokenLifetime_ReturnsNullForMissingClaim()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act and assert
        Assert.Null(identity.GetIdentityTokenLifetime());
    }

    [Fact]
    public void ClaimsPrincipal_GetIdentityTokenLifetime_ReturnsNullForMissingClaim()
    {
        // Arrange
        var principal = new ClaimsIdentity(new ClaimsIdentity());

        // Act and assert
        Assert.Null(principal.GetIdentityTokenLifetime());
    }

    [Fact]
    public void ClaimsIdentity_GetIdentityTokenLifetime_ReturnsExpectedResult()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.SetClaim(Claims.Private.IdentityTokenLifetime, "2520");

        // Act and assert
        Assert.Equal(TimeSpan.FromMinutes(42), identity.GetIdentityTokenLifetime());
    }

    [Fact]
    public void ClaimsPrincipal_GetIdentityTokenLifetime_ReturnsExpectedResult()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.SetClaim(Claims.Private.IdentityTokenLifetime, "2520");

        // Act and assert
        Assert.Equal(TimeSpan.FromMinutes(42), principal.GetIdentityTokenLifetime());
    }

    [Fact]
    public void ClaimsIdentity_GetRefreshTokenLifetime_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.GetRefreshTokenLifetime());

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_GetRefreshTokenLifetime_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.GetRefreshTokenLifetime());

        Assert.Equal("principal", exception.ParamName);
    }

    [Fact]
    public void ClaimsIdentity_GetRefreshTokenLifetime_ReturnsNullForMissingClaim()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act and assert
        Assert.Null(identity.GetRefreshTokenLifetime());
    }

    [Fact]
    public void ClaimsPrincipal_GetRefreshTokenLifetime_ReturnsNullForMissingClaim()
    {
        // Arrange
        var principal = new ClaimsIdentity(new ClaimsIdentity());

        // Act and assert
        Assert.Null(principal.GetRefreshTokenLifetime());
    }

    [Fact]
    public void ClaimsIdentity_GetRefreshTokenLifetime_ReturnsExpectedResult()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.SetClaim(Claims.Private.RefreshTokenLifetime, "2520");

        // Act and assert
        Assert.Equal(TimeSpan.FromMinutes(42), identity.GetRefreshTokenLifetime());
    }

    [Fact]
    public void ClaimsPrincipal_GetRefreshTokenLifetime_ReturnsExpectedResult()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.SetClaim(Claims.Private.RefreshTokenLifetime, "2520");

        // Act and assert
        Assert.Equal(TimeSpan.FromMinutes(42), principal.GetRefreshTokenLifetime());
    }

    [Fact]
    public void ClaimsIdentity_GetStateTokenLifetime_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.GetStateTokenLifetime());

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_GetStateTokenLifetime_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.GetStateTokenLifetime());

        Assert.Equal("principal", exception.ParamName);
    }

    [Fact]
    public void ClaimsIdentity_GetStateTokenLifetime_ReturnsNullForMissingClaim()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act and assert
        Assert.Null(identity.GetStateTokenLifetime());
    }

    [Fact]
    public void ClaimsPrincipal_GetStateTokenLifetime_ReturnsNullForMissingClaim()
    {
        // Arrange
        var principal = new ClaimsIdentity(new ClaimsIdentity());

        // Act and assert
        Assert.Null(principal.GetStateTokenLifetime());
    }

    [Fact]
    public void ClaimsIdentity_GetStateTokenLifetime_ReturnsExpectedResult()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.SetClaim(Claims.Private.StateTokenLifetime, "2520");

        // Act and assert
        Assert.Equal(TimeSpan.FromMinutes(42), identity.GetStateTokenLifetime());
    }

    [Fact]
    public void ClaimsPrincipal_GetStateTokenLifetime_ReturnsExpectedResult()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.SetClaim(Claims.Private.StateTokenLifetime, "2520");

        // Act and assert
        Assert.Equal(TimeSpan.FromMinutes(42), principal.GetStateTokenLifetime());
    }

    [Fact]
    public void ClaimsIdentity_GetUserCodeLifetime_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.GetUserCodeLifetime());

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_GetUserCodeLifetime_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.GetUserCodeLifetime());

        Assert.Equal("principal", exception.ParamName);
    }

    [Fact]
    public void ClaimsIdentity_GetUserCodeLifetime_ReturnsNullForMissingClaim()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act and assert
        Assert.Null(identity.GetUserCodeLifetime());
    }

    [Fact]
    public void ClaimsPrincipal_GetUserCodeLifetime_ReturnsNullForMissingClaim()
    {
        // Arrange
        var principal = new ClaimsIdentity(new ClaimsIdentity());

        // Act and assert
        Assert.Null(principal.GetUserCodeLifetime());
    }

    [Fact]
    public void ClaimsIdentity_GetUserCodeLifetime_ReturnsExpectedResult()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.SetClaim(Claims.Private.UserCodeLifetime, "2520");

        // Act and assert
        Assert.Equal(TimeSpan.FromMinutes(42), identity.GetUserCodeLifetime());
    }

    [Fact]
    public void ClaimsPrincipal_GetUserCodeLifetime_ReturnsExpectedResult()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.SetClaim(Claims.Private.UserCodeLifetime, "2520");

        // Act and assert
        Assert.Equal(TimeSpan.FromMinutes(42), principal.GetUserCodeLifetime());
    }

    [Fact]
    public void ClaimsIdentity_GetAuthorizationId_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(identity.GetAuthorizationId);

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_GetAuthorizationId_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(principal.GetAuthorizationId);

        Assert.Equal("principal", exception.ParamName);
    }

    [Fact]
    public void ClaimsIdentity_GetAuthorizationId_ReturnsNullForMissingClaim()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act and assert
        Assert.Null(identity.GetAuthorizationId());
    }

    [Fact]
    public void ClaimsPrincipal_GetAuthorizationId_ReturnsNullForMissingClaim()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act and assert
        Assert.Null(principal.GetAuthorizationId());
    }

    [Fact]
    public void ClaimsIdentity_GetAuthorizationId_ReturnsExpectedResult()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.SetClaim(Claims.Private.AuthorizationId, "42");

        // Act and assert
        Assert.Equal("42", identity.GetAuthorizationId());
    }

    [Fact]
    public void ClaimsPrincipal_GetAuthorizationId_ReturnsExpectedResult()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.SetClaim(Claims.Private.AuthorizationId, "42");

        // Act and assert
        Assert.Equal("42", principal.GetAuthorizationId());
    }

    [Fact]
    public void ClaimsIdentity_HasAudience_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.HasAudience("Fabrikam"));

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_HasAudience_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.HasAudience("Fabrikam"));

        Assert.Equal("principal", exception.ParamName);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsIdentity_HasAudience_ThrowsAnExceptionForNullOrEmptyAudience(string audience)
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => identity.HasAudience(audience));

        Assert.Equal("audience", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0186), exception.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsPrincipal_HasAudience_ThrowsAnExceptionForNullOrEmptyAudience(string audience)
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => principal.HasAudience(audience));

        Assert.Equal("audience", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0186), exception.Message);
    }

    [Theory]
    [InlineData(new string[0], false)]
    [InlineData(new[] { "contoso" }, false)]
    [InlineData(new[] { "contoso", "fabrikam" }, true)]
    [InlineData(new[] { "fabrikam" }, true)]
    [InlineData(new[] { "fabrikam", "contoso" }, true)]
    [InlineData(new[] { "CONTOSO" }, false)]
    [InlineData(new[] { "CONTOSO", "FABRIKAM" }, false)]
    [InlineData(new[] { "FABRIKAM" }, false)]
    [InlineData(new[] { "FABRIKAM", "CONTOSO" }, false)]
    public void ClaimsIdentity_HasAudience_ReturnsExpectedResult(string[] audience, bool result)
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.SetClaims(Claims.Private.Audience, audience.ToImmutableArray());

        // Act and assert
        Assert.Equal(result, identity.HasAudience("fabrikam"));
    }

    [Theory]
    [InlineData(new string[0], false)]
    [InlineData(new[] { "contoso" }, false)]
    [InlineData(new[] { "contoso", "fabrikam" }, true)]
    [InlineData(new[] { "fabrikam" }, true)]
    [InlineData(new[] { "fabrikam", "contoso" }, true)]
    [InlineData(new[] { "CONTOSO" }, false)]
    [InlineData(new[] { "CONTOSO", "FABRIKAM" }, false)]
    [InlineData(new[] { "FABRIKAM" }, false)]
    [InlineData(new[] { "FABRIKAM", "CONTOSO" }, false)]
    public void ClaimsPrincipal_HasAudience_ReturnsExpectedResult(string[] audience, bool result)
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.SetClaims(Claims.Private.Audience, audience.ToImmutableArray());

        // Act and assert
        Assert.Equal(result, principal.HasAudience("fabrikam"));
    }

    [Fact]
    public void ClaimsIdentity_HasPresenter_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.HasPresenter("Fabrikam"));

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_HasPresenter_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.HasPresenter("Fabrikam"));

        Assert.Equal("principal", exception.ParamName);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsIdentity_HasPresenter_ThrowsAnExceptionForNullOrEmptyPresenter(string presenter)
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => identity.HasPresenter(presenter));

        Assert.Equal("presenter", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0187), exception.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsPrincipal_HasPresenter_ThrowsAnExceptionForNullOrEmptyPresenter(string presenter)
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => principal.HasPresenter(presenter));

        Assert.Equal("presenter", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0187), exception.Message);
    }

    [Theory]
    [InlineData(new string[0], false)]
    [InlineData(new[] { "contoso" }, false)]
    [InlineData(new[] { "contoso", "fabrikam" }, true)]
    [InlineData(new[] { "fabrikam" }, true)]
    [InlineData(new[] { "fabrikam", "contoso" }, true)]
    [InlineData(new[] { "CONTOSO" }, false)]
    [InlineData(new[] { "CONTOSO", "FABRIKAM" }, false)]
    [InlineData(new[] { "FABRIKAM" }, false)]
    [InlineData(new[] { "FABRIKAM", "CONTOSO" }, false)]
    public void ClaimsIdentity_HasPresenter_ReturnsExpectedResult(string[] presenter, bool result)
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.SetClaims(Claims.Private.Presenter, presenter.ToImmutableArray());

        // Act and assert
        Assert.Equal(result, identity.HasPresenter("fabrikam"));
    }

    [Theory]
    [InlineData(new string[0], false)]
    [InlineData(new[] { "contoso" }, false)]
    [InlineData(new[] { "contoso", "fabrikam" }, true)]
    [InlineData(new[] { "fabrikam" }, true)]
    [InlineData(new[] { "fabrikam", "contoso" }, true)]
    [InlineData(new[] { "CONTOSO" }, false)]
    [InlineData(new[] { "CONTOSO", "FABRIKAM" }, false)]
    [InlineData(new[] { "FABRIKAM" }, false)]
    [InlineData(new[] { "FABRIKAM", "CONTOSO" }, false)]
    public void ClaimsPrincipal_HasPresenter_ReturnsExpectedResult(string[] presenter, bool result)
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.SetClaims(Claims.Private.Presenter, presenter.ToImmutableArray());

        // Act and assert
        Assert.Equal(result, principal.HasPresenter("fabrikam"));
    }

    [Fact]
    public void ClaimsIdentity_HasResource_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.HasResource("Fabrikam"));

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_HasResource_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.HasResource("Fabrikam"));

        Assert.Equal("principal", exception.ParamName);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsIdentity_HasResource_ThrowsAnExceptionForNullOrEmptyResource(string resource)
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => identity.HasResource(resource));

        Assert.Equal("resource", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0062), exception.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsPrincipal_HasResource_ThrowsAnExceptionForNullOrEmptyResource(string resource)
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => principal.HasResource(resource));

        Assert.Equal("resource", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0062), exception.Message);
    }

    [Theory]
    [InlineData(new string[0], false)]
    [InlineData(new[] { "contoso" }, false)]
    [InlineData(new[] { "contoso", "fabrikam" }, true)]
    [InlineData(new[] { "fabrikam" }, true)]
    [InlineData(new[] { "fabrikam", "contoso" }, true)]
    [InlineData(new[] { "CONTOSO" }, false)]
    [InlineData(new[] { "CONTOSO", "FABRIKAM" }, false)]
    [InlineData(new[] { "FABRIKAM" }, false)]
    [InlineData(new[] { "FABRIKAM", "CONTOSO" }, false)]
    public void ClaimsIdentity_HasResource_ReturnsExpectedResult(string[] resource, bool result)
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.SetClaims(Claims.Private.Resource, resource.ToImmutableArray());

        // Act and assert
        Assert.Equal(result, identity.HasResource("fabrikam"));
    }

    [Theory]
    [InlineData(new string[0], false)]
    [InlineData(new[] { "contoso" }, false)]
    [InlineData(new[] { "contoso", "fabrikam" }, true)]
    [InlineData(new[] { "fabrikam" }, true)]
    [InlineData(new[] { "fabrikam", "contoso" }, true)]
    [InlineData(new[] { "CONTOSO" }, false)]
    [InlineData(new[] { "CONTOSO", "FABRIKAM" }, false)]
    [InlineData(new[] { "FABRIKAM" }, false)]
    [InlineData(new[] { "FABRIKAM", "CONTOSO" }, false)]
    public void ClaimsPrincipal_HasResource_ReturnsExpectedResult(string[] resource, bool result)
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.SetClaims(Claims.Private.Resource, resource.ToImmutableArray());

        // Act and assert
        Assert.Equal(result, principal.HasResource("fabrikam"));
    }

    [Fact]
    public void ClaimsIdentity_HasScope_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.HasScope(Scopes.Profile));

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_HasScope_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.HasScope(Scopes.Profile));

        Assert.Equal("principal", exception.ParamName);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsIdentity_HasScope_ThrowsAnExceptionForNullOrEmptyScope(string scope)
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => identity.HasScope(scope));

        Assert.Equal("scope", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0180), exception.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsPrincipal_HasScope_ThrowsAnExceptionForNullOrEmptyScope(string scope)
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => principal.HasScope(scope));

        Assert.Equal("scope", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0180), exception.Message);
    }

    [Theory]
    [InlineData(new string[0], false)]
    [InlineData(new[] { "profile" }, false)]
    [InlineData(new[] { "profile", "openid" }, true)]
    [InlineData(new[] { "openid" }, true)]
    [InlineData(new[] { "openid", "profile" }, true)]
    [InlineData(new[] { "PROFILE" }, false)]
    [InlineData(new[] { "PROFILE", "OPENID" }, false)]
    [InlineData(new[] { "OPENID" }, false)]
    [InlineData(new[] { "OPENID", "PROFILE" }, false)]
    public void ClaimsIdentity_HasScope_ReturnsExpectedResult(string[] scope, bool result)
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.SetClaims(Claims.Private.Scope, scope.ToImmutableArray());

        // Act and assert
        Assert.Equal(result, identity.HasScope(Scopes.OpenId));
    }

    [Theory]
    [InlineData(new string[0], false)]
    [InlineData(new[] { "profile" }, false)]
    [InlineData(new[] { "profile", "openid" }, true)]
    [InlineData(new[] { "openid" }, true)]
    [InlineData(new[] { "openid", "profile" }, true)]
    [InlineData(new[] { "PROFILE" }, false)]
    [InlineData(new[] { "PROFILE", "OPENID" }, false)]
    [InlineData(new[] { "OPENID" }, false)]
    [InlineData(new[] { "OPENID", "PROFILE" }, false)]
    public void ClaimsPrincipal_HasScope_ReturnsExpectedResult(string[] scope, bool result)
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.SetClaims(Claims.Private.Scope, scope.ToImmutableArray());

        // Act and assert
        Assert.Equal(result, principal.HasScope(Scopes.OpenId));
    }

    [Fact]
    public void ClaimsIdentity_HasTokenType_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.HasTokenType(TokenTypeHints.AccessToken));

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_HasTokenType_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.HasTokenType(TokenTypeHints.AccessToken));

        Assert.Equal("principal", exception.ParamName);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsIdentity_HasTokenType_ThrowsAnExceptionForNullOrEmptyTokenType(string type)
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => identity.HasTokenType(type));

        Assert.Equal("type", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0188), exception.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsPrincipal_HasTokenType_ThrowsAnExceptionForNullOrEmptyTokenType(string type)
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => principal.HasTokenType(type));

        Assert.Equal("type", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0188), exception.Message);
    }

    [Fact]
    public void ClaimsIdentity_HasTokenType_ReturnsExpectedResult()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.SetTokenType(TokenTypeHints.AccessToken);

        // Act and assert
        Assert.True(identity.HasTokenType(TokenTypeHints.AccessToken));
        Assert.False(identity.HasTokenType(TokenTypeHints.RefreshToken));
    }

    [Fact]
    public void ClaimsPrincipal_HasTokenType_ReturnsExpectedResult()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.SetTokenType(TokenTypeHints.AccessToken);

        // Act and assert
        Assert.True(principal.HasTokenType(TokenTypeHints.AccessToken));
        Assert.False(principal.HasTokenType(TokenTypeHints.RefreshToken));
    }

    [Fact]
    public void ClaimsIdentity_SetCreationDate_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.SetCreationDate(date: null));

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_SetCreationDate_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.SetCreationDate(date: null));

        Assert.Equal("principal", exception.ParamName);
    }

    [Fact]
    public void ClaimsIdentity_SetCreationDate_AddsClaim()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act
        identity.SetCreationDate(new DateTimeOffset(2020, 01, 01, 05, 30, 30, TimeSpan.FromHours(1)));

        // Assert
        Assert.Equal("Wed, 01 Jan 2020 04:30:30 GMT", identity.GetClaim(Claims.Private.CreationDate));
    }

    [Fact]
    public void ClaimsPrincipal_SetCreationDate_AddsClaim()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act
        principal.SetCreationDate(new DateTimeOffset(2020, 01, 01, 05, 30, 30, TimeSpan.FromHours(1)));

        // Assert
        Assert.Equal("Wed, 01 Jan 2020 04:30:30 GMT", principal.GetClaim(Claims.Private.CreationDate));
    }

    [Fact]
    public void ClaimsIdentity_SetExpirationDate_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.SetExpirationDate(date: null));

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_SetExpirationDate_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.SetExpirationDate(date: null));

        Assert.Equal("principal", exception.ParamName);
    }

    [Fact]
    public void ClaimsIdentity_SetExpirationDate_AddsClaim()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act
        identity.SetExpirationDate(new DateTimeOffset(2020, 01, 01, 05, 30, 30, TimeSpan.FromHours(1)));

        // Assert
        Assert.Equal("Wed, 01 Jan 2020 04:30:30 GMT", identity.GetClaim(Claims.Private.ExpirationDate));
    }

    [Fact]
    public void ClaimsPrincipal_SetExpirationDate_AddsClaim()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act
        principal.SetExpirationDate(new DateTimeOffset(2020, 01, 01, 05, 30, 30, TimeSpan.FromHours(1)));

        // Assert
        Assert.Equal("Wed, 01 Jan 2020 04:30:30 GMT", principal.GetClaim(Claims.Private.ExpirationDate));
    }

    [Fact]
    public void ClaimsIdentity_SetAudiences_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.SetAudiences());

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_SetAudiences_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.SetAudiences());

        Assert.Equal("principal", exception.ParamName);
    }

    [Theory]
    [InlineData(null, new string[0])]
    [InlineData(new string[0], new string[0])]
    [InlineData(new[] { "fabrikam" }, new[] { "fabrikam" })]
    [InlineData(new[] { "fabrikam", "contoso" }, new[] { "fabrikam", "contoso" })]
    [InlineData(new[] { "fabrikam", "fabrikam", "contoso" }, new[] { "fabrikam", "contoso" })]
    [InlineData(new[] { "fabrikam", "FABRIKAM", "contoso" }, new[] { "fabrikam", "FABRIKAM", "contoso" })]
    public void ClaimsIdentity_SetAudiences_AddsAudiences(string[] audiences, string[] audience)
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act
        identity.SetAudiences(audiences);

        // Assert
        Assert.Equal(audience, identity.GetClaims(Claims.Private.Audience));
    }

    [Theory]
    [InlineData(null, new string[0])]
    [InlineData(new string[0], new string[0])]
    [InlineData(new[] { "fabrikam" }, new[] { "fabrikam" })]
    [InlineData(new[] { "fabrikam", "contoso" }, new[] { "fabrikam", "contoso" })]
    [InlineData(new[] { "fabrikam", "fabrikam", "contoso" }, new[] { "fabrikam", "contoso" })]
    [InlineData(new[] { "fabrikam", "FABRIKAM", "contoso" }, new[] { "fabrikam", "FABRIKAM", "contoso" })]
    public void ClaimsPrincipal_SetAudiences_AddsAudiences(string[] audiences, string[] audience)
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act
        principal.SetAudiences(audiences);

        // Assert
        Assert.Equal(audience, principal.GetClaims(Claims.Private.Audience));
    }

    [Fact]
    public void ClaimsIdentity_SetPresenters_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.SetPresenters());

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_SetPresenters_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.SetPresenters());

        Assert.Equal("principal", exception.ParamName);
    }

    [Theory]
    [InlineData(null, new string[0])]
    [InlineData(new string[0], new string[0])]
    [InlineData(new[] { "fabrikam" }, new[] { "fabrikam" })]
    [InlineData(new[] { "fabrikam", "contoso" }, new[] { "fabrikam", "contoso" })]
    [InlineData(new[] { "fabrikam", "fabrikam", "contoso" }, new[] { "fabrikam", "contoso" })]
    [InlineData(new[] { "fabrikam", "FABRIKAM", "contoso" }, new[] { "fabrikam", "FABRIKAM", "contoso" })]
    public void ClaimsIdentity_SetPresenters_AddsPresenters(string[] presenters, string[] presenter)
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act
        identity.SetPresenters(presenters);

        // Assert
        Assert.Equal(presenter, identity.GetClaims(Claims.Private.Presenter));
    }

    [Theory]
    [InlineData(null, new string[0])]
    [InlineData(new string[0], new string[0])]
    [InlineData(new[] { "fabrikam" }, new[] { "fabrikam" })]
    [InlineData(new[] { "fabrikam", "contoso" }, new[] { "fabrikam", "contoso" })]
    [InlineData(new[] { "fabrikam", "fabrikam", "contoso" }, new[] { "fabrikam", "contoso" })]
    [InlineData(new[] { "fabrikam", "FABRIKAM", "contoso" }, new[] { "fabrikam", "FABRIKAM", "contoso" })]
    public void ClaimsPrincipal_SetPresenters_AddsPresenters(string[] presenters, string[] presenter)
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act
        principal.SetPresenters(presenters);

        // Assert
        Assert.Equal(presenter, principal.GetClaims(Claims.Private.Presenter));
    }

    [Fact]
    public void ClaimsIdentity_SetResources_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.SetResources());

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_SetResources_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.SetResources());

        Assert.Equal("principal", exception.ParamName);
    }

    [Theory]
    [InlineData(null, new string[0])]
    [InlineData(new string[0], new string[0])]
    [InlineData(new[] { "fabrikam" }, new[] { "fabrikam" })]
    [InlineData(new[] { "fabrikam", "contoso" }, new[] { "fabrikam", "contoso" })]
    [InlineData(new[] { "fabrikam", "fabrikam", "contoso" }, new[] { "fabrikam", "contoso" })]
    [InlineData(new[] { "fabrikam", "FABRIKAM", "contoso" }, new[] { "fabrikam", "FABRIKAM", "contoso" })]
    public void ClaimsIdentity_SetResources_AddsResources(string[] resources, string[] resource)
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act
        identity.SetResources(resources);

        // Assert
        Assert.Equal(resource, identity.GetClaims(Claims.Private.Resource));
    }

    [Theory]
    [InlineData(null, new string[0])]
    [InlineData(new string[0], new string[0])]
    [InlineData(new[] { "fabrikam" }, new[] { "fabrikam" })]
    [InlineData(new[] { "fabrikam", "contoso" }, new[] { "fabrikam", "contoso" })]
    [InlineData(new[] { "fabrikam", "fabrikam", "contoso" }, new[] { "fabrikam", "contoso" })]
    [InlineData(new[] { "fabrikam", "FABRIKAM", "contoso" }, new[] { "fabrikam", "FABRIKAM", "contoso" })]
    public void ClaimsPrincipal_SetResources_AddsResources(string[] resources, string[] resource)
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act
        principal.SetResources(resources);

        // Assert
        Assert.Equal(resource, principal.GetClaims(Claims.Private.Resource));
    }

    [Fact]
    public void ClaimsIdentity_SetScopes_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.SetScopes());

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_SetScopes_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.SetScopes());

        Assert.Equal("principal", exception.ParamName);
    }

    [Theory]
    [InlineData(null, new string[0])]
    [InlineData(new string[0], new string[0])]
    [InlineData(new[] { "openid" }, new[] { "openid" })]
    [InlineData(new[] { "openid", "profile" }, new[] { "openid", "profile" })]
    [InlineData(new[] { "openid", "openid", "profile" }, new[] { "openid", "profile" })]
    [InlineData(new[] { "openid", "OPENID", "profile" }, new[] { "openid", "OPENID", "profile" })]
    public void ClaimsIdentity_SetScopes_AddsScopes(string[] scopes, string[] scope)
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act
        identity.SetScopes(scopes);

        // Assert
        Assert.Equal(scope, identity.GetClaims(Claims.Private.Scope));
    }

    [Theory]
    [InlineData(null, new string[0])]
    [InlineData(new string[0], new string[0])]
    [InlineData(new[] { "openid" }, new[] { "openid" })]
    [InlineData(new[] { "openid", "profile" }, new[] { "openid", "profile" })]
    [InlineData(new[] { "openid", "openid", "profile" }, new[] { "openid", "profile" })]
    [InlineData(new[] { "openid", "OPENID", "profile" }, new[] { "openid", "OPENID", "profile" })]
    public void ClaimsPrincipal_SetScopes_AddsScopes(string[] scopes, string[] scope)
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act
        principal.SetScopes(scopes);

        // Assert
        Assert.Equal(scope, principal.GetClaims(Claims.Private.Scope));
    }

    [Fact]
    public void ClaimsIdentity_SetAccessTokenLifetime_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.SetAccessTokenLifetime(null));

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_SetAccessTokenLifetime_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.SetAccessTokenLifetime(null));

        Assert.Equal("principal", exception.ParamName);
    }

    [Fact]
    public void ClaimsIdentity_SetAccessTokenLifetime_RemovesClaimForNullValue()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.AddClaim(Claims.Private.AccessTokenLifetime, "2520");

        // Act
        identity.SetAccessTokenLifetime(null);

        // Assert
        Assert.Empty(identity.Claims);
    }

    [Fact]
    public void ClaimsPrincipal_SetAccessTokenLifetime_RemovesClaimForNullValue()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.AddClaim(Claims.Private.AccessTokenLifetime, "2520");

        // Act
        principal.SetAccessTokenLifetime(null);

        // Assert
        Assert.Empty(principal.Claims);
    }

    [Fact]
    public void ClaimsIdentity_SetAccessTokenLifetime_AddsClaim()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act
        identity.SetAccessTokenLifetime(TimeSpan.FromMinutes(42));

        // Assert
        Assert.Equal("2520", identity.GetClaim(Claims.Private.AccessTokenLifetime));
    }

    [Fact]
    public void ClaimsPrincipal_SetAccessTokenLifetime_AddsClaim()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act
        principal.SetAccessTokenLifetime(TimeSpan.FromMinutes(42));

        // Assert
        Assert.Equal("2520", principal.GetClaim(Claims.Private.AccessTokenLifetime));
    }

    [Fact]
    public void ClaimsIdentity_SetAuthorizationCodeLifetime_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.SetAuthorizationCodeLifetime(null));

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_SetAuthorizationCodeLifetime_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.SetAuthorizationCodeLifetime(null));

        Assert.Equal("principal", exception.ParamName);
    }

    [Fact]
    public void ClaimsIdentity_SetAuthorizationCodeLifetime_RemovesClaimForNullValue()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.AddClaim(Claims.Private.AuthorizationCodeLifetime, "2520");

        // Act
        identity.SetAuthorizationCodeLifetime(null);

        // Assert
        Assert.Empty(identity.Claims);
    }

    [Fact]
    public void ClaimsPrincipal_SetAuthorizationCodeLifetime_RemovesClaimForNullValue()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.AddClaim(Claims.Private.AuthorizationCodeLifetime, "2520");

        // Act
        principal.SetAuthorizationCodeLifetime(null);

        // Assert
        Assert.Empty(principal.Claims);
    }

    [Fact]
    public void ClaimsIdentity_SetAuthorizationCodeLifetime_AddsClaim()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act
        identity.SetAuthorizationCodeLifetime(TimeSpan.FromMinutes(42));

        // Assert
        Assert.Equal("2520", identity.GetClaim(Claims.Private.AuthorizationCodeLifetime));
    }

    [Fact]
    public void ClaimsPrincipal_SetAuthorizationCodeLifetime_AddsClaim()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act
        principal.SetAuthorizationCodeLifetime(TimeSpan.FromMinutes(42));

        // Assert
        Assert.Equal("2520", principal.GetClaim(Claims.Private.AuthorizationCodeLifetime));
    }

    [Fact]
    public void ClaimsIdentity_SetDeviceCodeLifetime_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.SetDeviceCodeLifetime(null));

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_SetDeviceCodeLifetime_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.SetDeviceCodeLifetime(null));

        Assert.Equal("principal", exception.ParamName);
    }

    [Fact]
    public void ClaimsIdentity_SetDeviceCodeLifetime_RemovesClaimForNullValue()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.AddClaim(Claims.Private.DeviceCodeLifetime, "2520");

        // Act
        identity.SetDeviceCodeLifetime(null);

        // Assert
        Assert.Empty(identity.Claims);
    }

    [Fact]
    public void ClaimsPrincipal_SetDeviceCodeLifetime_RemovesClaimForNullValue()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.AddClaim(Claims.Private.DeviceCodeLifetime, "2520");

        // Act
        principal.SetDeviceCodeLifetime(null);

        // Assert
        Assert.Empty(principal.Claims);
    }

    [Fact]
    public void ClaimsIdentity_SetDeviceCodeLifetime_AddsClaim()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act
        identity.SetDeviceCodeLifetime(TimeSpan.FromMinutes(42));

        // Assert
        Assert.Equal("2520", identity.GetClaim(Claims.Private.DeviceCodeLifetime));
    }

    [Fact]
    public void ClaimsPrincipal_SetDeviceCodeLifetime_AddsClaim()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act
        principal.SetDeviceCodeLifetime(TimeSpan.FromMinutes(42));

        // Assert
        Assert.Equal("2520", principal.GetClaim(Claims.Private.DeviceCodeLifetime));
    }

    [Fact]
    public void ClaimsIdentity_SetIdentityTokenLifetime_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.SetIdentityTokenLifetime(null));

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_SetIdentityTokenLifetime_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.SetIdentityTokenLifetime(null));

        Assert.Equal("principal", exception.ParamName);
    }

    [Fact]
    public void ClaimsIdentity_SetIdentityTokenLifetime_RemovesClaimForNullValue()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.AddClaim(Claims.Private.IdentityTokenLifetime, "2520");

        // Act
        identity.SetIdentityTokenLifetime(null);

        // Assert
        Assert.Empty(identity.Claims);
    }

    [Fact]
    public void ClaimsPrincipal_SetIdentityTokenLifetime_RemovesClaimForNullValue()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.AddClaim(Claims.Private.IdentityTokenLifetime, "2520");

        // Act
        principal.SetIdentityTokenLifetime(null);

        // Assert
        Assert.Empty(principal.Claims);
    }

    [Fact]
    public void ClaimsIdentity_SetIdentityTokenLifetime_AddsClaim()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act
        identity.SetIdentityTokenLifetime(TimeSpan.FromMinutes(42));

        // Assert
        Assert.Equal("2520", identity.GetClaim(Claims.Private.IdentityTokenLifetime));
    }

    [Fact]
    public void ClaimsPrincipal_SetIdentityTokenLifetime_AddsClaim()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act
        principal.SetIdentityTokenLifetime(TimeSpan.FromMinutes(42));

        // Assert
        Assert.Equal("2520", principal.GetClaim(Claims.Private.IdentityTokenLifetime));
    }

    [Fact]
    public void ClaimsIdentity_SetRefreshTokenLifetime_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.SetRefreshTokenLifetime(null));

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_SetRefreshTokenLifetime_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.SetRefreshTokenLifetime(null));

        Assert.Equal("principal", exception.ParamName);
    }

    [Fact]
    public void ClaimsIdentity_SetRefreshTokenLifetime_RemovesClaimForNullValue()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.AddClaim(Claims.Private.RefreshTokenLifetime, "2520");

        // Act
        identity.SetRefreshTokenLifetime(null);

        // Assert
        Assert.Empty(identity.Claims);
    }

    [Fact]
    public void ClaimsPrincipal_SetRefreshTokenLifetime_RemovesClaimForNullValue()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.AddClaim(Claims.Private.RefreshTokenLifetime, "2520");

        // Act
        principal.SetRefreshTokenLifetime(null);

        // Assert
        Assert.Empty(principal.Claims);
    }

    [Fact]
    public void ClaimsIdentity_SetRefreshTokenLifetime_AddsClaim()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act
        identity.SetRefreshTokenLifetime(TimeSpan.FromMinutes(42));

        // Assert
        Assert.Equal("2520", identity.GetClaim(Claims.Private.RefreshTokenLifetime));
    }

    [Fact]
    public void ClaimsPrincipal_SetRefreshTokenLifetime_AddsClaim()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act
        principal.SetRefreshTokenLifetime(TimeSpan.FromMinutes(42));

        // Assert
        Assert.Equal("2520", principal.GetClaim(Claims.Private.RefreshTokenLifetime));
    }

    [Fact]
    public void ClaimsIdentity_SetStateTokenLifetime_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.SetStateTokenLifetime(null));

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_SetStateTokenLifetime_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.SetStateTokenLifetime(null));

        Assert.Equal("principal", exception.ParamName);
    }

    [Fact]
    public void ClaimsIdentity_SetStateTokenLifetime_RemovesClaimForNullValue()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.AddClaim(Claims.Private.StateTokenLifetime, "2520");

        // Act
        identity.SetStateTokenLifetime(null);

        // Assert
        Assert.Empty(identity.Claims);
    }

    [Fact]
    public void ClaimsPrincipal_SetStateTokenLifetime_RemovesClaimForNullValue()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.AddClaim(Claims.Private.StateTokenLifetime, "2520");

        // Act
        principal.SetStateTokenLifetime(null);

        // Assert
        Assert.Empty(principal.Claims);
    }

    [Fact]
    public void ClaimsIdentity_SetStateTokenLifetime_AddsClaim()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act
        identity.SetStateTokenLifetime(TimeSpan.FromMinutes(42));

        // Assert
        Assert.Equal("2520", identity.GetClaim(Claims.Private.StateTokenLifetime));
    }

    [Fact]
    public void ClaimsPrincipal_SetStateTokenLifetime_AddsClaim()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act
        principal.SetStateTokenLifetime(TimeSpan.FromMinutes(42));

        // Assert
        Assert.Equal("2520", principal.GetClaim(Claims.Private.StateTokenLifetime));
    }

    [Fact]
    public void ClaimsIdentity_SetUserCodeLifetime_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.SetUserCodeLifetime(null));

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_SetUserCodeLifetime_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.SetUserCodeLifetime(null));

        Assert.Equal("principal", exception.ParamName);
    }

    [Fact]
    public void ClaimsIdentity_SetUserCodeLifetime_RemovesClaimForNullValue()
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.AddClaim(Claims.Private.UserCodeLifetime, "2520");

        // Act
        identity.SetUserCodeLifetime(null);

        // Assert
        Assert.Empty(identity.Claims);
    }

    [Fact]
    public void ClaimsPrincipal_SetUserCodeLifetime_RemovesClaimForNullValue()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.AddClaim(Claims.Private.UserCodeLifetime, "2520");

        // Act
        principal.SetUserCodeLifetime(null);

        // Assert
        Assert.Empty(principal.Claims);
    }

    [Fact]
    public void ClaimsIdentity_SetUserCodeLifetime_AddsClaim()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act
        identity.SetUserCodeLifetime(TimeSpan.FromMinutes(42));

        // Assert
        Assert.Equal("2520", identity.GetClaim(Claims.Private.UserCodeLifetime));
    }

    [Fact]
    public void ClaimsPrincipal_SetUserCodeLifetime_AddsClaim()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act
        principal.SetUserCodeLifetime(TimeSpan.FromMinutes(42));

        // Assert
        Assert.Equal("2520", principal.GetClaim(Claims.Private.UserCodeLifetime));
    }

    [Fact]
    public void ClaimsIdentity_SetAuthorizationId_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.SetAuthorizationId(null));

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_SetAuthorizationId_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.SetAuthorizationId(null));

        Assert.Equal("principal", exception.ParamName);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsIdentity_SetAuthorizationId_RemovesClaimForNullOrEmptyValue(string value)
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.AddClaim(Claims.Private.AuthorizationId, "2520");

        // Act
        identity.SetAuthorizationId(value);

        // Assert
        Assert.Empty(identity.Claims);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsPrincipal_SetAuthorizationId_RemovesClaimForNullOrEmptyValue(string value)
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.AddClaim(Claims.Private.AuthorizationId, "2520");

        // Act
        principal.SetAuthorizationId(value);

        // Assert
        Assert.Empty(principal.Claims);
    }

    [Fact]
    public void ClaimsIdentity_SetAuthorizationId_AddsClaim()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act
        identity.SetAuthorizationId("42");

        // Assert
        Assert.Equal("42", identity.GetClaim(Claims.Private.AuthorizationId));
    }

    [Fact]
    public void ClaimsPrincipal_SetAuthorizationId_AddsClaim()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act
        principal.SetAuthorizationId("42");

        // Assert
        Assert.Equal("42", principal.GetClaim(Claims.Private.AuthorizationId));
    }

    [Fact]
    public void ClaimsIdentity_SetTokenId_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.SetTokenId(null));

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_SetTokenId_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.SetTokenId(null));

        Assert.Equal("principal", exception.ParamName);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsIdentity_SetTokenId_RemovesClaimForNullOrEmptyValue(string value)
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.AddClaim(Claims.Private.TokenId, "2520");

        // Act
        identity.SetTokenId(value);

        // Assert
        Assert.Empty(identity.Claims);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsPrincipal_SetTokenId_RemovesClaimForNullOrEmptyValue(string value)
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.AddClaim(Claims.Private.TokenId, "2520");

        // Act
        principal.SetTokenId(value);

        // Assert
        Assert.Empty(principal.Claims);
    }

    [Fact]
    public void ClaimsIdentity_SetTokenId_AddsClaim()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act
        identity.SetTokenId("42");

        // Assert
        Assert.Equal("42", identity.GetClaim(Claims.Private.TokenId));
    }

    [Fact]
    public void ClaimsPrincipal_SetTokenId_AddsClaim()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act
        principal.SetTokenId("42");

        // Assert
        Assert.Equal("42", principal.GetClaim(Claims.Private.TokenId));
    }

    [Fact]
    public void ClaimsIdentity_SetTokenType_ThrowsAnExceptionForNullIdentity()
    {
        // Arrange
        var identity = (ClaimsIdentity) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => identity.SetTokenType(null));

        Assert.Equal("identity", exception.ParamName);
    }

    [Fact]
    public void ClaimsPrincipal_SetTokenType_ThrowsAnExceptionForNullPrincipal()
    {
        // Arrange
        var principal = (ClaimsPrincipal) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => principal.SetTokenType(null));

        Assert.Equal("principal", exception.ParamName);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsIdentity_SetTokenType_RemovesClaimForNullOrEmptyValue(string value)
    {
        // Arrange
        var identity = new ClaimsIdentity();
        identity.AddClaim(Claims.Private.TokenType, "2520");

        // Act
        identity.SetTokenType(value);

        // Assert
        Assert.Empty(identity.Claims);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ClaimsPrincipal_SetTokenType_RemovesClaimForNullOrEmptyValue(string value)
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        principal.AddClaim(Claims.Private.TokenType, "2520");

        // Act
        principal.SetTokenType(value);

        // Assert
        Assert.Empty(principal.Claims);
    }

    [Fact]
    public void ClaimsIdentity_SetTokenType_AddsClaim()
    {
        // Arrange
        var identity = new ClaimsIdentity();

        // Act
        identity.SetTokenType(TokenTypeHints.AccessToken);

        // Assert
        Assert.Equal(TokenTypeHints.AccessToken, identity.GetClaim(Claims.Private.TokenType));
    }

    [Fact]
    public void ClaimsPrincipal_SetTokenType_AddsClaim()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity());

        // Act
        principal.SetTokenType(TokenTypeHints.AccessToken);

        // Assert
        Assert.Equal(TokenTypeHints.AccessToken, principal.GetClaim(Claims.Private.TokenType));
    }
}
