/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Xunit;

namespace OpenIddict.Abstractions.Tests.Primitives
{
    public class OpenIddictMessageTests
    {
        [Fact]
        public void Constructor_ImportsParameters()
        {
            // Arrange and act
            var message = new OpenIddictMessage(new[]
            {
                new KeyValuePair<string, OpenIddictParameter>("parameter", 42)
            });

            // Assert
            Assert.Equal(42, (long) message.GetParameter("parameter"));
        }

        [Fact]
        public void Constructor_IgnoresNamelessParameters()
        {
            // Arrange and act
            var message = new OpenIddictMessage(new[]
            {
                new KeyValuePair<string, OpenIddictParameter>(null, new OpenIddictParameter()),
                new KeyValuePair<string, OpenIddictParameter>(string.Empty, new OpenIddictParameter())
            });

            // Assert
            Assert.Empty(message.GetParameters());
        }

        [Fact]
        public void Constructor_PreservesEmptyParameters()
        {
            // Arrange and act
            var message = new OpenIddictMessage(new[]
            {
                new KeyValuePair<string, OpenIddictParameter>("null-parameter", (string) null),
                new KeyValuePair<string, OpenIddictParameter>("empty-parameter", string.Empty)
            });

            // Assert
            Assert.Equal(2, message.GetParameters().Count());
        }

        [Fact]
        public void Constructor_IgnoresDuplicateParameters()
        {
            // Arrange and act
            var message = new OpenIddictMessage(new[]
            {
                new KeyValuePair<string, OpenIddictParameter>("parameter", "Fabrikam"),
                new KeyValuePair<string, OpenIddictParameter>("parameter", "Contoso")
            });

            // Assert
            Assert.Single(message.GetParameters());
            Assert.Equal("Fabrikam", message.GetParameter("parameter"));
        }

        [Fact]
        public void Constructor_SupportsMultiValuedParameters()
        {
            // Arrange and act
            var message = new OpenIddictMessage(new[]
            {
                new KeyValuePair<string, string[]>("parameter", new[] { "Fabrikam", "Contoso" })
            });

            // Assert
            Assert.Single(message.GetParameters());
            Assert.Equal(new[] { "Fabrikam", "Contoso" }, (string[]) message.GetParameter("parameter"));
        }

        [Fact]
        public void Constructor_ExtractsSingleValuedParameters()
        {
            // Arrange and act
            var message = new OpenIddictMessage(new[]
            {
                new KeyValuePair<string, string[]>("parameter", new[] { "Fabrikam" })
            });

            // Assert
            Assert.Single(message.GetParameters());
            Assert.Equal("Fabrikam", message.GetParameter("parameter")?.Value);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void AddParameter_ThrowsAnExceptionForNullOrEmptyName(string name)
        {
            // Arrange
            var message = new OpenIddictMessage();

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(() =>
            {
                message.AddParameter(name, new OpenIddictParameter());
            });

            Assert.Equal("name", exception.ParamName);
            Assert.StartsWith("The parameter name cannot be null or empty.", exception.Message);
        }

        [Fact]
        public void AddParameter_AddsExpectedParameter()
        {
            // Arrange
            var message = new OpenIddictMessage();

            // Act
            message.AddParameter("parameter", 42);

            // Assert
            Assert.Equal(42, message.GetParameter("parameter"));
        }

        [Fact]
        public void AddParameter_IsCaseSensitive()
        {
            // Arrange
            var message = new OpenIddictMessage();

            // Act
            message.AddParameter("PARAMETER", 42);

            // Assert
            Assert.Null(message.GetParameter("parameter"));
        }

        [Fact]
        public void AddParameter_PreservesEmptyParameters()
        {
            // Arrange
            var message = new OpenIddictMessage();

            // Act
            message.AddParameter("string", string.Empty);
            message.AddParameter("array", new JArray());
            message.AddParameter("object", new JObject());
            message.AddParameter("value", new JValue(string.Empty));

            // Assert
            Assert.Empty((string) message.GetParameter("string"));
            Assert.Equal(new JArray(), (JArray) message.GetParameter("array"));
            Assert.Equal(new JObject(), (JObject) message.GetParameter("object"));
            Assert.Equal(new JValue(string.Empty), (JValue) message.GetParameter("value"));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void GetParameter_ThrowsAnExceptionForNullOrEmptyName(string name)
        {
            // Arrange
            var message = new OpenIddictMessage();

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(() => message.GetParameter(name));

            Assert.Equal("name", exception.ParamName);
            Assert.StartsWith("The parameter name cannot be null or empty.", exception.Message);
        }

        [Fact]
        public void GetParameter_ReturnsExpectedParameter()
        {
            // Arrange
            var message = new OpenIddictMessage();

            message.SetParameter("parameter", 42);

            // Act and assert
            Assert.Equal(42, (int) message.GetParameter("parameter"));
        }

        [Fact]
        public void GetParameter_IsCaseSensitive()
        {
            // Arrange
            var message = new OpenIddictMessage();

            message.SetParameter("parameter", 42);

            // Act and assert
            Assert.Null(message.GetParameter("PARAMETER"));
        }

        [Fact]
        public void GetParameter_ReturnsNullForUnsetParameter()
        {
            // Arrange
            var message = new OpenIddictMessage();

            // Act and assert
            Assert.Null(message.GetParameter("parameter"));
        }

        [Fact]
        public void GetParameters_EnumeratesParameters()
        {
            // Arrange
            var parameters = new Dictionary<string, OpenIddictParameter>
            {
                ["int"] = int.MaxValue,
                ["long"] = long.MaxValue,
                ["string"] = "value"
            };

            var message = new OpenIddictMessage(parameters);

            // Act and assert
            Assert.Equal(parameters, message.GetParameters());
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void HasParameter_ThrowsAnExceptionForNullOrEmptyName(string name)
        {
            // Arrange
            var message = new OpenIddictMessage();

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(() => message.HasParameter(name));

            Assert.Equal("name", exception.ParamName);
            Assert.StartsWith("The parameter name cannot be null or empty.", exception.Message);
        }

        [Theory]
        [InlineData("parameter", true)]
        [InlineData("PARAMETER", false)]
        [InlineData("missing_parameter", false)]
        public void HasParameter_ReturnsExpectedResult(string parameter, bool result)
        {
            // Arrange
            var message = new OpenIddictMessage();

            message.SetParameter("parameter", "value");

            // Act and assert
            Assert.Equal(result, message.HasParameter(parameter));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void RemoveParameter_ThrowsAnExceptionForNullOrEmptyName(string name)
        {
            // Arrange
            var message = new OpenIddictMessage();

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(() => message.RemoveParameter(name));

            Assert.Equal("name", exception.ParamName);
            Assert.StartsWith("The parameter name cannot be null or empty.", exception.Message);
        }

        [Fact]
        public void RemoveParameter_RemovesExpectedParameter()
        {
            // Arrange
            var message = new OpenIddictMessage();
            message.AddParameter("parameter", 42);

            // Act
            message.RemoveParameter("parameter");

            // Assert
            Assert.Null(message.GetParameter("parameter"));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void SetParameter_ThrowsAnExceptionForNullOrEmptyName(string name)
        {
            // Arrange
            var message = new OpenIddictMessage();

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(() => message.SetParameter(name, null));

            Assert.Equal("name", exception.ParamName);
            Assert.StartsWith("The parameter name cannot be null or empty.", exception.Message);
        }

        [Fact]
        public void SetParameter_AddsExpectedParameter()
        {
            // Arrange
            var message = new OpenIddictMessage();

            // Act
            message.SetParameter("parameter", 42);

            // Assert
            Assert.Equal(42, message.GetParameter("parameter"));
        }

        [Fact]
        public void SetParameter_IsCaseSensitive()
        {
            // Arrange
            var message = new OpenIddictMessage();

            // Act
            message.SetParameter("PARAMETER", 42);

            // Assert
            Assert.Null(message.GetParameter("parameter"));
        }

        [Fact]
        public void SetParameter_RemovesNullParameters()
        {
            // Arrange
            var message = new OpenIddictMessage();

            // Act
            message.SetParameter("null", null);

            // Assert
            Assert.Empty(message.GetParameters());
        }

        [Fact]
        public void SetParameter_RemovesEmptyParameters()
        {
            // Arrange
            var message = new OpenIddictMessage();

            // Act
            message.SetParameter("string", string.Empty);
            message.SetParameter("array", new JArray());
            message.SetParameter("object", new JObject());
            message.SetParameter("value", new JValue(string.Empty));

            // Assert
            Assert.Empty(message.GetParameters());
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void TryGetParameter_ThrowsAnExceptionForNullOrEmptyName(string name)
        {
            // Arrange
            var message = new OpenIddictMessage();

            // Act
            var exception = Assert.Throws<ArgumentException>(() => message.TryGetParameter(name, out OpenIddictParameter parameter));

            // Assert
            Assert.Equal("name", exception.ParamName);
            Assert.StartsWith("The parameter name cannot be null or empty.", exception.Message);
        }

        [Fact]
        public void TryGetParameter_ReturnsTrueAndExpectedParameter()
        {
            // Arrange
            var name = "paramName";
            var val = "paramValue";
            var message = new OpenIddictMessage();
            message.SetParameter(name, val);

            // Act
            var success = message.TryGetParameter(name, out OpenIddictParameter parameter);

            // Assert
            Assert.True(success);
            Assert.Equal(val, (string)parameter.Value);
        }

        [Fact]
        public void TryGetParameter_ReturnsFalse()
        {
            // Arrange
            var name = "paramName";
            var message = new OpenIddictMessage();

            // Act
            var success = message.TryGetParameter(name, out OpenIddictParameter parameter);

            // Assert
            Assert.False(success);
            Assert.Null(parameter.Value);
        }

        [Fact]
        public void ToString_ReturnsJsonRepresentation()
        {
            // Arrange
            var message = JsonConvert.DeserializeObject<OpenIddictMessage>(@"{
  ""redirect_uris"": [
    ""https://client.example.org/callback"",
    ""https://client.example.org/callback2""
  ],
  ""client_name"": ""My Example Client"",
  ""token_endpoint_auth_method"": ""client_secret_basic"",
  ""logo_uri"": ""https://client.example.org/logo.png"",
  ""jwks_uri"": ""https://client.example.org/my_public_keys.jwks"",
  ""example_extension_parameter"": ""example_value""
}");

            // Act and assert
            Assert.Equal(JsonConvert.SerializeObject(message, Formatting.Indented), message.ToString());
        }

        [Theory]
        [InlineData(OpenIddictConstants.Parameters.AccessToken)]
        [InlineData(OpenIddictConstants.Parameters.Assertion)]
        [InlineData(OpenIddictConstants.Parameters.ClientAssertion)]
        [InlineData(OpenIddictConstants.Parameters.ClientSecret)]
        [InlineData(OpenIddictConstants.Parameters.Code)]
        [InlineData(OpenIddictConstants.Parameters.IdToken)]
        [InlineData(OpenIddictConstants.Parameters.IdTokenHint)]
        [InlineData(OpenIddictConstants.Parameters.Password)]
        [InlineData(OpenIddictConstants.Parameters.RefreshToken)]
        [InlineData(OpenIddictConstants.Parameters.Token)]
        public void ToString_ExcludesSensitiveParameters(string parameter)
        {
            // Arrange
            var message = new OpenIddictMessage();
            message.AddParameter(parameter, "secret value");

            // Act and assert
            Assert.DoesNotContain("secret value", message.ToString());
            Assert.Equal("[removed for security reasons]", JObject.Parse(message.ToString())[parameter]);
        }
    }
}
