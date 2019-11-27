/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Xunit;

namespace AspNet.Security.OpenIdConnect.Primitives.Tests
{
    public class OpenIdConnectMessageTests
    {
        [Fact]
        public void Constructor_ImportsParameters()
        {
            // Arrange and act
            var message = new OpenIdConnectMessage(new[]
            {
                new KeyValuePair<string, OpenIdConnectParameter>("parameter", 42)
            });

            // Assert
            Assert.Equal(42, (long) message.GetParameter("parameter"));
        }

        [Fact]
        public void Constructor_IgnoresNamelessParameters()
        {
            // Arrange and act
            var message = new OpenIdConnectMessage(new[]
            {
                new KeyValuePair<string, OpenIdConnectParameter>(null, new OpenIdConnectParameter()),
                new KeyValuePair<string, OpenIdConnectParameter>(string.Empty, new OpenIdConnectParameter())
            });

            // Assert
            Assert.Empty(message.GetParameters());
        }

        [Fact]
        public void Constructor_PreservesEmptyParameters()
        {
            // Arrange and act
            var message = new OpenIdConnectMessage(new[]
            {
                new KeyValuePair<string, OpenIdConnectParameter>("null-parameter", (string) null),
                new KeyValuePair<string, OpenIdConnectParameter>("empty-parameter", string.Empty)
            });

            // Assert
            Assert.Equal(2, message.GetParameters().Count());
        }

        [Fact]
        public void Constructor_IgnoresDuplicateParameters()
        {
            // Arrange and act
            var message = new OpenIdConnectMessage(new[]
            {
                new KeyValuePair<string, OpenIdConnectParameter>("parameter", "Fabrikam"),
                new KeyValuePair<string, OpenIdConnectParameter>("parameter", "Contoso")
            });

            // Assert
            Assert.Single(message.GetParameters());
            Assert.Equal("Fabrikam", message.GetParameter("parameter"));
        }

        [Fact]
        public void Constructor_SupportsMultiValuedParameters()
        {
            // Arrange and act
            var message = new OpenIdConnectMessage(new[]
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
            var message = new OpenIdConnectMessage(new[]
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
            var message = new OpenIdConnectMessage();

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                message.AddParameter(name, new OpenIdConnectParameter());
            });

            Assert.Equal("name", exception.ParamName);
            Assert.StartsWith("The parameter name cannot be null or empty.", exception.Message);
        }

        [Fact]
        public void AddParameter_AddsExpectedParameter()
        {
            // Arrange
            var message = new OpenIdConnectMessage();

            // Act
            message.AddParameter("parameter", 42);

            // Assert
            Assert.Equal(42, message.GetParameter("parameter"));
        }

        [Fact]
        public void AddParameter_IsCaseSensitive()
        {
            // Arrange
            var message = new OpenIdConnectMessage();

            // Act
            message.AddParameter("PARAMETER", 42);

            // Assert
            Assert.Null(message.GetParameter("parameter"));
        }

        [Fact]
        public void AddParameter_PreservesEmptyParameters()
        {
            // Arrange
            var message = new OpenIdConnectMessage();

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
        public void AddProperty_ThrowsAnExceptionForNullOrEmptyName(string name)
        {
            // Arrange
            var message = new OpenIdConnectMessage();

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                message.AddProperty(name, null);
            });

            Assert.Equal("name", exception.ParamName);
            Assert.StartsWith("The property name cannot be null or empty.", exception.Message);
        }

        [Fact]
        public void AddProperty_AddsExpectedProperty()
        {
            // Arrange
            var message = new OpenIdConnectMessage();

            // Act
            message.AddProperty("property", "value");

            // Assert
            Assert.Equal("value", message.GetProperty("property"));
        }

        [Fact]
        public void AddProperty_IsCaseSensitive()
        {
            // Arrange
            var message = new OpenIdConnectMessage();

            // Act
            message.AddProperty("PROPERTY", "value");

            // Assert
            Assert.Null(message.GetProperty("property"));
        }

        [Fact]
        public void AddProperty_PreservesEmptyProperties()
        {
            // Arrange
            var message = new OpenIdConnectMessage();

            // Act
            message.AddProperty("property", string.Empty);

            // Assert
            Assert.Empty(message.GetProperty<string>("property"));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void GetParameter_ThrowsAnExceptionForNullOrEmptyName(string name)
        {
            // Arrange
            var message = new OpenIdConnectMessage();

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                message.GetParameter(name);
            });

            Assert.Equal("name", exception.ParamName);
            Assert.StartsWith("The parameter name cannot be null or empty.", exception.Message);
        }

        [Fact]
        public void GetParameter_ReturnsExpectedParameter()
        {
            // Arrange
            var message = new OpenIdConnectMessage();

            message.SetParameter("parameter", 42);

            // Act and assert
            Assert.Equal(42, (int) message.GetParameter("parameter"));
        }

        [Fact]
        public void GetParameter_IsCaseSensitive()
        {
            // Arrange
            var message = new OpenIdConnectMessage();

            message.SetParameter("parameter", 42);

            // Act and assert
            Assert.Null(message.GetParameter("PARAMETER"));
        }

        [Fact]
        public void GetParameter_ReturnsNullForUnsetParameter()
        {
            // Arrange
            var message = new OpenIdConnectMessage();

            // Act and assert
            Assert.Null(message.GetParameter("parameter"));
        }

        [Fact]
        public void GetParameters_EnumeratesParameters()
        {
            // Arrange
            var parameters = new Dictionary<string, OpenIdConnectParameter>
            {
                ["int"] = int.MaxValue,
                ["long"] = long.MaxValue,
                ["string"] = "value"
            };

            var message = new OpenIdConnectMessage(parameters);

            // Act and assert
            Assert.Equal(parameters, message.GetParameters());
        }

        [Fact]
        public void GetProperties_EnumeratesProperties()
        {
            // Arrange
            var properties = new Dictionary<string, object>
            {
                ["int"] = int.MaxValue,
                ["long"] = long.MaxValue,
                ["object"] = new object(),
                ["string"] = "value"
            };

            var message = new OpenIdConnectMessage();

            foreach (var property in properties)
            {
                message.SetProperty(property.Key, property.Value);
            }

            // Act and assert
            Assert.Equal(properties, message.GetProperties());
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void GetProperty_ThrowsAnExceptionForNullOrEmptyName(string name)
        {
            // Arrange
            var message = new OpenIdConnectMessage();

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                message.GetProperty(name);
            });

            Assert.Equal("name", exception.ParamName);
            Assert.StartsWith("The property name cannot be null or empty.", exception.Message);
        }

        [Fact]
        public void GetProperty_ReturnsDefaultInstanceForMissingProperty()
        {
            // Arrange
            var message = new OpenIdConnectMessage();

            // Act and assert
            Assert.Equal(0, message.GetProperty<long>("property"));
        }

        [Fact]
        public void GetProperty_ReturnsDefaultInstanceForInvalidType()
        {
            // Arrange
            var message = new OpenIdConnectMessage();

            message.SetProperty("property", "value");

            // Act and assert
            Assert.Equal(0, message.GetProperty<long>("property"));
        }

        [Theory]
        [InlineData("property", "value")]
        [InlineData("PROPERTY", null)]
        [InlineData("missing_property", null)]
        public void GetProperty_ReturnsExpectedResult(string property, object result)
        {
            // Arrange
            var message = new OpenIdConnectMessage();

            message.SetProperty("property", "value");

            // Act and assert
            Assert.Equal(result, message.GetProperty(property));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void HasParameter_ThrowsAnExceptionForNullOrEmptyName(string name)
        {
            // Arrange
            var message = new OpenIdConnectMessage();

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                message.HasParameter(name);
            });

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
            var message = new OpenIdConnectMessage();

            message.SetParameter("parameter", "value");

            // Act and assert
            Assert.Equal(result, message.HasParameter(parameter));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void HasProperty_ThrowsAnExceptionForNullOrEmptyName(string name)
        {
            // Arrange
            var message = new OpenIdConnectMessage();

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                message.HasProperty(name);
            });

            Assert.Equal("name", exception.ParamName);
            Assert.StartsWith("The property name cannot be null or empty.", exception.Message);
        }

        [Theory]
        [InlineData("property", true)]
        [InlineData("PROPERTY", false)]
        [InlineData("missing_property", false)]
        public void HasProperty_ReturnsExpectedResult(string property, bool result)
        {
            // Arrange
            var message = new OpenIdConnectMessage();
            message.SetProperty("property", "value");

            // Act and assert
            Assert.Equal(result, message.HasProperty(property));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void RemoveParameter_ThrowsAnExceptionForNullOrEmptyName(string name)
        {
            // Arrange
            var message = new OpenIdConnectMessage();

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                message.RemoveParameter(name);
            });

            Assert.Equal("name", exception.ParamName);
            Assert.StartsWith("The parameter name cannot be null or empty.", exception.Message);
        }

        [Fact]
        public void RemoveParameter_RemovesExpectedParameter()
        {
            // Arrange
            var message = new OpenIdConnectMessage();
            message.AddParameter("parameter", 42);

            // Act
            message.RemoveParameter("parameter");

            // Assert
            Assert.Null(message.GetParameter("parameter"));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void RemoveProperty_ThrowsAnExceptionForNullOrEmptyName(string name)
        {
            // Arrange
            var message = new OpenIdConnectMessage();

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                message.RemoveProperty(name);
            });

            Assert.Equal("name", exception.ParamName);
            Assert.StartsWith("The property name cannot be null or empty.", exception.Message);
        }

        [Fact]
        public void RemoveProperty_RemovesExpectedProperty()
        {
            // Arrange
            var message = new OpenIdConnectMessage();
            message.AddProperty("property", 42);

            // Act
            message.RemoveProperty("property");

            // Assert
            Assert.Null(message.GetProperty("property"));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void SetParameter_ThrowsAnExceptionForNullOrEmptyName(string name)
        {
            // Arrange
            var message = new OpenIdConnectMessage();

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                message.SetParameter(name, null);
            });

            Assert.Equal("name", exception.ParamName);
            Assert.StartsWith("The parameter name cannot be null or empty.", exception.Message);
        }

        [Fact]
        public void SetParameter_AddsExpectedParameter()
        {
            // Arrange
            var message = new OpenIdConnectMessage();

            // Act
            message.SetParameter("parameter", 42);

            // Assert
            Assert.Equal(42, message.GetParameter("parameter"));
        }

        [Fact]
        public void SetParameter_IsCaseSensitive()
        {
            // Arrange
            var message = new OpenIdConnectMessage();

            // Act
            message.SetParameter("PARAMETER", 42);

            // Assert
            Assert.Null(message.GetParameter("parameter"));
        }

        [Fact]
        public void SetParameter_RemovesNullParameters()
        {
            // Arrange
            var message = new OpenIdConnectMessage();

            // Act
            message.SetParameter("null", null);

            // Assert
            Assert.Empty(message.GetParameters());
        }

        [Fact]
        public void SetParameter_RemovesEmptyParameters()
        {
            // Arrange
            var message = new OpenIdConnectMessage();

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
        public void SetProperty_ThrowsAnExceptionForNullOrEmptyName(string name)
        {
            // Arrange
            var message = new OpenIdConnectMessage();

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                message.SetProperty(name, null);
            });

            Assert.Equal("name", exception.ParamName);
            Assert.StartsWith("The property name cannot be null or empty.", exception.Message);
        }

        [Fact]
        public void SetProperty_AddsExpectedProperty()
        {
            // Arrange
            var message = new OpenIdConnectMessage();

            // Act
            message.SetProperty("property", "value");

            // Assert
            Assert.Equal("value", message.GetProperty("property"));
        }

        [Fact]
        public void SetProperty_IsCaseSensitive()
        {
            // Arrange
            var message = new OpenIdConnectMessage();

            // Act
            message.SetProperty("PROPERTY", "value");

            // Assert
            Assert.Null(message.GetProperty("property"));
        }

        [Fact]
        public void SetProperty_RemovesEmptyProperties()
        {
            // Arrange
            var message = new OpenIdConnectMessage();

            // Act
            message.SetProperty("property", string.Empty);

            // Assert
            Assert.Null(message.GetProperty("property"));
        }

        [Fact]
        public void ToString_ReturnsJsonRepresentation()
        {
            // Arrange
            var message = JsonConvert.DeserializeObject<OpenIdConnectMessage>(@"{
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

        [Fact]
        public void ToString_IgnoresProperties()
        {
            // Arrange
            var message = new OpenIdConnectMessage();
            message.SetProperty("property", "value");

            // Act and assert
            Assert.Equal("{}", message.ToString());
        }

        [Theory]
        [InlineData(OpenIdConnectConstants.Parameters.AccessToken)]
        [InlineData(OpenIdConnectConstants.Parameters.Assertion)]
        [InlineData(OpenIdConnectConstants.Parameters.ClientAssertion)]
        [InlineData(OpenIdConnectConstants.Parameters.ClientSecret)]
        [InlineData(OpenIdConnectConstants.Parameters.Code)]
        [InlineData(OpenIdConnectConstants.Parameters.IdToken)]
        [InlineData(OpenIdConnectConstants.Parameters.IdTokenHint)]
        [InlineData(OpenIdConnectConstants.Parameters.Password)]
        [InlineData(OpenIdConnectConstants.Parameters.RefreshToken)]
        [InlineData(OpenIdConnectConstants.Parameters.Token)]
        public void ToString_ExcludesSensitiveParameters(string parameter)
        {
            // Arrange
            var message = new OpenIdConnectMessage();
            message.AddParameter(parameter, "secret value");

            // Act and assert
            Assert.DoesNotContain("secret value", message.ToString());
            Assert.Equal("[removed for security reasons]", JObject.Parse(message.ToString())[parameter]);
        }
    }
}
