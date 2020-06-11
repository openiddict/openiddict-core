/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Xunit;

namespace OpenIddict.Abstractions.Tests.Primitives
{
    public class OpenIddictParameterTests
    {
        [Fact]
        public void Equals_ReturnsTrueWhenBothParametersAreNull()
        {
            // Arrange
            var parameter = new OpenIddictParameter();

            // Act and assert
            Assert.True(parameter.Equals(new OpenIddictParameter()));
        }

        [Fact]
        public void Equals_ReturnsFalseWhenCurrentValueIsNull()
        {
            // Arrange
            var parameter = new OpenIddictParameter();

            // Act and assert
            Assert.False(parameter.Equals(new OpenIddictParameter(42)));
        }

        [Fact]
        public void Equals_ReturnsFalseWhenOtherValueIsNull()
        {
            // Arrange
            var parameter = new OpenIddictParameter(42);

            // Act and assert
            Assert.False(parameter.Equals(new OpenIddictParameter()));
        }

        [Fact]
        public void Equals_ReturnsFalseForDifferentTypes()
        {
            // Arrange, act and assert
            Assert.False(new OpenIddictParameter(true).Equals(new OpenIddictParameter("true")));
            Assert.False(new OpenIddictParameter("true").Equals(new OpenIddictParameter(true)));

            Assert.False(new OpenIddictParameter("42").Equals(new OpenIddictParameter(42)));
            Assert.False(new OpenIddictParameter(42).Equals(new OpenIddictParameter("42")));

            Assert.False(new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>("{}"))
                .Equals(new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>("[]"))));

            Assert.False(new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>("[]"))
                .Equals(new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>("{}"))));
        }

        [Fact]
        public void Equals_UsesSequenceEqualForArrays()
        {
            // Arrange
            var parameter = new OpenIddictParameter(new[] { "Fabrikam", "Contoso" });

            // Act and assert
            Assert.True(parameter.Equals(new string[] { "Fabrikam", "Contoso" }));
            Assert.False(parameter.Equals(new string[] { "Contoso", "Fabrikam" }));
        }

        [Fact]
        public void Equals_UsesDeepEqualsForJsonArrays()
        {
            // Arrange
            var parameter = new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>("[0,1,2,3]"));

            // Act and assert
            Assert.True(parameter.Equals(JsonSerializer.Deserialize<JsonElement>("[0,1,2,3]")));
            Assert.False(parameter.Equals(JsonSerializer.Deserialize<JsonElement>("[]")));
            Assert.False(parameter.Equals(JsonSerializer.Deserialize<JsonElement>("[0,1,2]")));
            Assert.False(parameter.Equals(JsonSerializer.Deserialize<JsonElement>("[3,2,1,0]")));
        }

        [Fact]
        public void Equals_UsesDeepEqualsForJsonObjects()
        {
            // Arrange
            var parameter = new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(@"{""field"":[0,1,2,3]}"));

            // Act and assert
            Assert.True(parameter.Equals(JsonSerializer.Deserialize<JsonElement>(@"{""field"":[0,1,2,3]}")));
            Assert.False(parameter.Equals(JsonSerializer.Deserialize<JsonElement>(@"{}")));
            Assert.False(parameter.Equals(JsonSerializer.Deserialize<JsonElement>(@"{""field"":""value""}")));
            Assert.False(parameter.Equals(JsonSerializer.Deserialize<JsonElement>(@"{""field"":[0,1,2]}")));
        }

        [Fact]
        public void Equals_ComparesUnderlyingValuesForJsonValues()
        {
            // Arrange
            var value = JsonSerializer.Deserialize<JsonElement>(@"{""field"":42}").GetProperty("field");
            var parameter = new OpenIddictParameter(value);

            // Act and assert
            Assert.True(parameter.Equals(new OpenIddictParameter(42)));
            Assert.False(parameter.Equals(new OpenIddictParameter(100)));
        }

        [Fact]
        public void Equals_SupportsUndefinedJsonValues()
        {
            // Arrange
            var parameter = new OpenIddictParameter(42);

            // Act and assert
            Assert.False(parameter.Equals(new OpenIddictParameter(default(JsonElement))));
        }

        [Fact]
        public void Equals_SupportsJsonValues()
        {
            // Arrange
            var parameter = new OpenIddictParameter(42);

            // Act and assert
            Assert.True(parameter.Equals(new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""field"":42}").GetProperty("field"))));
            Assert.False(parameter.Equals(new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""field"":100}").GetProperty("field"))));
        }

        [Fact]
        public void Equals_ReturnsFalseForNonParameters()
        {
            // Arrange
            var parameter = new OpenIddictParameter();

            // Act and assert
            Assert.False(parameter.Equals(new object()));
        }

        [Fact]
        public void GetHashCode_ReturnsZeroForNullValues()
        {
            // Arrange
            var parameter = new OpenIddictParameter();

            // Act and assert
            Assert.Equal(0, parameter.GetHashCode());
        }

        [Fact]
        public void GetHashCode_ReturnsHashCodeValue()
        {
            // Arrange
            var value = "Fabrikam";
            var parameter = new OpenIddictParameter(value);

            // Act and assert
            Assert.Equal(value.GetHashCode(), parameter.GetHashCode());
        }

        [Fact]
        public void GetHashCode_ReturnsUnderlyingJsonValueHashCode()
        {
            // Arrange
            var value = "Fabrikam";
            var parameter = new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(@"{""field"":""Fabrikam""}").GetProperty("field"));

            // Act and assert
            Assert.Equal(value.GetHashCode(), parameter.GetHashCode());
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void GetNamedParameter_ThrowsAnExceptionForNullOrEmptyName(string name)
        {
            // Arrange
            var parameter = new OpenIddictParameter();

            // Act
            var exception = Assert.Throws<ArgumentException>(() => parameter.GetNamedParameter(name));

            // Assert
            Assert.Equal("name", exception.ParamName);
            Assert.StartsWith("The item name cannot be null or empty.", exception.Message);
        }

        [Fact]
        public void GetNamedParameter_ReturnsNullForPrimitiveValues()
        {
            // Arrange
            var parameter = new OpenIddictParameter(42);

            // Act and assert
            Assert.Null(parameter.GetNamedParameter("parameter"));
        }

        [Fact]
        public void GetNamedParameter_ReturnsNullForArrays()
        {
            // Arrange
            var parameter = new OpenIddictParameter(new[]
            {
                "Fabrikam",
                "Contoso"
            });

            // Act and assert
            Assert.Null(parameter.GetNamedParameter("Fabrikam"));
        }

        [Fact]
        public void GetNamedParameter_ReturnsNullForNonexistentItem()
        {
            // Arrange
            var parameter = new OpenIddictParameter(new JsonElement());

            // Act and assert
            Assert.Null(parameter.GetNamedParameter("parameter"));
        }

        [Fact]
        public void GetNamedParameter_ReturnsNullForJsonArrays()
        {
            // Arrange
            var parameter = new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"[""Fabrikam"",""Contoso""]"));

            // Act and assert
            Assert.Null(parameter.GetNamedParameter("Fabrikam"));
        }

        [Fact]
        public void GetNamedParameter_ReturnsExpectedParameterForJsonObject()
        {
            // Arrange
            var parameter = new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""parameter"":""value""}"));

            // Act and assert
            Assert.Equal("value", (string) parameter.GetNamedParameter("parameter"));
        }

        [Fact]
        public void GetUnnamedParameter_ThrowsAnExceptionForNegativeIndex()
        {
            // Arrange
            var parameter = new OpenIddictParameter();

            // Act
            var exception = Assert.Throws<ArgumentOutOfRangeException>(() => parameter.GetUnnamedParameter(-1));

            // Assert
            Assert.Equal("index", exception.ParamName);
            Assert.StartsWith("The item index cannot be negative.", exception.Message);
        }

        [Fact]
        public void GetUnnamedParameter_ReturnsNullForPrimitiveValues()
        {
            // Arrange
            var parameter = new OpenIddictParameter(42);

            // Act and assert
            Assert.Null(parameter.GetUnnamedParameter(0));
        }

        [Fact]
        public void GetParameter_ReturnsNullForOutOfRangeArrayIndex()
        {
            // Arrange
            var parameter = new OpenIddictParameter(new[]
            {
                "Fabrikam",
                "Contoso"
            });

            // Act and assert
            Assert.Null(parameter.GetUnnamedParameter(2));
        }

        [Fact]
        public void GetUnnamedParameter_ReturnsExpectedNodeForArray()
        {
            // Arrange
            var parameter = new OpenIddictParameter(new[]
            {
                "Fabrikam",
                "Contoso"
            });

            // Act and assert
            Assert.Equal("Fabrikam", (string) parameter.GetUnnamedParameter(0));
        }

        [Fact]
        public void GetUnnamedParameter_ReturnsNullForOutOfRangeJsonArrayIndex()
        {
            // Arrange
            var parameter = new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"[""Fabrikam"",""Contoso""]"));

            // Act and assert
            Assert.Null(parameter.GetUnnamedParameter(2));
        }

        [Fact]
        public void GetUnnamedParameter_ReturnsNullForJsonObjects()
        {
            // Arrange
            var parameter = new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""parameter"":""value""}"));

            // Act and assert
            Assert.Null(parameter.GetUnnamedParameter(0));
        }

        [Fact]
        public void GetUnnamedParameter_ReturnsExpectedNodeForJsonArray()
        {
            // Arrange
            var parameter = new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"[""Fabrikam"",""Contoso""]"));

            // Act and assert
            Assert.Equal("Fabrikam", (string) parameter.GetUnnamedParameter(0));
        }

        [Fact]
        public void GetNamedParameters_ReturnsEmptyDictionaryForPrimitiveValues()
        {
            // Arrange
            var parameter = new OpenIddictParameter(42);

            // Act and assert
            Assert.Empty(parameter.GetNamedParameters());
        }

        [Fact]
        public void GetNamedParameters_ReturnsEmptyDictionaryForArrays()
        {
            // Arrange
            var parameters = new[]
            {
                "Fabrikam",
                "Contoso"
            };

            var parameter = new OpenIddictParameter(parameters);

            // Act and assert
            Assert.Empty(parameter.GetNamedParameters());
        }

        [Fact]
        public void GetNamedParameters_ReturnsEmptyDictionaryForJsonValues()
        {
            // Arrange
            var parameter = new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""field"":42}").GetProperty("field"));

            // Act and assert
            Assert.Empty(parameter.GetNamedParameters());
        }

        [Fact]
        public void GetNamedParameters_ReturnsEmptyDictionaryForJsonArrays()
        {
            // Arrange
            var parameter = new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"[""Fabrikam"",""Contoso""]"));

            // Act and assert
            Assert.Empty(parameter.GetNamedParameters());
        }

        [Fact]
        public void GetNamedParameters_ReturnsExpectedParametersForJsonObjects()
        {
            // Arrange
            var parameters = new Dictionary<string, string>
            {
                ["parameter"] = "value"
            };

            var parameter = new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""parameter"":""value""}"));

            // Act and assert
            Assert.Equal(parameters, parameter.GetNamedParameters().ToDictionary(pair => pair.Key, pair => (string) pair.Value));
        }

        [Fact]
        public void GetNamedParameters_ReturnsLastOccurrenceOfMultipleParameters()
        {
            // Arrange
            var parameter = new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""parameter"":""value_1"",""parameter"":""value_2""}"));

            // Act and assert
            Assert.Equal("value_2", parameter.GetNamedParameters()["parameter"]);
        }

        [Fact]
        public void GetUnnamedParameters_ReturnsEmptyListForPrimitiveValues()
        {
            // Arrange
            var parameter = new OpenIddictParameter(42);

            // Act and assert
            Assert.Empty(parameter.GetUnnamedParameters());
        }

        [Fact]
        public void GetUnnamedParameters_ReturnsExpectedParametersForArrays()
        {
            // Arrange
            var parameters = new[]
            {
                "Fabrikam",
                "Contoso"
            };

            var parameter = new OpenIddictParameter(parameters);

            // Act and assert
            Assert.Equal(parameters, from element in parameter.GetUnnamedParameters()
                                     select (string) element);
        }

        [Fact]
        public void GetUnnamedParameters_ReturnsEmptyListForJsonValues()
        {
            // Arrange
            var parameter = new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""field"":42}").GetProperty("field"));

            // Act and assert
            Assert.Empty(parameter.GetUnnamedParameters());
        }

        [Fact]
        public void GetUnnamedParameters_ReturnsExpectedParametersForJsonArrays()
        {
            // Arrange
            var parameters = new[]
            {
                "Fabrikam",
                "Contoso"
            };

            var parameter = new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"[""Fabrikam"",""Contoso""]"));

            // Act and assert
            Assert.Equal(parameters, from element in parameter.GetUnnamedParameters()
                                     select (string) element);
        }

        [Fact]
        public void GetUnnamedParameters_ReturnsEmptyListForJsonObjects()
        {
            // Arrange
            var parameter = new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""parameter"":""value""}"));

            // Act and assert
            Assert.Empty(parameter.GetUnnamedParameters());
        }

        [Fact]
        public void IsNullOrEmpty_ReturnsTrueForNullValues()
        {
            // Arrange, act and assert
            Assert.True(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter((bool?) null)));
            Assert.True(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter((long?) null)));
            Assert.True(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter((string) null)));
            Assert.True(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter((string[]) null)));
        }

        [Fact]
        public void IsNullOrEmpty_ReturnsTrueForUndefinedValues()
        {
            // Arrange, act and assert
            Assert.True(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter(default(JsonElement))));
        }

        [Fact]
        public void IsNullOrEmpty_ReturnsTrueForEmptyValues()
        {
            // Arrange, act and assert
            Assert.True(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter(string.Empty)));
            Assert.True(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter(Array.Empty<string>())));

            Assert.True(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>("[]"))));
            Assert.True(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>("{}"))));
            Assert.True(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""field"":""""}").GetProperty("field"))));
        }

        [Fact]
        public void IsNullOrEmpty_ReturnsFalseForNonEmptyValues()
        {
            // Arrange, act and assert
            Assert.False(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter(true)));
            Assert.False(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter((bool?) true)));
            Assert.False(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter(42)));
            Assert.False(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter((long?) 42)));
            Assert.False(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter("Fabrikam")));
            Assert.False(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter(new[] { "Fabrikam" })));

            Assert.False(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"[""Fabrikam""]"))));
            Assert.False(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""field"":""Fabrikam""}"))));
            Assert.False(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""field"":""Fabrikam""}").GetProperty("field"))));
        }

        [Fact]
        public void ToString_ReturnsEmptyStringForNullValues()
        {
            // Arrange
            var parameter = new OpenIddictParameter();

            // Act and assert
            Assert.Empty(parameter.ToString());
        }

        [Fact]
        public void ToString_ReturnsStringValue()
        {
            // Arrange
            var parameter = new OpenIddictParameter("Fabrikam");

            // Act and assert
            Assert.Equal("Fabrikam", parameter.ToString());
        }

        [Fact]
        public void ToString_ReturnsSimpleRepresentationForArrays()
        {
            // Arrange
            var parameter = new OpenIddictParameter(new[]
            {
                "Fabrikam",
                "Contoso"
            });

            // Act and assert
            Assert.Equal("Fabrikam, Contoso", parameter.ToString());
        }

        [Fact]
        public void ToString_ReturnsJsonRepresentation()
        {
            // Arrange
            var parameter = new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""parameter"":""value""}"));

            // Act and assert
            Assert.Equal(@"{""parameter"":""value""}", parameter.ToString());
        }

        [Fact]
        public void ToString_ReturnsEmptyStringForNullJsonValues()
        {
            // Arrange
            var parameter = new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""field"":null}").GetProperty("field"));

            // Act and assert
            Assert.Empty(parameter.ToString());
        }

        [Fact]
        public void ToString_ReturnsEmptyStringForUndefinedJsonValues()
        {
            // Arrange
            var parameter = new OpenIddictParameter(default(JsonElement));

            // Act and assert
            Assert.Empty(parameter.ToString());
        }

        [Fact]
        public void ToString_ReturnsUnderlyingJsonValue()
        {
            // Arrange, act and assert
            Assert.Equal(bool.TrueString, new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""field"":true}").GetProperty("field")).ToString());
            Assert.Equal(bool.FalseString, new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""field"":false}").GetProperty("field")).ToString());
            Assert.Equal("Fabrikam", new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""field"":""Fabrikam""}").GetProperty("field")).ToString());
            Assert.Equal(@"[""Fabrikam"",""Contoso""]", new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""field"":[""Fabrikam"",""Contoso""]}").GetProperty("field")).ToString());
            Assert.Equal(@"{""field"":""value""}", new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""field"":""value""}")).ToString());
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void TryGetParameter_ThrowsAnExceptionForNullOrEmptyName(string name)
        {
            // Arrange
            var parameter = new OpenIddictParameter();

            // Act
            var exception = Assert.Throws<ArgumentException>(() => parameter.TryGetParameter(name, out var value));

            // Assert
            Assert.Equal("name", exception.ParamName);
            Assert.StartsWith("The parameter name cannot be null or empty.", exception.Message);
        }

        [Fact]
        public void TryGetParameter_ReturnsTrueAndExpectedParameter()
        {
            // Arrange
            var parameter = new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""parameter"":""value""}"));

            // Act and assert
            Assert.True(parameter.TryGetParameter("parameter", out var value));
            Assert.Equal("value", (string) value);
        }

        [Fact]
        public void TryGetParameter_ReturnsFalse()
        {
            // Arrange
            var parameter = new OpenIddictParameter();

            // Act and assert
            Assert.False(parameter.TryGetParameter("parameter", out var value));
            Assert.Null(value.Value);
        }

        [Fact]
        public void WriteTo_ThrowsAnExceptionForNullWriter()
        {
            // Arrange
            var parameter = new OpenIddictParameter();

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => parameter.WriteTo(writer: null));
            Assert.Equal("writer", exception.ParamName);
        }

        [Fact]
        public void WriteTo_WritesUtf8JsonRepresentation()
        {
            // Arrange
            var parameter = new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(@"{
  ""redirect_uris"": [""https://abc.org/callback""],
  ""client_name"":""My Example Client""
}"));

            using var stream = new MemoryStream();
            using var writer = new Utf8JsonWriter(stream);

            // Act
            parameter.WriteTo(writer);
            writer.Flush();

            // Assert
            Assert.Equal(@"{""redirect_uris"":[""https://abc.org/callback""],""client_name"":""My Example Client""}",
                Encoding.UTF8.GetString(stream.ToArray()));
        }

        [Fact]
        public void BoolConverter_CanCreateParameterFromBooleanValue()
        {
            // Arrange, act and assert
            Assert.True((bool) new OpenIddictParameter(true).Value);
            Assert.True((bool) new OpenIddictParameter((bool?) true).Value);

            Assert.False((bool) new OpenIddictParameter(false).Value);
            Assert.False((bool) new OpenIddictParameter((bool?) false).Value);
        }

        [Fact]
        public void BoolConverter_ReturnsDefaultValueForNullValues()
        {
            // Arrange, act and assert
            Assert.False((bool) new OpenIddictParameter());
            Assert.False((bool) (OpenIddictParameter?) null);

            Assert.Null((bool?) new OpenIddictParameter());
            Assert.Null((bool?) (OpenIddictParameter?) null);
        }

        [Fact]
        public void BoolConverter_ReturnsDefaultValueForUnsupportedPrimitiveValues()
        {
            // Arrange, act and assert
            Assert.False((bool) new OpenIddictParameter("Fabrikam"));
            Assert.Null((bool?) new OpenIddictParameter("Fabrikam"));
        }

        [Fact]
        public void BoolConverter_ReturnsDefaultValueForUnsupportedArrays()
        {
            // Arrange, act and assert
            Assert.False((bool) new OpenIddictParameter(new[] { "Fabrikam", "Contoso" }));
            Assert.Null((bool?) new OpenIddictParameter(new[] { "Fabrikam", "Contoso" }));
        }

        [Fact]
        public void BoolConverter_ReturnsDefaultValueForUnsupportedJsonValues()
        {
            // Arrange, act and assert
            Assert.False((bool) new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>("[]")));
            Assert.Null((bool?) new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>("[]")));
        }

        [Fact]
        public void BoolConverter_CanConvertFromPrimitiveValues()
        {
            // Arrange, act and assert
            Assert.True((bool) new OpenIddictParameter(true));
            Assert.True((bool?) new OpenIddictParameter(true));
            Assert.True((bool) new OpenIddictParameter("true"));
            Assert.True((bool?) new OpenIddictParameter("true"));

            Assert.False((bool) new OpenIddictParameter(false));
            Assert.False((bool?) new OpenIddictParameter(false));
            Assert.False((bool) new OpenIddictParameter("false"));
            Assert.False((bool?) new OpenIddictParameter("false"));
        }

        [Fact]
        public void BoolConverter_CanConvertFromJsonValues()
        {
            // Arrange, act and assert
            Assert.True((bool) new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""field"":true}").GetProperty("field")));
            Assert.True((bool?) new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""field"":true}").GetProperty("field")));
            Assert.True((bool) new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""field"":""true""}").GetProperty("field")));
            Assert.True((bool?) new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""field"":""true""}").GetProperty("field")));

            Assert.False((bool) new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""field"":false}").GetProperty("field")));
            Assert.False((bool?) new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""field"":false}").GetProperty("field")));
            Assert.False((bool) new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""field"":""false""}").GetProperty("field")));
            Assert.False((bool?) new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""field"":""false""}").GetProperty("field")));
        }

        [Fact]
        public void JsonElementConverter_ReturnsDefaultValueForNullValues()
        {
            // Arrange, act and assert
            Assert.Equal(JsonValueKind.Undefined, ((JsonElement) new OpenIddictParameter()).ValueKind);
            Assert.Equal(JsonValueKind.Undefined, ((JsonElement) (OpenIddictParameter?) null).ValueKind);
        }

        [Fact]
        public void JsonElementConverter_ReturnsDefaultValueForUnsupportedJsonValues()
        {
            // Arrange, act and assert
            Assert.Equal(JsonValueKind.Undefined, ((JsonElement) new OpenIddictParameter(new JsonElement())).ValueKind);
        }

        [Fact]
        public void JsonElementConverter_CanConvertFromJsonValues()
        {
            // Arrange and act
            var array = (JsonElement) new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"[""Contoso"",""Fabrikam""]"));
            var dictionary = (JsonElement) new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""Property"":""value""}"));

            // Assert
            Assert.Equal("Contoso", array[0].GetString());
            Assert.Equal("Fabrikam", array[1].GetString());
            Assert.Equal("value", dictionary.GetProperty("Property").GetString());

            Assert.True(((JsonElement) new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""field"":true}").GetProperty("field"))).GetBoolean());

            Assert.Equal(42, ((JsonElement) new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""field"":42}").GetProperty("field"))).GetInt64());

            Assert.Equal("Fabrikam", ((JsonElement) new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""field"":""Fabrikam""}").GetProperty("field"))).GetString());
        }

        [Fact]
        public void JsonElementConverter_CanConvertFromSerializedJson()
        {
            // Arrange and act
            var array = (JsonElement) new OpenIddictParameter(@"[""Contoso"",""Fabrikam""]");
            var dictionary = (JsonElement) new OpenIddictParameter(@"{""Property"":""value""}");

            // Assert
            Assert.Equal("Contoso", array[0].GetString());
            Assert.Equal("Fabrikam", array[1].GetString());
            Assert.Equal("value", dictionary.GetProperty("Property").GetString());
        }

        [Fact]
        public void JsonElementConverter_CanConvertFromArrays()
        {
            // Arrange and act
            var array = (JsonElement) new OpenIddictParameter(new[] { "Contoso", "Fabrikam" });

            // Assert
            Assert.Equal("Contoso", array[0].GetString());
            Assert.Equal("Fabrikam", array[1].GetString());
        }

        [Fact]
        public void LongConverter_CanCreateParameterFromLongValue()
        {
            // Arrange, act and assert
            Assert.Equal(42, (long) new OpenIddictParameter(42).Value);
            Assert.Equal(42, (long) new OpenIddictParameter((long?) 42).Value);
        }

        [Fact]
        public void LongConverter_ReturnsDefaultValueForNullValues()
        {
            // Arrange, act and assert
            Assert.Equal(0, (long) new OpenIddictParameter());
            Assert.Null((long?) new OpenIddictParameter());
        }

        [Fact]
        public void LongConverter_ReturnsDefaultValueForUnsupportedPrimitiveValues()
        {
            // Arrange, act and assert
            Assert.Equal(0, (long) new OpenIddictParameter("Fabrikam"));
            Assert.Null((long?) new OpenIddictParameter("Fabrikam"));
        }

        [Fact]
        public void LongConverter_ReturnsDefaultValueForUnsupportedArrays()
        {
            // Arrange, act and assert
            Assert.Equal(0, (long) new OpenIddictParameter(new[] { "Contoso", "Fabrikam" }));
            Assert.Null((long?) new OpenIddictParameter(new[] { "Contoso", "Fabrikam" }));
        }

        [Fact]
        public void LongConverter_ReturnsDefaultValueForUnsupportedJsonValues()
        {
            // Arrange, act and assert
            Assert.Equal(0, (long) new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>("[]")));
            Assert.Null((long?) new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>("[]")));
        }

        [Fact]
        public void LongConverter_CanConvertFromPrimitiveValues()
        {
            // Arrange, act and assert
            Assert.Equal(42, (long) new OpenIddictParameter(42));
            Assert.Equal(42, (long?) new OpenIddictParameter(42));
            Assert.Equal(42, (long) new OpenIddictParameter(42));
            Assert.Equal(42, (long?) new OpenIddictParameter(42));
        }

        [Fact]
        public void LongConverter_CanConvertFromJsonValues()
        {
            // Arrange, act and assert
            Assert.Equal(42, (long) new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""field"":42}").GetProperty("field")));
            Assert.Equal(42, (long?) new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""field"":42}").GetProperty("field")));
        }

        [Fact]
        public void StringConverter_CanCreateParameterFromStringValue()
        {
            // Arrange, act and assert
            Assert.Equal("Fabrikam", (string) new OpenIddictParameter("Fabrikam").Value);
        }

        [Fact]
        public void StringConverter_ReturnsDefaultValueForNullValues()
        {
            // Arrange, act and assert
            Assert.Null((string) new OpenIddictParameter());
            Assert.Null((string) (OpenIddictParameter?) null);
        }

        [Fact]
        public void StringConverter_ReturnsDefaultValueForArrays()
        {
            // Arrange, act and assert
            Assert.Null((string) new OpenIddictParameter(new[] { "Contoso", "Fabrikam" }));
        }

        [Fact]
        public void StringConverter_ReturnsDefaultValueForUnsupportedJsonValues()
        {
            // Arrange, act and assert
            Assert.Null((string) new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"[""Contoso"",""Fabrikam""]")));
            Assert.Null((string) new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""field"":""Fabrikam""}")));
        }

        [Fact]
        public void StringConverter_CanConvertFromPrimitiveValues()
        {
            // Arrange, act and assert
            Assert.Equal("Fabrikam", (string) new OpenIddictParameter("Fabrikam"));
            Assert.Equal("False", (string) new OpenIddictParameter(false));
            Assert.Equal("42", (string) new OpenIddictParameter(42));
        }

        [Fact]
        public void StringConverter_CanConvertFromJsonValues()
        {
            // Arrange, act and assert
            Assert.Equal("Fabrikam", (string) new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""field"":""Fabrikam""}").GetProperty("field")));
            Assert.Equal(bool.FalseString, (string) new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""field"":false}").GetProperty("field")));
            Assert.Equal("42", (string) new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""field"":42}").GetProperty("field")));
        }

        [Fact]
        public void StringArrayConverter_CanCreateParameterFromArray()
        {
            // Arrange
            var array = new[] { "Fabrikam", "Contoso" };

            // Act
            var parameter = new OpenIddictParameter(array);

            // Assert
            Assert.Same(array, parameter.Value);
        }

        [Fact]
        public void StringArrayConverter_CanCreateParameterFromPrimitiveValues()
        {
            // Arrange, act and assert
            Assert.Equal(new[] { "Fabrikam" }, (string[]) new OpenIddictParameter("Fabrikam"));
            Assert.Equal(new[] { "False" }, (string[]) new OpenIddictParameter(false));
            Assert.Equal(new[] { "42" }, (string[]) new OpenIddictParameter(42));
        }

        [Fact]
        public void StringArrayConverter_ReturnsDefaultValueForNullValues()
        {
            // Arrange, act and assert
            Assert.Null((string[]) new OpenIddictParameter());
        }

        [Fact]
        public void StringArrayConverter_ReturnsSingleElementArrayForStringValue()
        {
            // Arrange, act and assert
            Assert.Equal(new[] { "Fabrikam" }, (string[]) new OpenIddictParameter("Fabrikam"));
        }

        [Fact]
        public void StringArrayConverter_ReturnsDefaultValueForUnsupportedJsonValues()
        {
            // Arrange, act and assert
            Assert.Null((string[]) new OpenIddictParameter(new JsonElement()));
        }

        [Fact]
        public void StringArrayConverter_CanConvertFromJsonValues()
        {
            // Arrange, act and assert
            Assert.Equal(new[] { "Fabrikam" }, (string[]) new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""field"":""Fabrikam""}").GetProperty("field")));
            Assert.Equal(new[] { "False" }, (string[]) new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""field"":false}").GetProperty("field")));
            Assert.Equal(new[] { "42" }, (string[]) new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"{""field"":42}").GetProperty("field")));
            Assert.Equal(new[] { "Fabrikam" }, (string[]) new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"[""Fabrikam""]")));
            Assert.Equal(new[] { "Contoso", "Fabrikam" }, (string[]) new OpenIddictParameter(
                JsonSerializer.Deserialize<JsonElement>(@"[""Contoso"",""Fabrikam""]")));
        }
    }
}
