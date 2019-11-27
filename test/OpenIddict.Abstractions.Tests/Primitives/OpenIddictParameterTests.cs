/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json.Linq;
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
        public void Equals_ReturnsTrueWhenReferencesAreIdentical()
        {
            // Arrange
            var value = new JObject();
            var parameter = new OpenIddictParameter(value);

            // Act and assert
            Assert.True(parameter.Equals(new OpenIddictParameter(value)));
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

            Assert.False(new OpenIddictParameter(new JObject()).Equals(new OpenIddictParameter(new JArray())));
            Assert.False(new OpenIddictParameter(new JArray()).Equals(new OpenIddictParameter(new JObject())));
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
            var parameter = new OpenIddictParameter(new JArray(new[] { 0, 1, 2, 3 }));

            // Act and assert
            Assert.True(parameter.Equals(new JArray(new[] { 0, 1, 2, 3 })));
            Assert.False(parameter.Equals(new JArray()));
            Assert.False(parameter.Equals(new JArray(new[] { 0, 1, 2 })));
            Assert.False(parameter.Equals(new JArray(new[] { 3, 2, 1, 0 })));
        }

        [Fact]
        public void Equals_UsesDeepEqualsForJsonObjects()
        {
            // Arrange
            var parameter = new OpenIddictParameter(new JObject
            {
                ["field"] = new JArray(new[] { 0, 1, 2, 3 })
            });

            // Act and assert
            Assert.True(parameter.Equals(new JObject
            {
                ["field"] = new JArray(new[] { 0, 1, 2, 3 })
            }));

            Assert.False(parameter.Equals(new JObject()));

            Assert.False(parameter.Equals(new JObject
            {
                ["field"] = "value"
            }));

            Assert.False(parameter.Equals(new JObject
            {
                ["field"] = new JArray(new[] { 0, 1, 2 })
            }));
        }

        [Fact]
        public void Equals_ComparesUnderlyingValuesForJsonValues()
        {
            // Arrange
            var value = new JValue(42);
            var parameter = new OpenIddictParameter(value);

            // Act and assert
            Assert.True(parameter.Equals(new OpenIddictParameter(42)));
            Assert.False(parameter.Equals(new OpenIddictParameter(100)));
        }

        [Fact]
        public void Equals_SupportsNullJsonValues()
        {
            // Arrange
            var parameter = new OpenIddictParameter(42);

            // Act and assert
            Assert.False(parameter.Equals(new OpenIddictParameter(new JValue((long?) null))));
        }

        [Fact]
        public void Equals_SupportsJsonValues()
        {
            // Arrange
            var parameter = new OpenIddictParameter(42);

            // Act and assert
            Assert.True(parameter.Equals(new OpenIddictParameter(new JValue(42))));
            Assert.False(parameter.Equals(new OpenIddictParameter(new JValue(100))));
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
            var parameter = new OpenIddictParameter(new JValue(value));

            // Act and assert
            Assert.Equal(value.GetHashCode(), parameter.GetHashCode());
        }

        [Fact]
        public void GetParameter_ThrowsAnExceptionForNegativeIndex()
        {
            // Arrange
            var parameter = new OpenIddictParameter();

            // Act
            var exception = Assert.Throws<ArgumentOutOfRangeException>(() => parameter.GetParameter(-1));

            // Assert
            Assert.Equal("index", exception.ParamName);
            Assert.StartsWith("The item index cannot be negative.", exception.Message);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void GetParameter_ThrowsAnExceptionForNullOrEmptyName(string name)
        {
            // Arrange
            var parameter = new OpenIddictParameter();

            // Act
            var exception = Assert.Throws<ArgumentException>(() => parameter.GetParameter(name));

            // Assert
            Assert.Equal("name", exception.ParamName);
            Assert.StartsWith("The item name cannot be null or empty.", exception.Message);
        }

        [Fact]
        public void GetParameter_ReturnsNullForPrimitiveValues()
        {
            // Arrange
            var parameter = new OpenIddictParameter(42);

            // Act and assert
            Assert.Null(parameter.GetParameter(0));
            Assert.Null(parameter.GetParameter("parameter"));
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
            Assert.Null(parameter.GetParameter(2));
        }

        [Fact]
        public void GetParameter_ReturnsNullForArrays()
        {
            // Arrange
            var parameter = new OpenIddictParameter(new[]
            {
                "Fabrikam",
                "Contoso"
            });

            // Act and assert
            Assert.Null(parameter.GetParameter("Fabrikam"));
        }

        [Fact]
        public void GetParameter_ReturnsNullForOutOfRangeJsonArrayIndex()
        {
            // Arrange
            var parameter = new OpenIddictParameter(new JArray
            {
                "Fabrikam",
                "Contoso"
            });

            // Act and assert
            Assert.Null(parameter.GetParameter(2));
        }

        [Fact]
        public void GetParameter_ReturnsNullForNonexistentItem()
        {
            // Arrange
            var parameter = new OpenIddictParameter(new JObject());

            // Act and assert
            Assert.Null(parameter.GetParameter("parameter"));
        }

        [Fact]
        public void GetParameter_ReturnsNullForJsonArrays()
        {
            // Arrange
            var parameter = new OpenIddictParameter(new JArray
            {
                "Fabrikam",
                "Contoso"
            });

            // Act and assert
            Assert.Null(parameter.GetParameter("Fabrikam"));
        }

        [Fact]
        public void GetParameter_ReturnsNullForJsonObjects()
        {
            // Arrange
            var parameter = new OpenIddictParameter(new JObject
            {
                ["parameter"] = new JValue("value")
            });

            // Act and assert
            Assert.Null(parameter.GetParameter(0));
        }

        [Fact]
        public void GetParameter_ReturnsNullForNullJsonObjects()
        {
            // Arrange
            var parameter = new OpenIddictParameter(new JObject
            {
                ["property"] = null
            });

            // Act and assert
            Assert.Null(parameter.GetParameter(0));
            Assert.Null(parameter.GetParameter("parameter"));
        }

        [Fact]
        public void GetParameter_ReturnsExpectedNodeForArray()
        {
            // Arrange
            var parameter = new OpenIddictParameter(new[]
            {
                "Fabrikam",
                "Contoso"
            });

            // Act and assert
            Assert.Equal("Fabrikam", (string) parameter.GetParameter(0));
        }

        [Fact]
        public void GetParameter_ReturnsExpectedParameterForJsonObject()
        {
            // Arrange
            var parameter = new OpenIddictParameter(new JObject
            {
                ["parameter"] = new JValue("value")
            });

            // Act and assert
            Assert.Equal("value", (string) parameter.GetParameter("parameter"));
        }

        [Fact]
        public void GetParameter_ReturnsExpectedNodeForJsonArray()
        {
            // Arrange
            var parameter = new OpenIddictParameter(new JArray
            {
                "Fabrikam",
                "Contoso"
            });

            // Act and assert
            Assert.Equal("Fabrikam", (string) parameter.GetParameter(0));
        }

        [Fact]
        public void GetParameters_ReturnsEmptyEnumerationForPrimitiveValues()
        {
            // Arrange
            var parameter = new OpenIddictParameter(42);

            // Act and assert
            Assert.Empty(parameter.GetParameters());
        }

        [Fact]
        public void GetParameters_ReturnsExpectedParametersForArrays()
        {
            // Arrange
            var parameters = new[]
            {
                "Fabrikam",
                "Contoso"
            };

            var parameter = new OpenIddictParameter(parameters);

            // Act and assert
            Assert.Equal(parameters, from element in parameter.GetParameters()
                                     select (string) element.Value);
        }

        [Fact]
        public void GetParameters_ReturnsEmptyEnumerationForJsonValues()
        {
            // Arrange
            var parameter = new OpenIddictParameter(new JValue(42));

            // Act and assert
            Assert.Empty(parameter.GetParameters());
        }

        [Fact]
        public void GetParameters_ReturnsNullKeysForJsonArrays()
        {
            // Arrange
            var parameters = new[]
            {
                "Fabrikam",
                "Contoso"
            };

            var parameter = new OpenIddictParameter(new JArray(parameters));

            // Act and assert
            Assert.All(from element in parameter.GetParameters()
                       select element.Key, key => Assert.Null(key));
        }

        [Fact]
        public void GetParameters_ReturnsExpectedParametersForJsonArrays()
        {
            // Arrange
            var parameters = new[]
            {
                "Fabrikam",
                "Contoso"
            };

            var parameter = new OpenIddictParameter(new JArray(parameters));

            // Act and assert
            Assert.Equal(parameters, from element in parameter.GetParameters()
                                     select (string) element.Value);
        }

        [Fact]
        public void GetParameters_ReturnsExpectedParametersForJsonObjects()
        {
            // Arrange
            var parameters = new Dictionary<string, string>
            {
                ["parameter"] = "value"
            };

            var parameter = new OpenIddictParameter(JObject.FromObject(parameters));

            // Act and assert
            Assert.Equal(parameters, parameter.GetParameters().ToDictionary(pair => pair.Key, pair => (string) pair.Value));
        }

        [Fact]
        public void IsNullOrEmpty_ReturnsTrueForNullValues()
        {
            // Arrange, act and assert
            Assert.True(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter((bool?) null)));
            Assert.True(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter((long?) null)));
            Assert.True(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter((string) null)));
            Assert.True(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter((string[]) null)));
            Assert.True(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter((JArray) null)));
            Assert.True(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter((JObject) null)));
            Assert.True(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter((JValue) null)));
        }

        [Fact]
        public void IsNullOrEmpty_ReturnsTrueForEmptyValues()
        {
            // Arrange, act and assert
            Assert.True(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter(string.Empty)));
            Assert.True(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter(new string[0])));
            Assert.True(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter(new JArray())));
            Assert.True(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter(new JObject())));
            Assert.True(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter(new JValue(string.Empty))));
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
            Assert.False(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter(new JArray("Fabrikam"))));
            Assert.False(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter(new JObject { ["property"] = "value" })));
            Assert.False(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter(new JValue("Fabrikam"))));
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
            var parameter = new OpenIddictParameter(new JObject
            {
                ["parameter"] = new JValue("value")
            });

            // Act and assert
            Assert.Equal(@"{""parameter"":""value""}", parameter.ToString());
        }

        [Fact]
        public void ToString_ReturnsEmptyStringForNullJsonValues()
        {
            // Arrange
            var parameter = new OpenIddictParameter(new JValue((object) null));

            // Act and assert
            Assert.Empty(parameter.ToString());
        }

        [Fact]
        public void ToString_ReturnsUnderlyingJsonValue()
        {
            // Arrange
            var parameter = new OpenIddictParameter(new JValue("Fabrikam"));

            // Act and assert
            Assert.Equal("Fabrikam", parameter.ToString());
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void TryGetParameter_ThrowsAnExceptionForNullOrEmptyName(string name)
        {
            // Arrange
            var parameter = new OpenIddictParameter();

            // Act
            var exception = Assert.Throws<ArgumentException>(() => parameter.TryGetParameter(name, out OpenIddictParameter val));

            // Assert
            Assert.Equal("name", exception.ParamName);
            Assert.StartsWith("The parameter name cannot be null or empty.", exception.Message);
        }

        [Fact]
        public void TryGetParameter_ReturnsTrueAndExpectedParameter()
        {
            // Arrange
            var name = "paramName";
            var val = new JValue("paramValue");
            var parameter = new OpenIddictParameter(new JObject
            {
                [name] = val
            });

            // Act
            var success = parameter.TryGetParameter(name, out OpenIddictParameter expectedParameter);

            // Assert
            Assert.True(success);
            Assert.Equal(val, expectedParameter.Value);
        }

        [Fact]
        public void TryGetParameter_ReturnsFalse()
        {
            // Arrange
            var name = "paramName";
            var parameter = new OpenIddictParameter();

            // Act
            var success = parameter.TryGetParameter(name, out OpenIddictParameter val);

            // Assert
            Assert.False(success);
            Assert.Null(val.Value);
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
            Assert.False((bool) new OpenIddictParameter(new JArray()));
            Assert.Null((bool?) new OpenIddictParameter(new JArray()));
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
            Assert.True((bool) new OpenIddictParameter(new JValue(true)));
            Assert.True((bool?) new OpenIddictParameter(new JValue(true)));
            Assert.True((bool) new OpenIddictParameter(new JValue("true")));
            Assert.True((bool?) new OpenIddictParameter(new JValue("true")));

            Assert.False((bool) new OpenIddictParameter(new JValue(false)));
            Assert.False((bool?) new OpenIddictParameter(new JValue(false)));
            Assert.False((bool) new OpenIddictParameter(new JValue("false")));
            Assert.False((bool?) new OpenIddictParameter(new JValue("false")));
        }

        [Fact]
        public void JArrayConverter_CanCreateParameterFromJArrayValue()
        {
            // Arrange
            var array = new JArray("Fabrikam", "Contoso");

            // Act
            var parameter = new OpenIddictParameter(array);

            // Assert
            Assert.Same(array, parameter.Value);
        }

        [Fact]
        public void JArrayConverter_ReturnsDefaultValueForNullValues()
        {
            // Arrange, act and assert
            Assert.Null((JArray) new OpenIddictParameter());
            Assert.Null((JArray) (OpenIddictParameter?) null);
        }

        [Fact]
        public void JArrayConverter_ReturnsDefaultValueForUnsupportedPrimitiveValues()
        {
            // Arrange, act and assert
            Assert.Null((JArray) new OpenIddictParameter("Fabrikam"));
        }

        [Fact]
        public void JArrayConverter_ReturnsDefaultValueForUnsupportedJsonValues()
        {
            // Arrange, act and assert
            Assert.Null((JArray) new OpenIddictParameter(new JObject()));
        }

        [Fact]
        public void JArrayConverter_ReturnsDefaultValueForUnsupportedSerializedJson()
        {
            // Arrange, act and assert
            Assert.Null((JArray) new OpenIddictParameter(@"{""Property"":""value""}"));
            Assert.Null((JArray) new OpenIddictParameter("["));
        }

        [Fact]
        public void JArrayConverter_CanConvertFromJsonValues()
        {
            // Arrange, act and assert
            Assert.Equal(new JArray("Contoso", "Fabrikam"), (JArray) new OpenIddictParameter(new JArray("Contoso", "Fabrikam")));
        }

        [Fact]
        public void JArrayConverter_CanConvertFromSerializedJson()
        {
            // Arrange, act and assert
            Assert.Equal(new JArray("Contoso", "Fabrikam"), (JArray) new OpenIddictParameter(@"[""Contoso"",""Fabrikam""]"));
        }

        [Fact]
        public void JArrayConverter_CanConvertFromArrays()
        {
            // Arrange, act and assert
            Assert.Equal(new JArray("Contoso", "Fabrikam"), (JArray) new OpenIddictParameter(new[] { "Contoso", "Fabrikam" }));
        }

        [Fact]
        public void JObjectConverter_CanCreateParameterFromJObjectValue()
        {
            // Arrange
            var value = JObject.FromObject(new { Property = "value" });

            // Act
            var parameter = new OpenIddictParameter(value);

            // Assert
            Assert.Same(value, parameter.Value);
        }

        [Fact]
        public void JObjectConverter_ReturnsDefaultValueForNullValues()
        {
            // Arrange, act and assert
            Assert.Null((JObject) new OpenIddictParameter());
            Assert.Null((JObject) (OpenIddictParameter?) null);
        }

        [Fact]
        public void JObjectConverter_ReturnsDefaultValueForUnsupportedPrimitiveValues()
        {
            // Arrange, act and assert
            Assert.Null((JObject) new OpenIddictParameter("Fabrikam"));
        }

        [Fact]
        public void JObjectConverter_ReturnsDefaultValueForUnsupportedArrays()
        {
            // Arrange, act and assert
            Assert.Null((JObject) new OpenIddictParameter(new[] { "Fabrikam", "Contoso" }));
        }

        [Fact]
        public void JObjectConverter_ReturnsDefaultValueForUnsupportedJsonValues()
        {
            // Arrange, act and assert
            Assert.Null((JObject) new OpenIddictParameter(new JArray()));
        }

        [Fact]
        public void JObjectConverter_ReturnsDefaultValueForUnsupportedSerializedJson()
        {
            // Arrange, act and assert
            Assert.Null((JObject) new OpenIddictParameter(@"[""Fabrikam"",""Contoso""]"));
            Assert.Null((JObject) new OpenIddictParameter("{"));
        }

        [Fact]
        public void JObjectConverter_CanConvertFromJsonValues()
        {
            // Arrange, act and assert
            Assert.Equal(JObject.FromObject(new { Property = "value" }), (JObject) new OpenIddictParameter(JObject.FromObject(new { Property = "value" })));
        }

        [Fact]
        public void JObjectConverter_CanConvertFromSerializedJson()
        {
            // Arrange, act and assert
            Assert.Equal(JObject.FromObject(new { Property = "value" }), (JObject) new OpenIddictParameter(@"{""Property"":""value""}"));
        }

        [Fact]
        public void JValueConverter_CanCreateParameterFromJValueValue()
        {
            // Arrange
            var value = new JValue("Fabrikam");

            // Act
            var parameter = new OpenIddictParameter(value);

            // Assert
            Assert.Same(value, parameter.Value);
        }

        [Fact]
        public void JValueConverter_ReturnsDefaultValueForNullValues()
        {
            // Arrange, act and assert
            Assert.Null((JValue) new OpenIddictParameter());
            Assert.Null((JValue) (OpenIddictParameter?) null);
        }

        [Fact]
        public void JValueConverter_ReturnsDefaultValueForUnsupportedJsonValues()
        {
            // Arrange, act and assert
            Assert.Null((JValue) new OpenIddictParameter(new JArray()));
        }

        [Fact]
        public void JValueConverter_CanConvertFromJsonValues()
        {
            // Arrange, act and assert
            Assert.Equal(new JValue(true), (JValue) new OpenIddictParameter(new JValue(true)));
            Assert.Equal(new JValue(42), (JValue) new OpenIddictParameter(new JValue(42)));
            Assert.Equal(new JValue("Fabrikam"), (JValue) new OpenIddictParameter(new JValue("Fabrikam")));
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
            Assert.Equal(0, (long) new OpenIddictParameter(new[] { "Fabrikam", "Contoso" }));
            Assert.Null((long?) new OpenIddictParameter(new[] { "Fabrikam", "Contoso" }));
        }

        [Fact]
        public void LongConverter_ReturnsDefaultValueForUnsupportedJsonValues()
        {
            // Arrange, act and assert
            Assert.Equal(0, (long) new OpenIddictParameter(new JArray()));
            Assert.Null((long?) new OpenIddictParameter(new JArray()));
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
            Assert.Equal(42, (long) new OpenIddictParameter(new JValue(42)));
            Assert.Equal(42, (long?) new OpenIddictParameter(new JValue(42)));
            Assert.Equal(42, (long) new OpenIddictParameter(new JValue(42)));
            Assert.Equal(42, (long?) new OpenIddictParameter(new JValue(42)));
            Assert.Equal(42, (long) new OpenIddictParameter(new JValue(42f)));
            Assert.Equal(42, (long?) new OpenIddictParameter(new JValue(42f)));
            Assert.Equal(42, (long) new OpenIddictParameter(new JValue(42f)));
            Assert.Equal(42, (long?) new OpenIddictParameter(new JValue(42f)));
            Assert.Equal(42, (long) new OpenIddictParameter(new JValue(42m)));
            Assert.Equal(42, (long?) new OpenIddictParameter(new JValue(42m)));
            Assert.Equal(42, (long) new OpenIddictParameter(new JValue(42m)));
            Assert.Equal(42, (long?) new OpenIddictParameter(new JValue(42m)));
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
            Assert.Null((string) new OpenIddictParameter(new[] { "Fabrikam", "Contoso" }));
        }

        [Fact]
        public void StringConverter_ReturnsDefaultValueForUnsupportedJsonValues()
        {
            // Arrange, act and assert
            Assert.Null((string) new OpenIddictParameter(new JArray()));
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
            Assert.Equal("Fabrikam", (string) new OpenIddictParameter(new JValue("Fabrikam")));
            Assert.Equal("False", (string) new OpenIddictParameter(new JValue(false)));
            Assert.Equal("42", (string) new OpenIddictParameter(new JValue(42)));
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
            Assert.Null((string[]) new OpenIddictParameter(new JObject()));
        }

        [Fact]
        public void StringArrayConverter_CanConvertFromJsonValues()
        {
            // Arrange, act and assert
            Assert.Equal(new[] { "Fabrikam" }, (string[]) new OpenIddictParameter(new JValue("Fabrikam")));
            Assert.Equal(new[] { "False" }, (string[]) new OpenIddictParameter(new JValue(false)));
            Assert.Equal(new[] { "42" }, (string[]) new OpenIddictParameter(new JValue(42)));
            Assert.Equal(new[] { "Fabrikam" }, (string[]) new OpenIddictParameter(new JArray("Fabrikam")));
            Assert.Equal(new[] { "Fabrikam", "Contoso" }, (string[]) new OpenIddictParameter(new JArray(new[] { "Fabrikam", "Contoso" })));
        }
    }
}
