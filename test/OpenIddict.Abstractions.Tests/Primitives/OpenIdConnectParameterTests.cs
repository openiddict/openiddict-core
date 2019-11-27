/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json.Linq;
using Xunit;

namespace AspNet.Security.OpenIdConnect.Primitives.Tests
{
    public class OpenIdConnectParameterTests
    {
        [Fact]
        public void Equals_ReturnsTrueWhenBothParametersAreNull()
        {
            // Arrange
            var parameter = new OpenIdConnectParameter();

            // Act and assert
            Assert.True(parameter.Equals(new OpenIdConnectParameter()));
        }

        [Fact]
        public void Equals_ReturnsTrueWhenReferencesAreIdentical()
        {
            // Arrange
            var value = new JObject();
            var parameter = new OpenIdConnectParameter(value);

            // Act and assert
            Assert.True(parameter.Equals(new OpenIdConnectParameter(value)));
        }

        [Fact]
        public void Equals_ReturnsFalseWhenCurrentValueIsNull()
        {
            // Arrange
            var parameter = new OpenIdConnectParameter();

            // Act and assert
            Assert.False(parameter.Equals(new OpenIdConnectParameter(42)));
        }

        [Fact]
        public void Equals_ReturnsFalseWhenOtherValueIsNull()
        {
            // Arrange
            var parameter = new OpenIdConnectParameter(42);

            // Act and assert
            Assert.False(parameter.Equals(new OpenIdConnectParameter()));
        }

        [Fact]
        public void Equals_ReturnsFalseForDifferentTypes()
        {
            // Arrange, act and assert
            Assert.False(new OpenIdConnectParameter(true).Equals(new OpenIdConnectParameter("true")));
            Assert.False(new OpenIdConnectParameter("true").Equals(new OpenIdConnectParameter(true)));

            Assert.False(new OpenIdConnectParameter("42").Equals(new OpenIdConnectParameter(42)));
            Assert.False(new OpenIdConnectParameter(42).Equals(new OpenIdConnectParameter("42")));

            Assert.False(new OpenIdConnectParameter(new JObject()).Equals(new OpenIdConnectParameter(new JArray())));
            Assert.False(new OpenIdConnectParameter(new JArray()).Equals(new OpenIdConnectParameter(new JObject())));
        }

        [Fact]
        public void Equals_UsesSequenceEqualForArrays()
        {
            // Arrange
            var parameter = new OpenIdConnectParameter(new[] { "Fabrikam", "Contoso" });

            // Act and assert
            Assert.True(parameter.Equals(new string[] { "Fabrikam", "Contoso" }));
            Assert.False(parameter.Equals(new string[] { "Contoso", "Fabrikam" }));
        }

        [Fact]
        public void Equals_UsesDeepEqualsForJsonArrays()
        {
            // Arrange
            var parameter = new OpenIdConnectParameter(new JArray(new[] { 0, 1, 2, 3 }));

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
            var parameter = new OpenIdConnectParameter(new JObject
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
            var parameter = new OpenIdConnectParameter(value);

            // Act and assert
            Assert.True(parameter.Equals(new OpenIdConnectParameter(42)));
            Assert.False(parameter.Equals(new OpenIdConnectParameter(100)));
        }

        [Fact]
        public void Equals_SupportsNullJsonValues()
        {
            // Arrange
            var parameter = new OpenIdConnectParameter(42);

            // Act and assert
            Assert.False(parameter.Equals(new OpenIdConnectParameter(new JValue((long?) null))));
        }

        [Fact]
        public void Equals_SupportsJsonValues()
        {
            // Arrange
            var parameter = new OpenIdConnectParameter(42);

            // Act and assert
            Assert.True(parameter.Equals(new OpenIdConnectParameter(new JValue(42))));
            Assert.False(parameter.Equals(new OpenIdConnectParameter(new JValue(100))));
        }

        [Fact]
        public void Equals_ReturnsFalseForNonParameters()
        {
            // Arrange
            var parameter = new OpenIdConnectParameter();

            // Act and assert
            Assert.False(parameter.Equals(new object()));
        }

        [Fact]
        public void GetHashCode_ReturnsZeroForNullValues()
        {
            // Arrange
            var parameter = new OpenIdConnectParameter();

            // Act and assert
            Assert.Equal(0, parameter.GetHashCode());
        }

        [Fact]
        public void GetHashCode_ReturnsHashCodeValue()
        {
            // Arrange
            var value = "Fabrikam";
            var parameter = new OpenIdConnectParameter(value);

            // Act and assert
            Assert.Equal(value.GetHashCode(), parameter.GetHashCode());
        }

        [Fact]
        public void GetHashCode_ReturnsUnderlyingJsonValueHashCode()
        {
            // Arrange
            var value = "Fabrikam";
            var parameter = new OpenIdConnectParameter(new JValue(value));

            // Act and assert
            Assert.Equal(value.GetHashCode(), parameter.GetHashCode());
        }

        [Fact]
        public void GetParameter_ThrowsAnExceptionForNegativeIndex()
        {
            // Arrange
            var parameter = new OpenIdConnectParameter();

            // Act
            var exception = Assert.Throws<ArgumentOutOfRangeException>(delegate
            {
                parameter.GetParameter(-1);
            });

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
            var parameter = new OpenIdConnectParameter();

            // Act
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                parameter.GetParameter(name);
            });

            // Assert
            Assert.Equal("name", exception.ParamName);
            Assert.StartsWith("The item name cannot be null or empty.", exception.Message);
        }

        [Fact]
        public void GetParameter_ReturnsNullForPrimitiveValues()
        {
            // Arrange
            var parameter = new OpenIdConnectParameter(42);

            // Act and assert
            Assert.Null(parameter.GetParameter(0));
            Assert.Null(parameter.GetParameter("parameter"));
        }

        [Fact]
        public void GetParameter_ReturnsNullForOutOfRangeArrayIndex()
        {
            // Arrange
            var parameter = new OpenIdConnectParameter(new[]
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
            var parameter = new OpenIdConnectParameter(new[]
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
            var parameter = new OpenIdConnectParameter(new JArray
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
            var parameter = new OpenIdConnectParameter(new JObject());

            // Act and assert
            Assert.Null(parameter.GetParameter("parameter"));
        }

        [Fact]
        public void GetParameter_ReturnsNullForJsonArrays()
        {
            // Arrange
            var parameter = new OpenIdConnectParameter(new JArray
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
            var parameter = new OpenIdConnectParameter(new JObject
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
            var parameter = new OpenIdConnectParameter(new JObject
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
            var parameter = new OpenIdConnectParameter(new[]
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
            var parameter = new OpenIdConnectParameter(new JObject
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
            var parameter = new OpenIdConnectParameter(new JArray
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
            var parameter = new OpenIdConnectParameter(42);

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

            var parameter = new OpenIdConnectParameter(parameters);

            // Act and assert
            Assert.Equal(parameters, from element in parameter.GetParameters()
                                     select (string) element.Value);
        }

        [Fact]
        public void GetParameters_ReturnsEmptyEnumerationForJsonValues()
        {
            // Arrange
            var parameter = new OpenIdConnectParameter(new JValue(42));

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

            var parameter = new OpenIdConnectParameter(new JArray(parameters));

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

            var parameter = new OpenIdConnectParameter(new JArray(parameters));

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

            var parameter = new OpenIdConnectParameter(JObject.FromObject(parameters));

            // Act and assert
            Assert.Equal(parameters, parameter.GetParameters().ToDictionary(pair => pair.Key, pair => (string) pair.Value));
        }

        [Fact]
        public void IsNullOrEmpty_ReturnsTrueForNullValues()
        {
            // Arrange, act and assert
            Assert.True(OpenIdConnectParameter.IsNullOrEmpty(new OpenIdConnectParameter((bool?) null)));
            Assert.True(OpenIdConnectParameter.IsNullOrEmpty(new OpenIdConnectParameter((long?) null)));
            Assert.True(OpenIdConnectParameter.IsNullOrEmpty(new OpenIdConnectParameter((string) null)));
            Assert.True(OpenIdConnectParameter.IsNullOrEmpty(new OpenIdConnectParameter((string[]) null)));
            Assert.True(OpenIdConnectParameter.IsNullOrEmpty(new OpenIdConnectParameter((JArray) null)));
            Assert.True(OpenIdConnectParameter.IsNullOrEmpty(new OpenIdConnectParameter((JObject) null)));
            Assert.True(OpenIdConnectParameter.IsNullOrEmpty(new OpenIdConnectParameter((JValue) null)));
        }

        [Fact]
        public void IsNullOrEmpty_ReturnsTrueForEmptyValues()
        {
            // Arrange, act and assert
            Assert.True(OpenIdConnectParameter.IsNullOrEmpty(new OpenIdConnectParameter(string.Empty)));
            Assert.True(OpenIdConnectParameter.IsNullOrEmpty(new OpenIdConnectParameter(new string[0])));
            Assert.True(OpenIdConnectParameter.IsNullOrEmpty(new OpenIdConnectParameter(new JArray())));
            Assert.True(OpenIdConnectParameter.IsNullOrEmpty(new OpenIdConnectParameter(new JObject())));
            Assert.True(OpenIdConnectParameter.IsNullOrEmpty(new OpenIdConnectParameter(new JValue(string.Empty))));
        }

        [Fact]
        public void IsNullOrEmpty_ReturnsFalseForNonEmptyValues()
        {
            // Arrange, act and assert
            Assert.False(OpenIdConnectParameter.IsNullOrEmpty(new OpenIdConnectParameter(true)));
            Assert.False(OpenIdConnectParameter.IsNullOrEmpty(new OpenIdConnectParameter((bool?) true)));
            Assert.False(OpenIdConnectParameter.IsNullOrEmpty(new OpenIdConnectParameter(42)));
            Assert.False(OpenIdConnectParameter.IsNullOrEmpty(new OpenIdConnectParameter((long?) 42)));
            Assert.False(OpenIdConnectParameter.IsNullOrEmpty(new OpenIdConnectParameter("Fabrikam")));
            Assert.False(OpenIdConnectParameter.IsNullOrEmpty(new OpenIdConnectParameter(new[] { "Fabrikam" })));
            Assert.False(OpenIdConnectParameter.IsNullOrEmpty(new OpenIdConnectParameter(new JArray("Fabrikam"))));
            Assert.False(OpenIdConnectParameter.IsNullOrEmpty(new OpenIdConnectParameter(new JObject { ["property"] = "value" })));
            Assert.False(OpenIdConnectParameter.IsNullOrEmpty(new OpenIdConnectParameter(new JValue("Fabrikam"))));
        }

        [Fact]
        public void ToString_ReturnsEmptyStringForNullValues()
        {
            // Arrange
            var parameter = new OpenIdConnectParameter();

            // Act and assert
            Assert.Empty(parameter.ToString());
        }

        [Fact]
        public void ToString_ReturnsStringValue()
        {
            // Arrange
            var parameter = new OpenIdConnectParameter("Fabrikam");

            // Act and assert
            Assert.Equal("Fabrikam", parameter.ToString());
        }

        [Fact]
        public void ToString_ReturnsSimpleRepresentationForArrays()
        {
            // Arrange
            var parameter = new OpenIdConnectParameter(new[]
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
            var parameter = new OpenIdConnectParameter(new JObject
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
            var parameter = new OpenIdConnectParameter(new JValue((object) null));

            // Act and assert
            Assert.Empty(parameter.ToString());
        }

        [Fact]
        public void ToString_ReturnsUnderlyingJsonValue()
        {
            // Arrange
            var parameter = new OpenIdConnectParameter(new JValue("Fabrikam"));

            // Act and assert
            Assert.Equal("Fabrikam", parameter.ToString());
        }

        [Fact]
        public void BoolConverter_CanCreateParameterFromBooleanValue()
        {
            // Arrange, act and assert
            Assert.True((bool) new OpenIdConnectParameter(true).Value);
            Assert.True((bool) new OpenIdConnectParameter((bool?) true).Value);

            Assert.False((bool) new OpenIdConnectParameter(false).Value);
            Assert.False((bool) new OpenIdConnectParameter((bool?) false).Value);
        }

        [Fact]
        public void BoolConverter_ReturnsDefaultValueForNullValues()
        {
            // Arrange, act and assert
            Assert.False((bool) new OpenIdConnectParameter());
            Assert.False((bool) (OpenIdConnectParameter?) null);

            Assert.Null((bool?) new OpenIdConnectParameter());
            Assert.Null((bool?) (OpenIdConnectParameter?) null);
        }

        [Fact]
        public void BoolConverter_ReturnsDefaultValueForUnsupportedPrimitiveValues()
        {
            // Arrange, act and assert
            Assert.False((bool) new OpenIdConnectParameter("Fabrikam"));
            Assert.Null((bool?) new OpenIdConnectParameter("Fabrikam"));
        }

        [Fact]
        public void BoolConverter_ReturnsDefaultValueForUnsupportedArrays()
        {
            // Arrange, act and assert
            Assert.False((bool) new OpenIdConnectParameter(new[] { "Fabrikam", "Contoso" }));
            Assert.Null((bool?) new OpenIdConnectParameter(new[] { "Fabrikam", "Contoso" }));
        }

        [Fact]
        public void BoolConverter_ReturnsDefaultValueForUnsupportedJsonValues()
        {
            // Arrange, act and assert
            Assert.False((bool) new OpenIdConnectParameter(new JArray()));
            Assert.Null((bool?) new OpenIdConnectParameter(new JArray()));
        }

        [Fact]
        public void BoolConverter_CanConvertFromPrimitiveValues()
        {
            // Arrange, act and assert
            Assert.True((bool) new OpenIdConnectParameter(true));
            Assert.True((bool?) new OpenIdConnectParameter(true));
            Assert.True((bool) new OpenIdConnectParameter("true"));
            Assert.True((bool?) new OpenIdConnectParameter("true"));

            Assert.False((bool) new OpenIdConnectParameter(false));
            Assert.False((bool?) new OpenIdConnectParameter(false));
            Assert.False((bool) new OpenIdConnectParameter("false"));
            Assert.False((bool?) new OpenIdConnectParameter("false"));
        }

        [Fact]
        public void BoolConverter_CanConvertFromJsonValues()
        {
            // Arrange, act and assert
            Assert.True((bool) new OpenIdConnectParameter(new JValue(true)));
            Assert.True((bool?) new OpenIdConnectParameter(new JValue(true)));
            Assert.True((bool) new OpenIdConnectParameter(new JValue("true")));
            Assert.True((bool?) new OpenIdConnectParameter(new JValue("true")));

            Assert.False((bool) new OpenIdConnectParameter(new JValue(false)));
            Assert.False((bool?) new OpenIdConnectParameter(new JValue(false)));
            Assert.False((bool) new OpenIdConnectParameter(new JValue("false")));
            Assert.False((bool?) new OpenIdConnectParameter(new JValue("false")));
        }

        [Fact]
        public void JArrayConverter_CanCreateParameterFromJArrayValue()
        {
            // Arrange
            var array = new JArray("Fabrikam", "Contoso");

            // Act
            var parameter = new OpenIdConnectParameter(array);

            // Assert
            Assert.Same(array, parameter.Value);
        }

        [Fact]
        public void JArrayConverter_ReturnsDefaultValueForNullValues()
        {
            // Arrange, act and assert
            Assert.Null((JArray) new OpenIdConnectParameter());
            Assert.Null((JArray) (OpenIdConnectParameter?) null);
        }

        [Fact]
        public void JArrayConverter_ReturnsDefaultValueForUnsupportedPrimitiveValues()
        {
            // Arrange, act and assert
            Assert.Null((JArray) new OpenIdConnectParameter("Fabrikam"));
        }

        [Fact]
        public void JArrayConverter_ReturnsDefaultValueForUnsupportedJsonValues()
        {
            // Arrange, act and assert
            Assert.Null((JArray) new OpenIdConnectParameter(new JObject()));
        }

        [Fact]
        public void JArrayConverter_ReturnsDefaultValueForUnsupportedSerializedJson()
        {
            // Arrange, act and assert
            Assert.Null((JArray) new OpenIdConnectParameter(@"{""Property"":""value""}"));
            Assert.Null((JArray) new OpenIdConnectParameter("["));
        }

        [Fact]
        public void JArrayConverter_CanConvertFromJsonValues()
        {
            // Arrange, act and assert
            Assert.Equal(new JArray("Contoso", "Fabrikam"), (JArray) new OpenIdConnectParameter(new JArray("Contoso", "Fabrikam")));
        }

        [Fact]
        public void JArrayConverter_CanConvertFromSerializedJson()
        {
            // Arrange, act and assert
            Assert.Equal(new JArray("Contoso", "Fabrikam"), (JArray) new OpenIdConnectParameter(@"[""Contoso"",""Fabrikam""]"));
        }

        [Fact]
        public void JArrayConverter_CanConvertFromArrays()
        {
            // Arrange, act and assert
            Assert.Equal(new JArray("Contoso", "Fabrikam"), (JArray) new OpenIdConnectParameter(new[] { "Contoso", "Fabrikam" }));
        }

        [Fact]
        public void JObjectConverter_CanCreateParameterFromJObjectValue()
        {
            // Arrange
            var value = JObject.FromObject(new { Property = "value" });

            // Act
            var parameter = new OpenIdConnectParameter(value);

            // Assert
            Assert.Same(value, parameter.Value);
        }

        [Fact]
        public void JObjectConverter_ReturnsDefaultValueForNullValues()
        {
            // Arrange, act and assert
            Assert.Null((JObject) new OpenIdConnectParameter());
            Assert.Null((JObject) (OpenIdConnectParameter?) null);
        }

        [Fact]
        public void JObjectConverter_ReturnsDefaultValueForUnsupportedPrimitiveValues()
        {
            // Arrange, act and assert
            Assert.Null((JObject) new OpenIdConnectParameter("Fabrikam"));
        }

        [Fact]
        public void JObjectConverter_ReturnsDefaultValueForUnsupportedArrays()
        {
            // Arrange, act and assert
            Assert.Null((JObject) new OpenIdConnectParameter(new[] { "Fabrikam", "Contoso" }));
        }

        [Fact]
        public void JObjectConverter_ReturnsDefaultValueForUnsupportedJsonValues()
        {
            // Arrange, act and assert
            Assert.Null((JObject) new OpenIdConnectParameter(new JArray()));
        }

        [Fact]
        public void JObjectConverter_ReturnsDefaultValueForUnsupportedSerializedJson()
        {
            // Arrange, act and assert
            Assert.Null((JObject) new OpenIdConnectParameter(@"[""Fabrikam"",""Contoso""]"));
            Assert.Null((JObject) new OpenIdConnectParameter("{"));
        }

        [Fact]
        public void JObjectConverter_CanConvertFromJsonValues()
        {
            // Arrange, act and assert
            Assert.Equal(JObject.FromObject(new { Property = "value" }), (JObject) new OpenIdConnectParameter(JObject.FromObject(new { Property = "value" })));
        }

        [Fact]
        public void JObjectConverter_CanConvertFromSerializedJson()
        {
            // Arrange, act and assert
            Assert.Equal(JObject.FromObject(new { Property = "value" }), (JObject) new OpenIdConnectParameter(@"{""Property"":""value""}"));
        }

        [Fact]
        public void JValueConverter_CanCreateParameterFromJValueValue()
        {
            // Arrange
            var value = new JValue("Fabrikam");

            // Act
            var parameter = new OpenIdConnectParameter(value);

            // Assert
            Assert.Same(value, parameter.Value);
        }

        [Fact]
        public void JValueConverter_ReturnsDefaultValueForNullValues()
        {
            // Arrange, act and assert
            Assert.Null((JValue) new OpenIdConnectParameter());
            Assert.Null((JValue) (OpenIdConnectParameter?) null);
        }

        [Fact]
        public void JValueConverter_ReturnsDefaultValueForUnsupportedJsonValues()
        {
            // Arrange, act and assert
            Assert.Null((JValue) new OpenIdConnectParameter(new JArray()));
        }

        [Fact]
        public void JValueConverter_CanConvertFromJsonValues()
        {
            // Arrange, act and assert
            Assert.Equal(new JValue(true), (JValue) new OpenIdConnectParameter(new JValue(true)));
            Assert.Equal(new JValue(42), (JValue) new OpenIdConnectParameter(new JValue(42)));
            Assert.Equal(new JValue("Fabrikam"), (JValue) new OpenIdConnectParameter(new JValue("Fabrikam")));
        }

        [Fact]
        public void LongConverter_CanCreateParameterFromLongValue()
        {
            // Arrange, act and assert
            Assert.Equal(42, (long) new OpenIdConnectParameter(42).Value);
            Assert.Equal(42, (long) new OpenIdConnectParameter((long?) 42).Value);
        }

        [Fact]
        public void LongConverter_ReturnsDefaultValueForNullValues()
        {
            // Arrange, act and assert
            Assert.Equal(0, (long) new OpenIdConnectParameter());
            Assert.Null((long?) new OpenIdConnectParameter());
        }

        [Fact]
        public void LongConverter_ReturnsDefaultValueForUnsupportedPrimitiveValues()
        {
            // Arrange, act and assert
            Assert.Equal(0, (long) new OpenIdConnectParameter("Fabrikam"));
            Assert.Null((long?) new OpenIdConnectParameter("Fabrikam"));
        }

        [Fact]
        public void LongConverter_ReturnsDefaultValueForUnsupportedArrays()
        {
            // Arrange, act and assert
            Assert.Equal(0, (long) new OpenIdConnectParameter(new[] { "Fabrikam", "Contoso" }));
            Assert.Null((long?) new OpenIdConnectParameter(new[] { "Fabrikam", "Contoso" }));
        }

        [Fact]
        public void LongConverter_ReturnsDefaultValueForUnsupportedJsonValues()
        {
            // Arrange, act and assert
            Assert.Equal(0, (long) new OpenIdConnectParameter(new JArray()));
            Assert.Null((long?) new OpenIdConnectParameter(new JArray()));
        }

        [Fact]
        public void LongConverter_CanConvertFromPrimitiveValues()
        {
            // Arrange, act and assert
            Assert.Equal(42, (long) new OpenIdConnectParameter(42));
            Assert.Equal(42, (long?) new OpenIdConnectParameter(42));
            Assert.Equal(42, (long) new OpenIdConnectParameter(42));
            Assert.Equal(42, (long?) new OpenIdConnectParameter(42));
        }

        [Fact]
        public void LongConverter_CanConvertFromJsonValues()
        {
            // Arrange, act and assert
            Assert.Equal(42, (long) new OpenIdConnectParameter(new JValue(42)));
            Assert.Equal(42, (long?) new OpenIdConnectParameter(new JValue(42)));
            Assert.Equal(42, (long) new OpenIdConnectParameter(new JValue(42)));
            Assert.Equal(42, (long?) new OpenIdConnectParameter(new JValue(42)));
            Assert.Equal(42, (long) new OpenIdConnectParameter(new JValue(42f)));
            Assert.Equal(42, (long?) new OpenIdConnectParameter(new JValue(42f)));
            Assert.Equal(42, (long) new OpenIdConnectParameter(new JValue(42f)));
            Assert.Equal(42, (long?) new OpenIdConnectParameter(new JValue(42f)));
            Assert.Equal(42, (long) new OpenIdConnectParameter(new JValue(42m)));
            Assert.Equal(42, (long?) new OpenIdConnectParameter(new JValue(42m)));
            Assert.Equal(42, (long) new OpenIdConnectParameter(new JValue(42m)));
            Assert.Equal(42, (long?) new OpenIdConnectParameter(new JValue(42m)));
        }

        [Fact]
        public void StringConverter_CanCreateParameterFromStringValue()
        {
            // Arrange, act and assert
            Assert.Equal("Fabrikam", (string) new OpenIdConnectParameter("Fabrikam").Value);
        }

        [Fact]
        public void StringConverter_ReturnsDefaultValueForNullValues()
        {
            // Arrange, act and assert
            Assert.Null((string) new OpenIdConnectParameter());
            Assert.Null((string) (OpenIdConnectParameter?) null);
        }

        [Fact]
        public void StringConverter_ReturnsDefaultValueForArrays()
        {
            // Arrange, act and assert
            Assert.Null((string) new OpenIdConnectParameter(new[] { "Fabrikam", "Contoso" }));
        }

        [Fact]
        public void StringConverter_ReturnsDefaultValueForUnsupportedJsonValues()
        {
            // Arrange, act and assert
            Assert.Null((string) new OpenIdConnectParameter(new JArray()));
        }

        [Fact]
        public void StringConverter_CanConvertFromPrimitiveValues()
        {
            // Arrange, act and assert
            Assert.Equal("Fabrikam", (string) new OpenIdConnectParameter("Fabrikam"));
            Assert.Equal("False", (string) new OpenIdConnectParameter(false));
            Assert.Equal("42", (string) new OpenIdConnectParameter(42));
        }

        [Fact]
        public void StringConverter_CanConvertFromJsonValues()
        {
            // Arrange, act and assert
            Assert.Equal("Fabrikam", (string) new OpenIdConnectParameter(new JValue("Fabrikam")));
            Assert.Equal("False", (string) new OpenIdConnectParameter(new JValue(false)));
            Assert.Equal("42", (string) new OpenIdConnectParameter(new JValue(42)));
        }

        [Fact]
        public void StringArrayConverter_CanCreateParameterFromArray()
        {
            // Arrange
            var array = new[] { "Fabrikam", "Contoso" };

            // Act
            var parameter = new OpenIdConnectParameter(array);

            // Assert
            Assert.Same(array, parameter.Value);
        }

        [Fact]
        public void StringArrayConverter_CanCreateParameterFromPrimitiveValues()
        {
            // Arrange, act and assert
            Assert.Equal(new[] { "Fabrikam" }, (string[]) new OpenIdConnectParameter("Fabrikam"));
            Assert.Equal(new[] { "False" }, (string[]) new OpenIdConnectParameter(false));
            Assert.Equal(new[] { "42" }, (string[]) new OpenIdConnectParameter(42));
        }

        [Fact]
        public void StringArrayConverter_ReturnsDefaultValueForNullValues()
        {
            // Arrange, act and assert
            Assert.Null((string[]) new OpenIdConnectParameter());
        }

        [Fact]
        public void StringArrayConverter_ReturnsSingleElementArrayForStringValue()
        {
            // Arrange, act and assert
            Assert.Equal(new[] { "Fabrikam" }, (string[]) new OpenIdConnectParameter("Fabrikam"));
        }

        [Fact]
        public void StringArrayConverter_ReturnsDefaultValueForUnsupportedJsonValues()
        {
            // Arrange, act and assert
            Assert.Null((string[]) new OpenIdConnectParameter(new JObject()));
        }

        [Fact]
        public void StringArrayConverter_CanConvertFromJsonValues()
        {
            // Arrange, act and assert
            Assert.Equal(new[] { "Fabrikam" }, (string[]) new OpenIdConnectParameter(new JValue("Fabrikam")));
            Assert.Equal(new[] { "False" }, (string[]) new OpenIdConnectParameter(new JValue(false)));
            Assert.Equal(new[] { "42" }, (string[]) new OpenIdConnectParameter(new JValue(42)));
            Assert.Equal(new[] { "Fabrikam" }, (string[]) new OpenIdConnectParameter(new JArray("Fabrikam")));
            Assert.Equal(new[] { "Fabrikam", "Contoso" }, (string[]) new OpenIdConnectParameter(new JArray(new[] { "Fabrikam", "Contoso" })));
        }
    }
}
