/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Globalization;
using System.IO;
using System.Linq;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Xunit;

namespace AspNet.Security.OpenIdConnect.Primitives.Tests
{
    public class OpenIdConnectConverterTests
    {
        [Fact]
        public void CanConvert_ThrowsAnExceptionForNullType()
        {
            // Arrange
            var converter = new OpenIdConnectConverter();

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                converter.CanConvert(type: null);
            });

            Assert.Equal("type", exception.ParamName);
        }

        [Theory]
        [InlineData(typeof(OpenIdConnectMessage), true)]
        [InlineData(typeof(OpenIdConnectRequest), true)]
        [InlineData(typeof(OpenIdConnectResponse), true)]
        [InlineData(typeof(OpenIdConnectMessage[]), false)]
        [InlineData(typeof(OpenIdConnectRequest[]), false)]
        [InlineData(typeof(OpenIdConnectResponse[]), false)]
        [InlineData(typeof(OpenIdConnectParameter), false)]
        [InlineData(typeof(OpenIdConnectParameter?), false)]
        [InlineData(typeof(OpenIdConnectParameter[]), false)]
        [InlineData(typeof(OpenIdConnectParameter?[]), false)]
        [InlineData(typeof(object), false)]
        [InlineData(typeof(long), false)]
        public void CanConvert_ReturnsExpectedResult(Type type, bool result)
        {
            // Arrange
            var converter = new OpenIdConnectConverter();

            // Act and assert
            Assert.Equal(result, converter.CanConvert(type));
        }

        [Fact]
        public void ReadJson_ThrowsAnExceptionForNullReader()
        {
            // Arrange
            var converter = new OpenIdConnectConverter();

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                converter.ReadJson(reader: null, type: null, value: null, serializer: null);
            });

            Assert.Equal("reader", exception.ParamName);
        }

        [Fact]
        public void ReadJson_ThrowsAnExceptionForNullType()
        {
            // Arrange
            var converter = new OpenIdConnectConverter();

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                converter.ReadJson(reader: new JsonTextReader(TextReader.Null),
                                   type: null, value: null, serializer: null);
            });

            Assert.Equal("type", exception.ParamName);
        }

        [Fact]
        public void ReadJson_ThrowsAnExceptionForUnexpectedJsonToken()
        {
            // Arrange
            var converter = new OpenIdConnectConverter();
            var reader = new JsonTextReader(new StringReader("[0,1,2,3]"));

            // Act and assert
            var exception = Assert.Throws<JsonSerializationException>(delegate
            {
                converter.ReadJson(reader: reader, type: typeof(OpenIdConnectRequest),
                                   value: null, serializer: null);
            });

            Assert.Equal("An error occurred while reading the JSON payload.", exception.Message);
        }

        [Theory]
        [InlineData(typeof(OpenIdConnectMessage[]))]
        [InlineData(typeof(OpenIdConnectRequest[]))]
        [InlineData(typeof(OpenIdConnectResponse[]))]
        [InlineData(typeof(OpenIdConnectParameter))]
        [InlineData(typeof(OpenIdConnectParameter?))]
        [InlineData(typeof(OpenIdConnectParameter[]))]
        [InlineData(typeof(OpenIdConnectParameter?[]))]
        [InlineData(typeof(object))]
        [InlineData(typeof(long))]
        public void ReadJson_ThrowsAnExceptionForUnsupportedType(Type type)
        {
            // Arrange
            var converter = new OpenIdConnectConverter();
            var reader = new JsonTextReader(new StringReader(@"{""name"":""value""}"));

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                converter.ReadJson(reader, type, value: null, serializer: null);
            });

            Assert.StartsWith("The specified type is not supported.", exception.Message);
            Assert.Equal("type", exception.ParamName);
        }

        [Fact]
        public void ReadJson_PopulatesExistingInstance()
        {
            // Arrange
            var message = new OpenIdConnectMessage();
            var converter = new OpenIdConnectConverter();
            var reader = new JsonTextReader(new StringReader(@"{""name"":""value""}"));

            // Act
            var result = converter.ReadJson(reader: reader, type: typeof(OpenIdConnectMessage),
                                            value: message, serializer: null);

            // Assert
            Assert.Same(message, result);
            Assert.Equal("value", message.GetParameter("name"));
        }

        [Theory]
        [InlineData(typeof(OpenIdConnectMessage))]
        [InlineData(typeof(OpenIdConnectRequest))]
        [InlineData(typeof(OpenIdConnectResponse))]
        public void ReadJson_ReturnsRequestedType(Type type)
        {
            // Arrange
            var converter = new OpenIdConnectConverter();
            var reader = new JsonTextReader(new StringReader(@"{""name"":""value""}"));

            // Act
            var result = (OpenIdConnectMessage) converter.ReadJson(reader, type, value: null, serializer: null);

            // Assert
            Assert.IsType(type, result);
            Assert.Equal("value", result.GetParameter("name"));
        }

        [Fact]
        public void ReadJson_PreservesNullParameters()
        {
            // Arrange
            var converter = new OpenIdConnectConverter();
            var reader = new JsonTextReader(new StringReader(@"{""string"":null,""bool"":null,""long"":null,""array"":null,""object"":null}"));

            // Act
            var result = (OpenIdConnectMessage) converter.ReadJson(reader, typeof(OpenIdConnectMessage),
                                                                   value: null, serializer: null);

            // Assert
            Assert.Equal(5, result.GetParameters().Count());
            Assert.NotNull(result.GetParameter("string"));
            Assert.NotNull(result.GetParameter("bool"));
            Assert.NotNull(result.GetParameter("long"));
            Assert.NotNull(result.GetParameter("array"));
            Assert.NotNull(result.GetParameter("object"));
            Assert.Null((string) result.GetParameter("string"));
            Assert.Null((bool?) result.GetParameter("bool"));
            Assert.Null((long?) result.GetParameter("long"));
            Assert.Null((JArray) result.GetParameter("array"));
            Assert.Null((JObject) result.GetParameter("object"));
        }

        [Fact]
        public void ReadJson_PreservesEmptyParameters()
        {
            // Arrange
            var converter = new OpenIdConnectConverter();
            var reader = new JsonTextReader(new StringReader(@"{""string"":"""",""array"":[],""object"":{}}"));

            // Act
            var result = (OpenIdConnectMessage) converter.ReadJson(reader, typeof(OpenIdConnectMessage),
                                                                   value: null, serializer: null);

            // Assert
            Assert.Equal(3, result.GetParameters().Count());
            Assert.NotNull(result.GetParameter("string"));
            Assert.NotNull(result.GetParameter("array"));
            Assert.NotNull(result.GetParameter("object"));
            Assert.Empty((string) result.GetParameter("string"));
            Assert.Empty((JArray) result.GetParameter("array"));
            Assert.Empty((JObject) result.GetParameter("object"));
        }

        [Fact]
        public void WriteJson_ThrowsAnExceptionForNullWriter()
        {
            // Arrange
            var converter = new OpenIdConnectConverter();

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                converter.WriteJson(writer: null, value: null, serializer: null);
            });

            Assert.Equal("writer", exception.ParamName);
        }

        [Fact]
        public void WriteJson_ThrowsAnExceptionForNullValue()
        {
            // Arrange
            var converter = new OpenIdConnectConverter();

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                converter.WriteJson(writer: new JsonTextWriter(TextWriter.Null), value: null, serializer: null);
            });

            Assert.Equal("value", exception.ParamName);
        }

        [Fact]
        public void WriteJson_ThrowsAnExceptionForInvalidValue()
        {
            // Arrange
            var converter = new OpenIdConnectConverter();

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                converter.WriteJson(writer: new JsonTextWriter(TextWriter.Null), value: new object(), serializer: null);
            });

            Assert.StartsWith("The specified object is not supported.", exception.Message);
            Assert.Equal("value", exception.ParamName);
        }

        [Fact]
        public void WriteJson_WritesEmptyPayloadForEmptyMessages()
        {
            // Arrange
            var message = new OpenIdConnectMessage();
            var converter = new OpenIdConnectConverter();
            var writer = new StringWriter(CultureInfo.InvariantCulture);

            // Act
            converter.WriteJson(writer: new JsonTextWriter(writer), value: message, serializer: null);

            Assert.Equal("{}", writer.ToString());
        }

        [Fact]
        public void WriteJson_PreservesNullParameters()
        {
            // Arrange
            var converter = new OpenIdConnectConverter();
            var writer = new StringWriter(CultureInfo.InvariantCulture);

            var message = new OpenIdConnectMessage();
            message.AddParameter("string", new OpenIdConnectParameter((string) null));
            message.AddParameter("bool", new OpenIdConnectParameter((bool?) null));
            message.AddParameter("long", new OpenIdConnectParameter((long?) null));
            message.AddParameter("array", new OpenIdConnectParameter((JArray) null));
            message.AddParameter("object", new OpenIdConnectParameter((JObject) null));

            // Act
            converter.WriteJson(writer: new JsonTextWriter(writer), value: message, serializer: null);

            // Assert
            Assert.Equal(@"{""string"":null,""bool"":null,""long"":null,""array"":null,""object"":null}", writer.ToString());
        }

        [Fact]
        public void WriteJson_PreservesEmptyParameters()
        {
            // Arrange
            var converter = new OpenIdConnectConverter();
            var writer = new StringWriter(CultureInfo.InvariantCulture);

            var message = new OpenIdConnectMessage();
            message.AddParameter("string", new OpenIdConnectParameter(string.Empty));
            message.AddParameter("array", new OpenIdConnectParameter(new JArray()));
            message.AddParameter("object", new OpenIdConnectParameter(new JObject()));

            // Act
            converter.WriteJson(writer: new JsonTextWriter(writer), value: message, serializer: null);

            // Assert
            Assert.Equal(@"{""string"":"""",""array"":[],""object"":{}}", writer.ToString());
        }

        [Fact]
        public void WriteJson_WritesExpectedPayload()
        {
            // Arrange
            var converter = new OpenIdConnectConverter();
            var writer = new StringWriter(CultureInfo.InvariantCulture);

            var message = new OpenIdConnectMessage();
            message.AddParameter("string", "value");
            message.AddParameter("array", new JArray("value"));

            // Act
            converter.WriteJson(writer: new JsonTextWriter(writer), value: message, serializer: null);

            // Assert
            Assert.Equal(@"{""string"":""value"",""array"":[""value""]}", writer.ToString());
        }
    }
}
