/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using Xunit;

namespace OpenIddict.Abstractions.Tests.Primitives
{
    public class OpenIddictConverterTests
    {
        [Fact]
        public void CanConvert_ThrowsAnExceptionForNullType()
        {
            // Arrange
            var converter = new OpenIddictConverter();

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => converter.CanConvert(type: null));

            Assert.Equal("type", exception.ParamName);
        }

        [Theory]
        [InlineData(typeof(OpenIddictMessage), true)]
        [InlineData(typeof(OpenIddictRequest), true)]
        [InlineData(typeof(OpenIddictResponse), true)]
        [InlineData(typeof(OpenIddictMessage[]), false)]
        [InlineData(typeof(OpenIddictRequest[]), false)]
        [InlineData(typeof(OpenIddictResponse[]), false)]
        [InlineData(typeof(OpenIddictParameter), false)]
        [InlineData(typeof(OpenIddictParameter?), false)]
        [InlineData(typeof(OpenIddictParameter[]), false)]
        [InlineData(typeof(OpenIddictParameter?[]), false)]
        [InlineData(typeof(object), false)]
        [InlineData(typeof(long), false)]
        public void CanConvert_ReturnsExpectedResult(Type type, bool result)
        {
            // Arrange
            var converter = new OpenIddictConverter();

            // Act and assert
            Assert.Equal(result, converter.CanConvert(type));
        }

        [Fact]
        public void Read_ThrowsAnExceptionForNullType()
        {
            // Arrange
            var converter = new OpenIddictConverter();

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() =>
            {
                var reader = new Utf8JsonReader();
                converter.Read(ref reader, type: null, options: null);
            });

            Assert.Equal("type", exception.ParamName);
        }

        [Fact]
        public void Read_ThrowsAnExceptionForUnexpectedJsonToken()
        {
            // Arrange
            var converter = new OpenIddictConverter();

            // Act and assert
            var exception = Assert.Throws<JsonException>(() =>
            {
                var reader = new Utf8JsonReader(Encoding.UTF8.GetBytes("[0,1,2,3]"));
                converter.Read(ref reader, type: typeof(OpenIddictRequest), options: null);
            });

            Assert.Equal("An error occurred while reading the JSON payload.", exception.Message);
        }

        [Theory]
        [InlineData(typeof(OpenIddictMessage[]))]
        [InlineData(typeof(OpenIddictRequest[]))]
        [InlineData(typeof(OpenIddictResponse[]))]
        [InlineData(typeof(OpenIddictParameter))]
        [InlineData(typeof(OpenIddictParameter?))]
        [InlineData(typeof(OpenIddictParameter[]))]
        [InlineData(typeof(OpenIddictParameter?[]))]
        [InlineData(typeof(object))]
        [InlineData(typeof(long))]
        public void Read_ThrowsAnExceptionForUnsupportedType(Type type)
        {
            // Arrange
            var converter = new OpenIddictConverter();

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(() =>
            {
                var reader = new Utf8JsonReader(Encoding.UTF8.GetBytes(@"{""name"":""value""}"));
                converter.Read(ref reader, type, options: null);
            });

            Assert.StartsWith("The specified type is not supported.", exception.Message);
            Assert.Equal("type", exception.ParamName);
        }

        [Theory]
        [InlineData(typeof(OpenIddictMessage))]
        [InlineData(typeof(OpenIddictRequest))]
        [InlineData(typeof(OpenIddictResponse))]
        public void Read_ReturnsRequestedType(Type type)
        {
            // Arrange
            var converter = new OpenIddictConverter();
            var reader = new Utf8JsonReader(Encoding.UTF8.GetBytes(@"{""name"":""value""}"));

            // Act
            var result = converter.Read(ref reader, type, options: null);

            // Assert
            Assert.IsType(type, result);
            Assert.Equal("value", (string) result.GetParameter("name"));
        }

        [Fact]
        public void Read_PreservesNullParameters()
        {
            // Arrange
            var converter = new OpenIddictConverter();
            var reader = new Utf8JsonReader(Encoding.UTF8.GetBytes(
                @"{""string"":null,""bool"":null,""long"":null,""array"":null,""object"":null}"));

            // Act
            var result = converter.Read(ref reader, typeof(OpenIddictMessage), options: null);

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
            Assert.Null((JsonElement?) result.GetParameter("array"));
            Assert.Null((JsonElement?) result.GetParameter("object"));
        }

        [Fact]
        public void Read_PreservesEmptyParameters()
        {
            // Arrange
            var converter = new OpenIddictConverter();
            var reader = new Utf8JsonReader(Encoding.UTF8.GetBytes(@"{""string"":"""",""array"":[],""object"":{}}"));

            // Act
            var result = converter.Read(ref reader, typeof(OpenIddictMessage), options: null);

            // Assert
            Assert.Equal(3, result.GetParameters().Count());
            Assert.NotNull(result.GetParameter("string"));
            Assert.NotNull(result.GetParameter("array"));
            Assert.NotNull(result.GetParameter("object"));
            Assert.Empty((string) result.GetParameter("string"));
            Assert.NotNull((JsonElement?) result.GetParameter("array"));
            Assert.NotNull((JsonElement?) result.GetParameter("object"));
        }

        [Fact]
        public void Write_ThrowsAnExceptionForNullWriter()
        {
            // Arrange
            var converter = new OpenIddictConverter();

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() =>
            {
                converter.Write(writer: null, value: null, options: null);
            });

            Assert.Equal("writer", exception.ParamName);
        }

        [Fact]
        public void Write_ThrowsAnExceptionForNullValue()
        {
            // Arrange
            var converter = new OpenIddictConverter();

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() =>
            {
                converter.Write(writer: new Utf8JsonWriter(Stream.Null), value: null, options: null);
            });

            Assert.Equal("value", exception.ParamName);
        }

        [Fact]
        public void Write_WritesEmptyPayloadForEmptyMessages()
        {
            // Arrange
            var message = new OpenIddictMessage();
            var converter = new OpenIddictConverter();
            using var stream = new MemoryStream();
            using var reader = new StreamReader(stream);
            using var writer = new Utf8JsonWriter(stream);

            // Act
            converter.Write(writer, value: message, options: null);

            // Assert
            writer.Flush();
            stream.Seek(0L, SeekOrigin.Begin);
            Assert.Equal("{}", reader.ReadToEnd());
        }

        [Fact]
        public void Write_PreservesNullParameters()
        {
            // Arrange
            var converter = new OpenIddictConverter();
            using var stream = new MemoryStream();
            using var reader = new StreamReader(stream);
            using var writer = new Utf8JsonWriter(stream);

            var message = new OpenIddictMessage();
            message.AddParameter("string", new OpenIddictParameter((string) null));
            message.AddParameter("bool", new OpenIddictParameter((bool?) null));
            message.AddParameter("long", new OpenIddictParameter((long?) null));
            message.AddParameter("array", new OpenIddictParameter((JsonElement?) null));
            message.AddParameter("object", new OpenIddictParameter((JsonElement?) null));

            // Act
            converter.Write(writer, value: message, options: null);

            // Assert
            writer.Flush();
            stream.Seek(0L, SeekOrigin.Begin);
            Assert.Equal(@"{""string"":null,""bool"":null,""long"":null,""array"":null,""object"":null}", reader.ReadToEnd());
        }

        [Fact]
        public void Write_PreservesEmptyParameters()
        {
            // Arrange
            var converter = new OpenIddictConverter();
            using var stream = new MemoryStream();
            using var reader = new StreamReader(stream);
            using var writer = new Utf8JsonWriter(stream);

            var message = new OpenIddictMessage();
            message.AddParameter("string", new OpenIddictParameter(string.Empty));
            message.AddParameter("array", new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>("[]")));
            message.AddParameter("object", new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>("{}")));

            // Act
            converter.Write(writer, value: message, options: null);

            // Assert
            writer.Flush();
            stream.Seek(0L, SeekOrigin.Begin);
            Assert.Equal(@"{""string"":"""",""array"":[],""object"":{}}", reader.ReadToEnd());
        }

        [Fact]
        public void Write_WritesExpectedPayload()
        {
            // Arrange
            var converter = new OpenIddictConverter();
            using var stream = new MemoryStream();
            using var reader = new StreamReader(stream);
            using var writer = new Utf8JsonWriter(stream);

            var message = new OpenIddictMessage();
            message.AddParameter("string", "value");
            message.AddParameter("array", new[] { "value" });

            // Act
            converter.Write(writer, value: message, options: null);

            // Assert
            writer.Flush();
            stream.Seek(0L, SeekOrigin.Begin);
            Assert.Equal(@"{""string"":""value"",""array"":[""value""]}", reader.ReadToEnd());
        }
    }
}
