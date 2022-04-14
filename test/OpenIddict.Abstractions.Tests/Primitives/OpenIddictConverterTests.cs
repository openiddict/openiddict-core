/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Text;
using System.Text.Json;
using Xunit;

#if SUPPORTS_JSON_NODES
using System.Text.Json.Nodes;
#endif

namespace OpenIddict.Abstractions.Tests.Primitives;

public class OpenIddictConverterTests
{
    [Fact]
    public void CanConvert_ThrowsAnExceptionForNullType()
    {
        // Arrange
        var converter = new OpenIddictConverter();

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => converter.CanConvert(typeToConvert: null!));

        Assert.Equal("typeToConvert", exception.ParamName);
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
        var exception = Assert.Throws<ArgumentNullException>(delegate
        {
            var reader = new Utf8JsonReader();
            return converter.Read(ref reader, typeToConvert: null!, options: null!);
        });

        Assert.Equal("typeToConvert", exception.ParamName);
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
        var exception = Assert.Throws<ArgumentException>(delegate
        {
            var reader = new Utf8JsonReader(Encoding.UTF8.GetBytes(@"{""name"":""value""}"));
            return converter.Read(ref reader, type, options: null!);
        });

        Assert.StartsWith(SR.GetResourceString(SR.ID0176), exception.Message);
        Assert.Equal("typeToConvert", exception.ParamName);
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
        var message = converter.Read(ref reader, type, options: null!);

        // Assert
        Assert.IsType(type, message);
        Assert.Equal("value", (string?) message.GetParameter("name"));
    }

    [Fact]
    public void Read_PreservesNullParameters()
    {
        // Arrange
        var converter = new OpenIddictConverter();
        var reader = new Utf8JsonReader(Encoding.UTF8.GetBytes(
            @"{""string"":null,""bool"":null,""long"":null,""array"":null,""object"":null}"));

        // Act
        var message = converter.Read(ref reader, typeof(OpenIddictMessage), options: null!);

        // Assert
        Assert.Equal(5, message.Count);
        Assert.NotNull(message.GetParameter("string"));
        Assert.NotNull(message.GetParameter("bool"));
        Assert.NotNull(message.GetParameter("long"));
        Assert.NotNull(message.GetParameter("array"));
        Assert.NotNull(message.GetParameter("object"));
        Assert.Null((string?) message.GetParameter("string"));
        Assert.Null((bool?) message.GetParameter("bool"));
        Assert.Null((long?) message.GetParameter("long"));
        Assert.Equal(JsonValueKind.Null, ((JsonElement) message.GetParameter("array")).ValueKind);
        Assert.Equal(JsonValueKind.Null, ((JsonElement) message.GetParameter("object")).ValueKind);

#if SUPPORTS_JSON_NODES
        Assert.Null((JsonNode?) message.GetParameter("array"));
        Assert.Null((JsonNode?) message.GetParameter("object"));
#endif
    }

    [Fact]
    public void Read_PreservesEmptyParameters()
    {
        // Arrange
        var converter = new OpenIddictConverter();
        var reader = new Utf8JsonReader(Encoding.UTF8.GetBytes(@"{""string"":"""",""array"":[],""object"":{}}"));

        // Act
        var message = converter.Read(ref reader, typeof(OpenIddictMessage), options: null!);

        // Assert
        Assert.Equal(3, message.Count);
        Assert.NotNull(message.GetParameter("string"));
        Assert.NotNull(message.GetParameter("array"));
        Assert.NotNull(message.GetParameter("object"));
        Assert.Empty((string?) message.GetParameter("string"));
        Assert.NotNull((JsonElement?) message.GetParameter("array"));
        Assert.NotNull((JsonElement?) message.GetParameter("object"));

#if SUPPORTS_JSON_NODES
        Assert.NotNull((JsonNode?) message.GetParameter("array"));
        Assert.NotNull((JsonNode?) message.GetParameter("object"));
#endif
    }

    [Fact]
    public void Write_ThrowsAnExceptionForNullWriter()
    {
        // Arrange
        var converter = new OpenIddictConverter();

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() =>
        {
            converter.Write(writer: null!, value: null!, options: null!);
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
            converter.Write(writer: new Utf8JsonWriter(Stream.Null), value: null!, options: null!);
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
        converter.Write(writer, value: message, options: null!);

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
        message.AddParameter("string", new OpenIddictParameter((string?) null));
        message.AddParameter("bool", new OpenIddictParameter((bool?) null));
        message.AddParameter("long", new OpenIddictParameter((long?) null));
        message.AddParameter("element", new OpenIddictParameter(default(JsonElement)));

#if SUPPORTS_JSON_NODES
        message.AddParameter("node", new OpenIddictParameter((JsonNode?) null));
#endif

        // Act
        converter.Write(writer, value: message, options: null!);

        // Assert
        writer.Flush();
        stream.Seek(0L, SeekOrigin.Begin);

#if SUPPORTS_JSON_NODES
        Assert.Equal(@"{""string"":null,""bool"":null,""long"":null,""element"":null,""node"":null}", reader.ReadToEnd());
#else
        Assert.Equal(@"{""string"":null,""bool"":null,""long"":null,""element"":null}", reader.ReadToEnd());
#endif
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
        message.AddParameter("element_array", new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>("[]")));
        message.AddParameter("element_object", new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>("{}")));

#if SUPPORTS_JSON_NODES
        message.AddParameter("node_array", new OpenIddictParameter(new JsonArray()));
        message.AddParameter("node_object", new OpenIddictParameter(new JsonObject()));
        message.AddParameter("node_value", new OpenIddictParameter(JsonValue.Create(new { })));
#endif

        // Act
        converter.Write(writer, value: message, options: null!);

        // Assert
        writer.Flush();
        stream.Seek(0L, SeekOrigin.Begin);

#if SUPPORTS_JSON_NODES
        Assert.Equal(@"{""string"":"""",""element_array"":[],""element_object"":{},""node_array"":[],""node_object"":{},""node_value"":{}}", reader.ReadToEnd());
#else
        Assert.Equal(@"{""string"":"""",""element_array"":[],""element_object"":{}}", reader.ReadToEnd());
#endif
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
        converter.Write(writer, value: message, options: null!);

        // Assert
        writer.Flush();
        stream.Seek(0L, SeekOrigin.Begin);
        Assert.Equal(@"{""string"":""value"",""array"":[""value""]}", reader.ReadToEnd());
    }
}
