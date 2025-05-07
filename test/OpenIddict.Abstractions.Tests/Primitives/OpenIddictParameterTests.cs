/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Primitives;
using Xunit;

namespace OpenIddict.Abstractions.Tests.Primitives;

public class OpenIddictParameterTests
{
    [Fact]
    public void Count_ReturnsZeroForNullValue()
    {
        // Arrange
        var parameter = new OpenIddictParameter();

        // Act and assert
        Assert.Equal(0, parameter.Count);
    }

    [Fact]
    public void Count_ReturnsZeroForBoolean()
    {
        // Arrange
        var parameter = new OpenIddictParameter(true);

        // Act and assert
        Assert.Equal(0, parameter.Count);
    }

    [Fact]
    public void Count_ReturnsZeroForLongValue()
    {
        // Arrange
        var parameter = new OpenIddictParameter(42);

        // Act and assert
        Assert.Equal(0, parameter.Count);
    }

    [Fact]
    public void Count_ReturnsZeroForString()
    {
        // Arrange
        var parameter = new OpenIddictParameter("Fabrikam");

        // Act and assert
        Assert.Equal(0, parameter.Count);
    }

    [Fact]
    public void Count_ReturnsExpectedValueForArray()
    {
        // Arrange
        var parameter = new OpenIddictParameter(
        [
            "Fabrikam",
            "Contoso"
        ]);

        // Act and assert
        Assert.Equal(2, parameter.Count);
    }

    [Fact]
    public void Count_ReturnsExpectedValueForJsonArrayElements()
    {
        // Arrange
        var parameter = new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"[""Fabrikam"",""Contoso""]"));

        // Act and assert
        Assert.Equal(2, parameter.Count);
    }

    [Fact]
    public void Count_ReturnsExpectedValueForJsonObjectElements()
    {
        // Arrange
        var parameter = new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"{""parameter"":""value""}"));

        // Act and assert
        Assert.Equal(1, parameter.Count);
    }

    [Fact]
    public void Count_ReturnsExpectedValueForJsonArrayNodes()
    {
        // Arrange
        var parameter = new OpenIddictParameter(new JsonArray("Fabrikam", "Contoso"));

        // Act and assert
        Assert.Equal(2, parameter.Count);
    }

    [Fact]
    public void Count_ReturnsExpectedValueForJsonValueNodes()
    {
        // Arrange
        var parameter = new OpenIddictParameter(JsonValue.Create(new[] { "Fabrikam", "Contoso" }));

        // Act and assert
        Assert.Equal(2, parameter.Count);
    }

    [Fact]
    public void Count_ReturnsReturnsExpectedValueForJsonObjectNodes()
    {
        // Arrange
        var parameter = new OpenIddictParameter(new JsonObject
        {
            ["parameter"] = "value"
        });

        // Act and assert
        Assert.Equal(1, parameter.Count);
    }

    [Fact]
    public void Count_ReturnsZeroForJsonValueNodes()
    {
        // Arrange
        var parameter = new OpenIddictParameter(JsonValue.Create("value"));

        // Act and assert
        Assert.Equal(0, parameter.Count);
    }

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

        Assert.False(new OpenIddictParameter(JsonValue.Create(true)).Equals(new OpenIddictParameter(JsonValue.Create("true"))));
        Assert.False(new OpenIddictParameter(JsonValue.Create("true")).Equals(new OpenIddictParameter(JsonValue.Create(true))));
        Assert.False(new OpenIddictParameter(new JsonObject()).Equals(new OpenIddictParameter(new JsonArray())));
        Assert.False(new OpenIddictParameter(new JsonArray()).Equals(new OpenIddictParameter(new JsonObject())));
    }

    [Fact]
    public void Equals_UsesSequenceEqualForArrays()
    {
        // Arrange
        var parameter = new OpenIddictParameter(["Fabrikam", "Contoso"]);

        // Act and assert
        Assert.True(parameter.Equals(new OpenIddictParameter(["Fabrikam", "Contoso"])));
        Assert.False(parameter.Equals(new OpenIddictParameter(["Fabrikam"])));
        Assert.False(parameter.Equals(new OpenIddictParameter(["Contoso", "Fabrikam"])));
    }

    [Fact]
    public void Equals_UsesDeepEqualsForJsonArrayElements()
    {
        // Arrange
        var parameter = new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>("[0,1,2,3]"));

        // Act and assert
        Assert.True(parameter.Equals(new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>("[0,1,2,3]"))));
        Assert.False(parameter.Equals(new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>("[]"))));
        Assert.False(parameter.Equals(new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>("[0,1,2]"))));
        Assert.False(parameter.Equals(new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>("[3,2,1,0]"))));
        Assert.False(parameter.Equals(new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>("{}"))));

        Assert.True(parameter.Equals(new OpenIddictParameter(new JsonArray(0, 1, 2, 3))));
        Assert.False(parameter.Equals(new OpenIddictParameter(new JsonArray())));
        Assert.False(parameter.Equals(new OpenIddictParameter(new JsonArray(0, 1, 2))));
        Assert.False(parameter.Equals(new OpenIddictParameter(new JsonArray(3, 2, 1, 0))));
        Assert.False(parameter.Equals(new OpenIddictParameter(new JsonObject())));
    }

    [Fact]
    public void Equals_UsesDeepEqualsForJsonArrayNodes()
    {
        // Arrange
        var parameter = new OpenIddictParameter(new JsonArray(0, 1, 2, 3));

        // Act and assert
        Assert.True(parameter.Equals(new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>("[0,1,2,3]"))));
        Assert.False(parameter.Equals(new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>("[]"))));
        Assert.False(parameter.Equals(new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>("[0,1,2]"))));
        Assert.False(parameter.Equals(new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>("[3,2,1,0]"))));
        Assert.False(parameter.Equals(new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>("{}"))));

        Assert.True(parameter.Equals(new OpenIddictParameter(new JsonArray(0, 1, 2, 3))));
        Assert.False(parameter.Equals(new OpenIddictParameter(new JsonArray())));
        Assert.False(parameter.Equals(new OpenIddictParameter(new JsonArray(0, 1, 2))));
        Assert.False(parameter.Equals(new OpenIddictParameter(new JsonArray(3, 2, 1, 0))));
        Assert.False(parameter.Equals(new OpenIddictParameter(new JsonObject())));
    }

    [Fact]
    public void Equals_UsesDeepEqualsForJsonObjectElements()
    {
        // Arrange
        var parameter = new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(@"{""field"":[0,1,2,3]}"));

        // Act and assert
        Assert.True(parameter.Equals(new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(@"{""field"":[0,1,2,3]}"))));
        Assert.False(parameter.Equals(new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(@"{}"))));
        Assert.False(parameter.Equals(new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(@"{""field"":""value""}"))));
        Assert.False(parameter.Equals(new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(@"{""field"":[0,1,2]}"))));
        Assert.False(parameter.Equals(new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(@"[]"))));

        Assert.True(parameter.Equals(new OpenIddictParameter(new JsonObject
        {
            ["field"] = new JsonArray(0, 1, 2, 3)
        })));

        Assert.False(parameter.Equals(new OpenIddictParameter(new JsonObject())));

        Assert.False(parameter.Equals(new OpenIddictParameter(new JsonObject
        {
            ["field"] = JsonValue.Create("value")
        })));

        Assert.False(parameter.Equals(new OpenIddictParameter(new JsonObject
        {
            ["field"] =  JsonValue.Create(JsonSerializer.Deserialize<JsonElement>(
                @"{""field"":""value""}").GetProperty("field"))
        })));

        Assert.False(parameter.Equals(new OpenIddictParameter(new JsonObject
        {
            ["field"] = new JsonArray(0, 1, 2)
        })));

        Assert.False(parameter.Equals(new OpenIddictParameter(new JsonArray())));
    }

    [Fact]
    public void Equals_UsesDeepEqualsForJsonObjectNodes()
    {
        // Arrange
        var parameter = new OpenIddictParameter(new JsonObject
        {
            ["field"] = new JsonArray(0, 1, 2, 3)
        });

        // Act and assert
        Assert.True(parameter.Equals(new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(@"{""field"":[0,1,2,3]}"))));
        Assert.False(parameter.Equals(new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(@"{}"))));
        Assert.False(parameter.Equals(new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(@"{""field"":""value""}"))));
        Assert.False(parameter.Equals(new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(@"{""field"":[0,1,2]}"))));
        Assert.False(parameter.Equals(new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(@"[]"))));

        Assert.True(parameter.Equals(new OpenIddictParameter(new JsonObject
        {
            ["field"] = new JsonArray(0, 1, 2, 3)
        })));

        Assert.False(parameter.Equals(new OpenIddictParameter(new JsonObject())));

        Assert.False(parameter.Equals(new OpenIddictParameter(new JsonObject
        {
            ["field"] = JsonValue.Create("value")
        })));

        Assert.False(parameter.Equals(new OpenIddictParameter(new JsonObject
        {
            ["field"] = JsonValue.Create(JsonSerializer.Deserialize<JsonElement>(
                @"{""field"":""value""}").GetProperty("field"))
        })));

        Assert.False(parameter.Equals(new OpenIddictParameter(new JsonObject
        {
            ["field"] = new JsonArray(0, 1, 2)
        })));

        Assert.True(parameter.Equals(new OpenIddictParameter(JsonValue.Create(new Dictionary<string, object>
        {
            ["field"] = new JsonArray(0, 1, 2, 3)
        }))));

        Assert.True(parameter.Equals(new OpenIddictParameter(JsonValue.Create(new Dictionary<string, object>
        {
            ["field"] = new[] { 0, 1, 2, 3 }
        }))));
    }

    [Fact]
    public void Equals_ComparesUnderlyingValuesForJsonValueElements()
    {
        // Arrange, act and assert
        Assert.True(new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(
            @"{""field"":42}").GetProperty("field")).Equals(new OpenIddictParameter(42)));

        Assert.False(new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(
            @"{""field"":42}").GetProperty("field")).Equals(new OpenIddictParameter(100)));

        Assert.True(new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(
            @"{""field"":""Fabrikam""}").GetProperty("field")).Equals(new OpenIddictParameter("Fabrikam")));

        Assert.False(new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(
            @"{""field"":""Fabrikam""}").GetProperty("field")).Equals(new OpenIddictParameter("Contoso")));
    }

    [Fact]
    public void Equals_ComparesUnderlyingValuesForJsonValueNodes()
    {
        // Arrange, act and assert
        Assert.True(new OpenIddictParameter(JsonValue.Create(42)).Equals(new OpenIddictParameter(42)));
        Assert.False(new OpenIddictParameter(JsonValue.Create(42)).Equals(new OpenIddictParameter(100)));
        Assert.True(new OpenIddictParameter(JsonValue.Create(42L)).Equals(new OpenIddictParameter(42)));
        Assert.False(new OpenIddictParameter(JsonValue.Create(42L)).Equals(new OpenIddictParameter(100)));
        Assert.True(new OpenIddictParameter(JsonValue.Create("Fabrikam")).Equals(new OpenIddictParameter("Fabrikam")));
        Assert.False(new OpenIddictParameter(JsonValue.Create("Fabrikam")).Equals(new OpenIddictParameter("Contoso")));

        Assert.True(new OpenIddictParameter(JsonValue.Create(JsonSerializer.Deserialize<JsonElement>(
            @"{""field"":42}").GetProperty("field")))!.Equals(new OpenIddictParameter(42)));

        Assert.False(new OpenIddictParameter(JsonValue.Create(JsonSerializer.Deserialize<JsonElement>(
            @"{""field"":42}").GetProperty("field")))!.Equals(new OpenIddictParameter(100)));

        Assert.True(new OpenIddictParameter(JsonValue.Create(JsonSerializer.Deserialize<JsonElement>(
            @"{""field"":""Fabrikam""}").GetProperty("field")))!.Equals(new OpenIddictParameter("Fabrikam")));

        Assert.False(new OpenIddictParameter(JsonValue.Create(JsonSerializer.Deserialize<JsonElement>(
            @"{""field"":""Fabrikam""}").GetProperty("field")))!.Equals(new OpenIddictParameter("Contoso")));
    }

    [Fact]
    public void Equals_SupportsUndefinedJsonValueElements()
    {
        // Arrange
        var parameter = new OpenIddictParameter(42);

        // Act and assert
        Assert.False(parameter.Equals(new OpenIddictParameter(default(JsonElement))));
    }

    [Fact]
    public void Equals_SupportsUndefinedJsonValueNodes()
    {
        // Arrange
        var parameter = new OpenIddictParameter(42);

        // Act and assert
        Assert.False(parameter.Equals(new OpenIddictParameter((JsonNode?) null)));
    }

    [Fact]
    public void Equals_SupportsJsonValueElements()
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
    public void Equals_SupportsJsonValueNodes()
    {
        // Arrange
        var parameter = new OpenIddictParameter(42);

        // Act and assert
        Assert.True(parameter.Equals(new OpenIddictParameter(JsonValue.Create(42))));
        Assert.False(parameter.Equals(new OpenIddictParameter(JsonValue.Create(100))));

        Assert.True(parameter.Equals(new OpenIddictParameter(JsonValue.Create(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":42}").GetProperty("field")))));

        Assert.False(parameter.Equals(new OpenIddictParameter(JsonValue.Create(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":100}").GetProperty("field")))));
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
    public void GetHashCode_ReturnsUnderlyingHashCodeForPrimitiveValues()
    {
        // Arrange, act and assert
        Assert.Equal(1, new OpenIddictParameter(true).GetHashCode());
        Assert.Equal(0, new OpenIddictParameter(false).GetHashCode());
        Assert.Equal(42.GetHashCode(), new OpenIddictParameter(42).GetHashCode());
        Assert.Equal("Fabrikam".GetHashCode(), new OpenIddictParameter("Fabrikam").GetHashCode());

        Assert.NotEqual(1, new OpenIddictParameter("true").GetHashCode());
        Assert.NotEqual(0, new OpenIddictParameter("false").GetHashCode());
        Assert.NotEqual(42.GetHashCode(), new OpenIddictParameter("42").GetHashCode());
        Assert.NotEqual("Fabrikam".GetHashCode(), new OpenIddictParameter(42).GetHashCode());
    }

    [Fact]
    public void GetHashCode_ReturnsUnderlyingHashCodeForArrays()
    {
        // Arrange, act and assert
        Assert.Equal(
            new OpenIddictParameter(["Fabrikam", "Contoso"]).GetHashCode(),
            new OpenIddictParameter(["Fabrikam", "Contoso"]).GetHashCode());

        Assert.NotEqual(
            new OpenIddictParameter(["Fabrikam", "Contoso"]).GetHashCode(),
            new OpenIddictParameter(["Contoso", "Fabrikam"]).GetHashCode());
    }

    [Fact]
    public void GetHashCode_ReturnsUnderlyingHashCodeForJsonElements()
    {
        // Arrange, act and assert
        Assert.Equal(
            new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(
                @"{""field"":""Fabrikam""}").GetProperty("field")).GetHashCode(),
            new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(
                @"{""field"":""Fabrikam""}").GetProperty("field")).GetHashCode());

        Assert.Equal(
            new OpenIddictParameter("Fabrikam").GetHashCode(),
            new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(
                @"{""field"":""Fabrikam""}").GetProperty("field")).GetHashCode());

        Assert.NotEqual(
            new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(
                @"{""field"":""Fabrikam""}").GetProperty("field")).GetHashCode(),
            new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(
                @"{""field"":""Contoso""}").GetProperty("field")).GetHashCode());

        Assert.NotEqual(
            new OpenIddictParameter("Fabrikam").GetHashCode(),
            new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(
                @"{""field"":""Contoso""}").GetProperty("field")).GetHashCode());

        Assert.Equal(
            new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(
                @"{""field"":""Fabrikam""}")).GetHashCode(),
            new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(
                @"{""field"":""Fabrikam""}")).GetHashCode());

        Assert.NotEqual(
            new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(
                @"{""field"":""Fabrikam""}")).GetHashCode(),
            new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(
                @"{""field"":""Contoso""}")).GetHashCode());

        Assert.Equal(
            new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(
                @"[""Fabrikam"",""Contoso""]")).GetHashCode(),
            new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(
                @"[""Fabrikam"",""Contoso""]")).GetHashCode());

        Assert.Equal(
            new OpenIddictParameter(["Fabrikam", "Contoso"]).GetHashCode(),
            new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(
                @"[""Fabrikam"",""Contoso""]")).GetHashCode());

        Assert.NotEqual(
            new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(
                @"[""Fabrikam"",""Contoso""]")).GetHashCode(),
            new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(
                @"[""Contoso"",""Fabrikam""]")).GetHashCode());

        Assert.NotEqual(
            new OpenIddictParameter(["Fabrikam", "Contoso"]).GetHashCode(),
            new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(
                @"[""Contoso"",""Fabrikam""]")).GetHashCode());
    }

    [Fact]
    public void GetHashCode_ReturnsUnderlyingHashCodeForJsonNodes()
    {
        // Arrange, act and assert
        Assert.Equal(
            new OpenIddictParameter(JsonValue.Create(true)).GetHashCode(),
            new OpenIddictParameter(JsonValue.Create(true)).GetHashCode());

        Assert.Equal(
            new OpenIddictParameter(true).GetHashCode(),
            new OpenIddictParameter(JsonValue.Create(true)).GetHashCode());

        Assert.NotEqual(
            new OpenIddictParameter(JsonValue.Create(true)).GetHashCode(),
            new OpenIddictParameter(JsonValue.Create(false)).GetHashCode());

        Assert.NotEqual(
            new OpenIddictParameter(true).GetHashCode(),
            new OpenIddictParameter(JsonValue.Create(false)).GetHashCode());

        Assert.Equal(
            new OpenIddictParameter(JsonValue.Create(42)).GetHashCode(),
            new OpenIddictParameter(JsonValue.Create(42)).GetHashCode());

        Assert.Equal(
            new OpenIddictParameter(42).GetHashCode(),
            new OpenIddictParameter(JsonValue.Create(42)).GetHashCode());

        Assert.NotEqual(
            new OpenIddictParameter(JsonValue.Create(42)).GetHashCode(),
            new OpenIddictParameter(JsonValue.Create(0)).GetHashCode());

        Assert.NotEqual(
            new OpenIddictParameter(42).GetHashCode(),
            new OpenIddictParameter(JsonValue.Create(0)).GetHashCode());

        Assert.Equal(
            new OpenIddictParameter(JsonValue.Create(new { field = "value" })).GetHashCode(),
            new OpenIddictParameter(JsonValue.Create(new { field = "value" })).GetHashCode());

        Assert.NotEqual(
            new OpenIddictParameter(JsonValue.Create(new { field = "value" })).GetHashCode(),
            new OpenIddictParameter(JsonValue.Create(new { field = "abc" })).GetHashCode());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void GetNamedParameter_ThrowsAnExceptionForNullOrEmptyName(string? name)
    {
        // Arrange
        var parameter = new OpenIddictParameter();

        // Act
        var exception = Assert.Throws<ArgumentException>(() => parameter.GetNamedParameter(name!));

        // Assert
        Assert.Equal("name", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0192), exception.Message);
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
        var parameter = new OpenIddictParameter(
        [
            "Fabrikam",
            "Contoso"
        ]);

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
    public void GetNamedParameter_ReturnsNullForJsonArrayElements()
    {
        // Arrange
        var parameter = new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"[""Fabrikam"",""Contoso""]"));

        // Act and assert
        Assert.Null(parameter.GetNamedParameter("Fabrikam"));
    }

    [Fact]
    public void GetNamedParameter_ReturnsNullForJsonArrayNodes()
    {
        // Arrange
        var parameter = new OpenIddictParameter(new JsonArray("Fabrikam", "Contoso"));

        // Act and assert
        Assert.Null(parameter.GetNamedParameter("Fabrikam"));
    }

    [Fact]
    public void GetNamedParameter_ReturnsExpectedParameterForJsonObjectElements()
    {
        // Arrange
        var parameter = new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"{""parameter"":""value""}"));

        // Act and assert
        Assert.Equal("value", (string?) parameter.GetNamedParameter("parameter"));
    }

    [Fact]
    public void GetNamedParameter_ReturnsExpectedParameterForJsonObjectNodes()
    {
        // Arrange
        var parameter = new OpenIddictParameter(new JsonObject
        {
            ["parameter"] = "value"
        });

        // Act and assert
        Assert.Equal("value", (string?) parameter.GetNamedParameter("parameter"));
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
        Assert.StartsWith(SR.GetResourceString(SR.ID0193), exception.Message);
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
    public void GetUnnamedParameter_ReturnsNullForOutOfRangeArrayIndex()
    {
        // Arrange
        var parameter = new OpenIddictParameter(
        [
            "Fabrikam",
            "Contoso"
        ]);

        // Act and assert
        Assert.Null(parameter.GetUnnamedParameter(2));
    }

    [Fact]
    public void GetUnnamedParameter_ReturnsExpectedNodeForArray()
    {
        // Arrange
        var parameter = new OpenIddictParameter(
        [
            "Fabrikam",
            "Contoso"
        ]);

        // Act and assert
        Assert.Equal("Fabrikam", (string?) parameter.GetUnnamedParameter(0));
    }

    [Fact]
    public void GetUnnamedParameter_ReturnsNullForOutOfRangeJsonArrayElementIndex()
    {
        // Arrange
        var parameter = new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"[""Fabrikam"",""Contoso""]"));

        // Act and assert
        Assert.Null(parameter.GetUnnamedParameter(2));
    }

    [Fact]
    public void GetUnnamedParameter_ReturnsNullForOutOfRangeJsonArrayNodeIndex()
    {
        // Arrange
        var parameter = new OpenIddictParameter(new JsonArray("Fabrikam", "Contoso"));

        // Act and assert
        Assert.Null(parameter.GetUnnamedParameter(2));
    }

    [Fact]
    public void GetUnnamedParameter_ReturnsNullForJsonObjectElements()
    {
        // Arrange
        var parameter = new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"{""parameter"":""value""}"));

        // Act and assert
        Assert.Null(parameter.GetUnnamedParameter(0));
    }

    [Fact]
    public void GetUnnamedParameter_ReturnsNullForJsonObjectNodes()
    {
        // Arrange
        var parameter = new OpenIddictParameter(new JsonObject
        {
            ["parameter"] = "value"
        });

        // Act and assert
        Assert.Null(parameter.GetUnnamedParameter(0));
    }

    [Fact]
    public void GetUnnamedParameter_ReturnsExpectedNodeForJsonArrayElements()
    {
        // Arrange
        var parameter = new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"[""Fabrikam"",""Contoso""]"));

        // Act and assert
        Assert.Equal("Fabrikam", (string?) parameter.GetUnnamedParameter(0));
    }

    [Fact]
    public void GetUnnamedParameter_ReturnsExpectedNodeForJsonArrayNodes()
    {
        // Arrange
        var parameter = new OpenIddictParameter(new JsonArray("Fabrikam", "Contoso"));

        // Act and assert
        Assert.Equal("Fabrikam", (string?) parameter.GetUnnamedParameter(0));
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
        ImmutableArray<string?> parameters = ["Fabrikam", "Contoso"];

        var parameter = new OpenIddictParameter(parameters);

        // Act and assert
        Assert.Empty(parameter.GetNamedParameters());
    }

    [Fact]
    public void GetNamedParameters_ReturnsEmptyDictionaryForJsonValueElements()
    {
        // Arrange
        var parameter = new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":42}").GetProperty("field"));

        // Act and assert
        Assert.Empty(parameter.GetNamedParameters());
    }

    [Fact]
    public void GetNamedParameters_ReturnsEmptyDictionaryForJsonValueNodes()
    {
        // Arrange
        var parameter = new OpenIddictParameter(JsonValue.Create(42));

        // Act and assert
        Assert.Empty(parameter.GetNamedParameters());
    }

    [Fact]
    public void GetNamedParameters_ReturnsEmptyDictionaryForJsonArrayElements()
    {
        // Arrange
        var parameter = new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"[""Fabrikam"",""Contoso""]"));

        // Act and assert
        Assert.Empty(parameter.GetNamedParameters());
    }

    [Fact]
    public void GetNamedParameters_ReturnsEmptyDictionaryForJsonArrayNodes()
    {
        // Arrange
        var parameter = new OpenIddictParameter(new JsonArray("Fabrikam", "Contoso"));

        // Act and assert
        Assert.Empty(parameter.GetNamedParameters());
    }

    [Fact]
    public void GetNamedParameters_ReturnsExpectedParametersForJsonObjectElements()
    {
        // Arrange
        var parameters = new Dictionary<string, string?>
        {
            ["parameter"] = "value"
        };

        var parameter = new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"{""parameter"":""value""}"));

        // Act and assert
        Assert.Equal(parameters, parameter.GetNamedParameters().ToDictionary(pair => pair.Key, pair => (string?) pair.Value));
    }

    [Fact]
    public void GetNamedParameters_ReturnsExpectedParametersForJsonObjectNodes()
    {
        // Arrange
        var parameters = new Dictionary<string, string?>
        {
            ["parameter"] = "value"
        };

        var parameter = new OpenIddictParameter(new JsonObject
        {
            ["parameter"] = "value"
        });

        // Act and assert
        Assert.Equal(parameters, parameter.GetNamedParameters().ToDictionary(pair => pair.Key, pair => (string?) pair.Value));
    }

    [Fact]
    public void GetNamedParameters_ReturnsLastOccurrenceOfMultipleElementParameters()
    {
        // Arrange
        var parameter = new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"{""parameter"":""value_1"",""parameter"":""value_2""}"));

        // Act and assert
        Assert.Equal("value_2", parameter.GetNamedParameters()["parameter"]);
    }

    [Fact]
    public void GetNamedParameters_ReturnsLastOccurrenceOfMultipleNodeParameters()
    {
        // Arrange
        var parameter = new OpenIddictParameter(new JsonObject
        {
            ["parameter"] = "value_1",
            ["parameter"] = "value_2"
        });

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
        ImmutableArray<string?> parameters = ["Fabrikam", "Contoso"];

        var parameter = new OpenIddictParameter(parameters);

        // Act and assert
        Assert.Equal(parameters, from element in parameter.GetUnnamedParameters()
                                 select (string?) element);
    }

    [Fact]
    public void GetUnnamedParameters_ReturnsEmptyListForJsonValueElements()
    {
        // Arrange
        var parameter = new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":42}").GetProperty("field"));

        // Act and assert
        Assert.Empty(parameter.GetUnnamedParameters());
    }

    [Fact]
    public void GetUnnamedParameters_ReturnsEmptyListForJsonValueNodes()
    {
        // Arrange
        var parameter = new OpenIddictParameter(JsonValue.Create(42));

        // Act and assert
        Assert.Empty(parameter.GetUnnamedParameters());
    }

    [Fact]
    public void GetUnnamedParameters_ReturnsExpectedParametersForJsonArrayElements()
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
                                 select (string?) element);
    }

    [Fact]
    public void GetUnnamedParameters_ReturnsExpectedParametersForJsonArrayNodes()
    {
        // Arrange
        var parameters = new[]
        {
            "Fabrikam",
            "Contoso"
        };

        var parameter = new OpenIddictParameter(new JsonArray("Fabrikam", "Contoso"));

        // Act and assert
        Assert.Equal(parameters, from element in parameter.GetUnnamedParameters()
                                 select (string?) element);
    }

    [Fact]
    public void GetUnnamedParameters_ReturnsEmptyListForJsonObjectElements()
    {
        // Arrange
        var parameter = new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"{""parameter"":""value""}"));

        // Act and assert
        Assert.Empty(parameter.GetUnnamedParameters());
    }

    [Fact]
    public void GetUnnamedParameters_ReturnsEmptyListForJsonObjectNodes()
    {
        // Arrange
        var parameter = new OpenIddictParameter(new JsonObject
        {
            ["parameter"] = "value"
        });

        // Act and assert
        Assert.Empty(parameter.GetUnnamedParameters());
    }

    [Fact]
    public void IsNullOrEmpty_ReturnsTrueForNullValues()
    {
        // Arrange, act and assert
        Assert.True(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter((bool?) null)));
        Assert.True(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter((long?) null)));
        Assert.True(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter((string?) null)));
        Assert.True(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter((ImmutableArray<string?>?) null)));
    }

    [Fact]
    public void IsNullOrEmpty_ReturnsTrueForUndefinedValues()
    {
        // Arrange, act and assert
        Assert.True(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter(default(JsonElement))));
        Assert.True(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter((JsonNode?) null)));
    }

    [Fact]
    public void IsNullOrEmpty_ReturnsTrueForEmptyValues()
    {
        // Arrange, act and assert
        Assert.True(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter(string.Empty)));
        Assert.True(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter([])));

        Assert.True(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>("[]"))));
        Assert.True(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>("{}"))));
        Assert.True(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":""""}").GetProperty("field"))));

        Assert.True(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter(new JsonArray())));
        Assert.True(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter(new JsonObject())));
        Assert.True(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter(JsonValue.Create(string.Empty))));

        Assert.True(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter(JsonValue.Create(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":""""}").GetProperty("field")))));
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
        Assert.False(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter(["Fabrikam"])));

        Assert.False(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"[""Fabrikam""]"))));
        Assert.False(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":""Fabrikam""}"))));
        Assert.False(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":""Fabrikam""}").GetProperty("field"))));

        Assert.False(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter(new JsonArray("Fabrikam"))));

        Assert.False(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter(new JsonObject
        {
            ["field"] = "Fabrikam"
        })));

        Assert.False(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter(JsonValue.Create(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":""Fabrikam""}").GetProperty("field")))));

        Assert.False(OpenIddictParameter.IsNullOrEmpty(new OpenIddictParameter(JsonValue.Create("Fabrikam"))));
    }

    [Fact]
    public void ToString_ReturnsEmptyStringForNullValues()
    {
        // Arrange
        var parameter = new OpenIddictParameter();

        // Act
        var result = parameter.ToString();

        // Assert
        Assert.NotNull(result);
        Assert.Empty(result);
    }

    [Fact]
    public void ToString_ReturnsBooleanValue()
    {
        // Arrange, act and assert
        Assert.Equal("true", new OpenIddictParameter(true).ToString());
        Assert.Equal("false", new OpenIddictParameter(false).ToString());
    }

    [Fact]
    public void ToString_ReturnsLongValue()
    {
        // Arrange
        var parameter = new OpenIddictParameter(42);

        // Act and assert
        Assert.Equal("42", parameter.ToString());
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
        var parameter = new OpenIddictParameter(
        [
            "Fabrikam",
            "Contoso"
        ]);

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
    public void ToString_ReturnsEmptyStringForNullJsonValueElements()
    {
        // Arrange
        var parameter = new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":null}").GetProperty("field"));

        // Act
        var result = parameter.ToString();

        // Assert
        Assert.NotNull(result);
        Assert.Empty(result);
    }

    [Fact]
    public void ToString_ReturnsEmptyStringForUndefinedJsonValueElements()
    {
        // Arrange
        var parameter = new OpenIddictParameter(default(JsonElement));

        // Act
        var result = parameter.ToString();

        // Assert
        Assert.NotNull(result);
        Assert.Empty(result);
    }

    [Fact]
    public void ToString_ReturnsEmptyStringForUndefinedJsonValueNodes()
    {
        // Arrange
        var parameter = new OpenIddictParameter((JsonNode?) null);

        // Act
        var result = parameter.ToString();

        // Assert
        Assert.NotNull(result);
        Assert.Empty(result);
    }

    [Fact]
    public void ToString_ReturnsUnderlyingJsonValue()
    {
        // Arrange, act and assert
        Assert.Equal("true", new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":true}").GetProperty("field")).ToString());
        Assert.Equal("false", new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":false}").GetProperty("field")).ToString());
        Assert.Equal("Fabrikam", new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":""Fabrikam""}").GetProperty("field")).ToString());
        Assert.Equal(@"[""Fabrikam"",""Contoso""]", new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":[""Fabrikam"",""Contoso""]}").GetProperty("field")).ToString());
        Assert.Equal(@"{""field"":""value""}", new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":""value""}")).ToString());

        Assert.Equal("true", new OpenIddictParameter(JsonValue.Create(true)).ToString());
        Assert.Equal("false", new OpenIddictParameter(JsonValue.Create(false)).ToString());
        Assert.Equal("Fabrikam", new OpenIddictParameter(JsonValue.Create("Fabrikam")).ToString());
        Assert.Equal(@"[""Fabrikam"",""Contoso""]", new OpenIddictParameter(new JsonArray("Fabrikam", "Contoso")).ToString());

        Assert.Equal(@"{""field"":""value""}", new OpenIddictParameter(new JsonObject
        {
            ["field"] = "value"
        }).ToString());

        Assert.Equal(@"{""field"":""value""}", new OpenIddictParameter(JsonValue.Create(new
        {
            field = "value"
        })).ToString());

        Assert.Equal("true", new OpenIddictParameter(JsonValue.Create(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":true}").GetProperty("field"))).ToString());
        Assert.Equal("false", new OpenIddictParameter(JsonValue.Create(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":false}").GetProperty("field"))).ToString());
        Assert.Equal("Fabrikam", new OpenIddictParameter(JsonValue.Create(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":""Fabrikam""}").GetProperty("field"))).ToString());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void TryGetNamedParameter_ThrowsAnExceptionForNullOrEmptyName(string? name)
    {
        // Arrange
        var parameter = new OpenIddictParameter();

        // Act
        var exception = Assert.Throws<ArgumentException>(() => parameter.TryGetNamedParameter(name!, out _));

        // Assert
        Assert.Equal("name", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0192), exception.Message);
    }

    [Fact]
    public void TryGetNamedParameter_ReturnsFalseForPrimitiveValues()
    {
        // Arrange
        var parameter = new OpenIddictParameter(42);

        // Act and assert
        Assert.False(parameter.TryGetNamedParameter("parameter", out var value));
        Assert.Equal(default, value);
    }

    [Fact]
    public void TryGetNamedParameter_ReturnsFalseForArrays()
    {
        // Arrange
        var parameter = new OpenIddictParameter(
        [
            "Fabrikam",
            "Contoso"
        ]);

        // Act and assert
        Assert.False(parameter.TryGetNamedParameter("Fabrikam", out var value));
        Assert.Equal(default, value);
    }

    [Fact]
    public void TryGetNamedParameter_ReturnsFalseForNonexistentItem()
    {
        // Arrange
        var parameter = new OpenIddictParameter(new JsonElement());

        // Act and assert
        Assert.False(parameter.TryGetNamedParameter("parameter", out var value));
        Assert.Equal(default, value);
    }

    [Fact]
    public void TryGetNamedParameter_ReturnsFalseForJsonArrayElements()
    {
        // Arrange
        var parameter = new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"[""Fabrikam"",""Contoso""]"));

        // Act and assert
        Assert.False(parameter.TryGetNamedParameter("Fabrikam", out var value));
        Assert.Equal(default, value);
    }

    [Fact]
    public void TryGetNamedParameter_ReturnsFalseForJsonArrayNodes()
    {
        // Arrange
        var parameter = new OpenIddictParameter(new JsonArray("Fabrikam", "Contoso"));

        // Act and assert
        Assert.False(parameter.TryGetNamedParameter("Fabrikam", out var value));
        Assert.Equal(default, value);
    }

    [Fact]
    public void TryGetNamedParameter_ReturnsExpectedParameterForJsonObjectElements()
    {
        // Arrange
        var parameter = new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"{""parameter"":""value""}"));

        // Act and assert
        Assert.True(parameter.TryGetNamedParameter("parameter", out var value));
        Assert.Equal("value", (string?) value);
    }

    [Fact]
    public void TryGetNamedParameter_ReturnsExpectedParameterForJsonObjectNodes()
    {
        // Arrange
        var parameter = new OpenIddictParameter(new JsonObject
        {
            ["parameter"] = "value"
        });

        // Act and assert
        Assert.True(parameter.TryGetNamedParameter("parameter", out var value));
        Assert.Equal("value", (string?) value);
    }

    [Fact]
    public void TryGetUnnamedParameter_ThrowsAnExceptionForNegativeIndex()
    {
        // Arrange
        var parameter = new OpenIddictParameter();

        // Act
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() => parameter.TryGetUnnamedParameter(-1, out _));

        // Assert
        Assert.Equal("index", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0193), exception.Message);
    }

    [Fact]
    public void TryGetUnnamedParameter_ReturnsFalseForPrimitiveValues()
    {
        // Arrange
        var parameter = new OpenIddictParameter(42);

        // Act and assert
        Assert.False(parameter.TryGetUnnamedParameter(0, out var value));
        Assert.Equal(default, value);
    }

    [Fact]
    public void GetParameter_ReturnsFalseForOutOfRangeArrayIndex()
    {
        // Arrange
        var parameter = new OpenIddictParameter(
        [
            "Fabrikam",
            "Contoso"
        ]);

        // Act and assert
        Assert.False(parameter.TryGetUnnamedParameter(2, out var value));
        Assert.Equal(default, value);
    }

    [Fact]
    public void TryGetUnnamedParameter_ReturnsExpectedNodeForArray()
    {
        // Arrange
        var parameter = new OpenIddictParameter(
        [
            "Fabrikam",
            "Contoso"
        ]);

        // Act and assert
        Assert.True(parameter.TryGetUnnamedParameter(0, out var value));
        Assert.Equal("Fabrikam", (string?) value);
    }

    [Fact]
    public void TryGetUnnamedParameter_ReturnsFalseForOutOfRangeJsonArrayElementIndex()
    {
        // Arrange
        var parameter = new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"[""Fabrikam"",""Contoso""]"));

        // Act and assert
        Assert.False(parameter.TryGetUnnamedParameter(2, out var value));
        Assert.Equal(default, value);
    }

    [Fact]
    public void TryGetUnnamedParameter_ReturnsFalseForOutOfRangeJsonArrayNodeIndex()
    {
        // Arrange
        var parameter = new OpenIddictParameter(new JsonArray("Fabrikam", "Contoso"));

        // Act and assert
        Assert.False(parameter.TryGetUnnamedParameter(2, out var value));
        Assert.Equal(default, value);
    }

    [Fact]
    public void TryGetUnnamedParameter_ReturnsFalseForJsonObjectElements()
    {
        // Arrange
        var parameter = new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"{""parameter"":""value""}"));

        // Act and assert
        Assert.False(parameter.TryGetUnnamedParameter(0, out var value));
        Assert.Equal(default, value);
    }

    [Fact]
    public void TryGetUnnamedParameter_ReturnsFalseForJsonObjectNodes()
    {
        // Arrange
        var parameter = new OpenIddictParameter(new JsonObject
        {
            ["parameter"] = "value"
        });

        // Act and assert
        Assert.False(parameter.TryGetUnnamedParameter(0, out var value));
        Assert.Equal(default, value);
    }

    [Fact]
    public void TryGetUnnamedParameter_ReturnsExpectedNodeForJsonArrayElements()
    {
        // Arrange
        var parameter = new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"[""Fabrikam"",""Contoso""]"));

        // Act and assert
        Assert.True(parameter.TryGetUnnamedParameter(0, out var value));
        Assert.Equal("Fabrikam", (string?) value);
    }

    [Fact]
    public void TryGetUnnamedParameter_ReturnsExpectedNodeForJsonArrayNodes()
    {
        // Arrange
        var parameter = new OpenIddictParameter(new JsonArray("Fabrikam", "Contoso"));

        // Act and assert
        Assert.True(parameter.TryGetUnnamedParameter(0, out var value));
        Assert.Equal("Fabrikam", (string?) value);
    }

    [Fact]
    public void WriteTo_ThrowsAnExceptionForNullWriter()
    {
        // Arrange
        var parameter = new OpenIddictParameter();

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => parameter.WriteTo(writer: null!));
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
        Assert.True((bool?) new OpenIddictParameter(true));
        Assert.True((bool?) new OpenIddictParameter((bool?) true));

        Assert.False((bool?) new OpenIddictParameter(false));
        Assert.False((bool?) new OpenIddictParameter((bool?) false));
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
        Assert.False((bool) new OpenIddictParameter(["Fabrikam", "Contoso"]));
        Assert.Null((bool?) new OpenIddictParameter(["Fabrikam", "Contoso"]));
    }

    [Fact]
    public void BoolConverter_ReturnsDefaultValueForUnsupportedJsonValues()
    {
        // Arrange, act and assert
        Assert.False((bool) new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>("[]")));
        Assert.Null((bool?) new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>("[]")));
        Assert.False((bool) new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>("{}")));
        Assert.Null((bool?) new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>("{}")));
        Assert.False((bool) new OpenIddictParameter(new JsonObject()));
        Assert.Null((bool?) new OpenIddictParameter(new JsonObject()));
        Assert.False((bool) new OpenIddictParameter(new JsonArray()));
        Assert.Null((bool?) new OpenIddictParameter(new JsonArray()));
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

        Assert.True((bool) new OpenIddictParameter(JsonValue.Create(true)));
        Assert.True((bool?) new OpenIddictParameter(JsonValue.Create(true)));
        Assert.True((bool) new OpenIddictParameter(JsonValue.Create("true")));
        Assert.True((bool?) new OpenIddictParameter(JsonValue.Create("true")));

        Assert.False((bool) new OpenIddictParameter(JsonValue.Create(false)));
        Assert.False((bool?) new OpenIddictParameter(JsonValue.Create(false)));
        Assert.False((bool) new OpenIddictParameter(JsonValue.Create("false")));
        Assert.False((bool?) new OpenIddictParameter(JsonValue.Create("false")));

        Assert.True((bool) new OpenIddictParameter(JsonValue.Create(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":true}").GetProperty("field"))));
        Assert.True((bool?) new OpenIddictParameter(JsonValue.Create(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":true}").GetProperty("field"))));
        Assert.True((bool) new OpenIddictParameter(JsonValue.Create(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":""true""}").GetProperty("field"))));
        Assert.True((bool?) new OpenIddictParameter(JsonValue.Create(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":""true""}").GetProperty("field"))));

        Assert.False((bool) new OpenIddictParameter(JsonValue.Create(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":false}").GetProperty("field"))));
        Assert.False((bool?) new OpenIddictParameter(JsonValue.Create(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":false}").GetProperty("field"))));
        Assert.False((bool) new OpenIddictParameter(JsonValue.Create(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":""false""}").GetProperty("field"))));
        Assert.False((bool?) new OpenIddictParameter(JsonValue.Create(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":""false""}").GetProperty("field"))));
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
    public void JsonElementConverter_CanConvertFromPrimitiveValues()
    {
        // Arrange, act and assert
        Assert.Equal(JsonValueKind.True, ((JsonElement) new OpenIddictParameter(true)).ValueKind);
        Assert.True(((JsonElement) new OpenIddictParameter(true)).GetBoolean());

        Assert.Equal(JsonValueKind.Number, ((JsonElement) new OpenIddictParameter(42)).ValueKind);
        Assert.Equal(42L, ((JsonElement) new OpenIddictParameter(42)).GetInt64());

        Assert.Equal(JsonValueKind.String, ((JsonElement) new OpenIddictParameter(string.Empty)).ValueKind);
        Assert.Empty(((JsonElement) new OpenIddictParameter(string.Empty)).GetString()!);

        Assert.Equal(JsonValueKind.String, ((JsonElement) new OpenIddictParameter("value")).ValueKind);
        Assert.Equal("value", ((JsonElement) new OpenIddictParameter("value")).GetString());

        Assert.Equal(JsonValueKind.String, ((JsonElement) new OpenIddictParameter("true")).ValueKind);
        Assert.Equal("true", ((JsonElement) new OpenIddictParameter("true")).GetString());

        Assert.Equal(JsonValueKind.String, ((JsonElement) new OpenIddictParameter("42")).ValueKind);
        Assert.Equal("42", ((JsonElement) new OpenIddictParameter("42")).GetString());

        Assert.Equal(JsonValueKind.String, ((JsonElement) new OpenIddictParameter("{abc}")).ValueKind);
        Assert.Equal("{abc}", ((JsonElement) new OpenIddictParameter("{abc}")).GetString());

        Assert.Equal(JsonValueKind.String, ((JsonElement) new OpenIddictParameter("[abc]")).ValueKind);
        Assert.Equal("[abc]", ((JsonElement) new OpenIddictParameter("[abc]")).GetString());
    }

    [Fact]
    public void JsonElementConverter_CanConvertFromArrays()
    {
        // Arrange and act
        var array = (JsonElement) new OpenIddictParameter(["Contoso", "Fabrikam"]);

        // Assert
        Assert.Equal(2, array.GetArrayLength());
        Assert.Equal("Contoso", array[0].GetString());
        Assert.Equal("Fabrikam", array[1].GetString());
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
    public void JsonNodeConverter_ReturnsDefaultValueForNullValues()
    {
        // Arrange, act and assert
        Assert.Null((JsonNode?) new OpenIddictParameter());
        Assert.Null((JsonNode?) (OpenIddictParameter?) null);
    }

    [Fact]
    public void JsonNodeConverter_CanConvertFromJsonValues()
    {
        // Arrange and act
        var array = (JsonNode?) new OpenIddictParameter(new JsonArray("Contoso", "Fabrikam"));
        var dictionary = (JsonNode?) new OpenIddictParameter(new JsonObject
        {
            ["Property"] = "value"
        });

        // Assert
        Assert.Equal("Contoso", array!.AsArray()[0]!.GetValue<string>());
        Assert.Equal("Fabrikam", array!.AsArray()[1]!.GetValue<string>());
        Assert.Equal("value", dictionary!.AsObject()["Property"]!.GetValue<string>());

        Assert.True(((JsonNode?) new OpenIddictParameter(JsonValue.Create(true)))!.GetValue<bool>());
        Assert.Equal(42, ((JsonNode?) new OpenIddictParameter(JsonValue.Create(42)))!.GetValue<int>());
        Assert.Equal("Fabrikam", ((JsonNode?) new OpenIddictParameter(JsonValue.Create("Fabrikam")))!.GetValue<string>());

        Assert.True(((JsonElement) new OpenIddictParameter(JsonValue.Create(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":true}").GetProperty("field")))).GetBoolean());

        Assert.Equal(42, ((JsonElement) new OpenIddictParameter(JsonValue.Create(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":42}").GetProperty("field")))).GetInt64());

        Assert.Equal("Fabrikam", ((JsonElement) new OpenIddictParameter(JsonValue.Create(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":""Fabrikam""}").GetProperty("field")))).GetString());
    }

    [Fact]
    public void JsonNodeConverter_CanConvertFromSerializedJson()
    {
        // Arrange and act
        var array = (JsonNode?) new OpenIddictParameter(@"[""Contoso"",""Fabrikam""]");
        var dictionary = (JsonNode?) new OpenIddictParameter(@"{""Property"":""value""}");

        // Assert
        Assert.Equal("Contoso", array!.AsArray()[0]!.GetValue<string>());
        Assert.Equal("Fabrikam", array!.AsArray()[1]!.GetValue<string>());
        Assert.Equal("value", dictionary!.AsObject()["Property"]!.GetValue<string>());
    }

    [Fact]
    public void JsonNodeConverter_CanConvertFromArrays()
    {
        // Arrange and act
        var array = (JsonNode?) new OpenIddictParameter(["Contoso", "Fabrikam"]);

        // Assert
        Assert.Equal("Contoso", array!.AsArray()[0]!.GetValue<string>());
        Assert.Equal("Fabrikam", array!.AsArray()[1]!.GetValue<string>());
    }

    [Fact]
    public void JsonArrayConverter_ReturnsDefaultValueForNullValues()
    {
        // Arrange, act and assert
        Assert.Null((JsonArray?) new OpenIddictParameter());
        Assert.Null((JsonArray?) (OpenIddictParameter?) null);
    }

    [Fact]
    public void JsonArrayConverter_CanConvertFromJsonArrays()
    {
        // Arrange and act
        var array = (JsonArray?) new OpenIddictParameter(new JsonArray("Contoso", "Fabrikam"));

        // Assert
        Assert.Equal("Contoso", array![0]!.GetValue<string>());
        Assert.Equal("Fabrikam", array![1]!.GetValue<string>());
    }

    [Fact]
    public void JsonArrayConverter_CanConvertFromSerializedJson()
    {
        // Arrange and act
        var array = (JsonArray?) new OpenIddictParameter(@"[""Contoso"",""Fabrikam""]");

        // Assert
        Assert.Equal("Contoso", array![0]!.GetValue<string>());
        Assert.Equal("Fabrikam", array![1]!.GetValue<string>());
    }

    [Fact]
    public void JsonArrayConverter_CanConvertFromArrays()
    {
        // Arrange and act
        var array = (JsonArray?) new OpenIddictParameter(["Contoso", "Fabrikam"]);

        // Assert
        Assert.Equal("Contoso", array![0]!.GetValue<string>());
        Assert.Equal("Fabrikam", array![1]!.GetValue<string>());
    }

    [Fact]
    public void JsonArrayConverter_ReturnsDefaultValueForUnsupportedJsonValues()
    {
        // Assert, arrange and act
        Assert.Null((JsonArray?) new OpenIddictParameter(@"{""Property"":""value""}"));
        Assert.Null((JsonArray?) new OpenIddictParameter(new JsonObject
        {
            ["Property"] = "value"
        }));
    }

    [Fact]
    public void JsonObjectConverter_ReturnsDefaultValueForNullValues()
    {
        // Arrange, act and assert
        Assert.Null((JsonObject?) new OpenIddictParameter());
        Assert.Null((JsonObject?) (OpenIddictParameter?) null);
    }

    [Fact]
    public void JsonObjectConverter_CanConvertFromJsonValues()
    {
        // Arrange and act
        var dictionary = (JsonObject?) new OpenIddictParameter(new JsonObject
        {
            ["Property"] = "value"
        });

        // Assert
        Assert.Equal("value", dictionary!.AsObject()["Property"]!.GetValue<string>());
    }

    [Fact]
    public void JsonObjectConverter_CanConvertFromSerializedJson()
    {
        // Arrange and act
        var dictionary = (JsonObject?) new OpenIddictParameter(@"{""Property"":""value""}");

        // Assert
        Assert.Equal("value", dictionary!.AsObject()["Property"]!.GetValue<string>());
    }

    [Fact]
    public void JsonObjectConverter_ReturnsDefaultValueForUnsupportedJsonValues()
    {
        // Assert, arrange and act
        Assert.Null((JsonObject?) new OpenIddictParameter(@"[""Contoso"",""Fabrikam""]"));
        Assert.Null((JsonObject?) new OpenIddictParameter(["Contoso", "Fabrikam"]));
    }

    [Fact]
    public void JsonValueConverter_ReturnsDefaultValueForNullValues()
    {
        // Arrange, act and assert
        Assert.Null((JsonValue?) new OpenIddictParameter());
        Assert.Null((JsonValue?) (OpenIddictParameter?) null);
    }

    [Fact]
    public void JsonValueConverter_CanConvertFromPrimitiveValues()
    {
        // Arrange, act and assert
        Assert.True(((JsonValue?) new OpenIddictParameter(JsonValue.Create(true)))!.GetValue<bool>());
        Assert.Equal(42, ((JsonValue?) new OpenIddictParameter(JsonValue.Create(42)))!.GetValue<int>());
        Assert.Equal(42L, ((JsonValue?) new OpenIddictParameter(JsonValue.Create(42L)))!.GetValue<long>());
        Assert.Equal("value", ((JsonValue?) new OpenIddictParameter(JsonValue.Create("value")))!.GetValue<string>());
    }

    [Fact]
    public void JsonValueConverter_ReturnsDefaultValueForUnsupportedJsonValues()
    {
        // Assert, arrange and act
        Assert.Null((JsonValue?) new OpenIddictParameter(@"[""Contoso"",""Fabrikam""]"));
        Assert.Null((JsonValue?) new OpenIddictParameter(["Contoso", "Fabrikam"]));

        Assert.Null((JsonValue?) new OpenIddictParameter(@"{""Property"":""value""}"));

        Assert.Null((JsonValue?) new OpenIddictParameter(new JsonObject
        {
            ["Property"] = "value"
        }));
    }

    [Fact]
    public void LongConverter_CanCreateParameterFromLongValue()
    {
        // Arrange, act and assert
        Assert.Equal(42, (long?) new OpenIddictParameter(42));
        Assert.Equal(42, (long?) new OpenIddictParameter((long?) 42));
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
        Assert.Equal(0, (long) new OpenIddictParameter(["Contoso", "Fabrikam"]));
        Assert.Null((long?) new OpenIddictParameter(["Contoso", "Fabrikam"]));
    }

    [Fact]
    public void LongConverter_ReturnsDefaultValueForUnsupportedJsonValues()
    {
        // Arrange, act and assert
        Assert.Equal(0, (long) new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>("[]")));
        Assert.Null((long?) new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>("[]")));
        Assert.Equal(0, (long) new OpenIddictParameter(new JsonArray()));
        Assert.Null((long?) new OpenIddictParameter(new JsonArray()));
    }

    [Fact]
    public void LongConverter_CanConvertFromPrimitiveValues()
    {
        // Arrange, act and assert
        Assert.Equal(42, (long?) new OpenIddictParameter(42));
        Assert.Equal(42, (long?) new OpenIddictParameter(42));
        Assert.Equal(42, (long?) new OpenIddictParameter(42));
        Assert.Equal(42, (long?) new OpenIddictParameter(42));
    }

    [Fact]
    public void LongConverter_CanConvertFromJsonValues()
    {
        // Arrange, act and assert
        Assert.Equal(42, (long?) new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":42}").GetProperty("field")));
        Assert.Equal(42, (long?) new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":42}").GetProperty("field")));

        Assert.Equal(42, (long?) new OpenIddictParameter(JsonValue.Create(42)));
        Assert.Equal(42, (long?) new OpenIddictParameter(JsonValue.Create(42)));
        Assert.Equal(42, (long?) new OpenIddictParameter(JsonValue.Create(42L)));
        Assert.Equal(42, (long?) new OpenIddictParameter(JsonValue.Create(42L)));

        Assert.Equal(42, (long?) new OpenIddictParameter(JsonValue.Create(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":42}").GetProperty("field"))));
        Assert.Equal(42, (long?) new OpenIddictParameter(JsonValue.Create(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":42}").GetProperty("field"))));
    }

    [Fact]
    public void StringConverter_CanCreateParameterFromStringValue()
    {
        // Arrange, act and assert
        Assert.Equal("Fabrikam", (string?) new OpenIddictParameter("Fabrikam"));
    }

    [Fact]
    public void StringConverter_ReturnsDefaultValueForNullValues()
    {
        // Arrange, act and assert
        Assert.Null((string?) new OpenIddictParameter());
        Assert.Null((string?) (OpenIddictParameter?) null);
    }

    [Fact]
    public void StringConverter_ReturnsDefaultValueForArrays()
    {
        // Arrange, act and assert
        Assert.Null((string?) new OpenIddictParameter(["Contoso", "Fabrikam"]));
    }

    [Fact]
    public void StringConverter_ReturnsDefaultValueForUnsupportedJsonValues()
    {
        // Arrange, act and assert
        Assert.Null((string?) new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"[""Contoso"",""Fabrikam""]")));
        Assert.Null((string?) new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":""Fabrikam""}")));

        Assert.Null((string?) new OpenIddictParameter(new JsonArray("Contoso", "Fabrikam")));
        Assert.Null((string?) new OpenIddictParameter(new JsonObject
        {
            ["field"] = "Fabrikam"
        }));
    }

    [Fact]
    public void StringConverter_CanConvertFromPrimitiveValues()
    {
        // Arrange, act and assert
        Assert.Equal("Fabrikam", (string?) new OpenIddictParameter("Fabrikam"));
        Assert.Equal("false", (string?) new OpenIddictParameter(false));
        Assert.Equal("42", (string?) new OpenIddictParameter(42));
    }

    [Fact]
    public void StringConverter_CanConvertFromJsonValues()
    {
        // Arrange, act and assert
        Assert.Equal("Fabrikam", (string?) new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":""Fabrikam""}").GetProperty("field")));
        Assert.Equal("false", (string?) new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":false}").GetProperty("field")));
        Assert.Equal("42", (string?) new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":42}").GetProperty("field")));

        Assert.Equal("Fabrikam", (string?) new OpenIddictParameter(JsonValue.Create("Fabrikam")));
        Assert.Equal("false", (string?) new OpenIddictParameter(JsonValue.Create(false)));
        Assert.Equal("42", (string?) new OpenIddictParameter(JsonValue.Create(42)));
        Assert.Equal("42", (string?) new OpenIddictParameter(JsonValue.Create(42L)));

        Assert.Equal("Fabrikam", (string?) new OpenIddictParameter(JsonValue.Create(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":""Fabrikam""}").GetProperty("field"))));
        Assert.Equal("false", (string?) new OpenIddictParameter(JsonValue.Create(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":false}").GetProperty("field"))));
        Assert.Equal("42", (string?) new OpenIddictParameter(JsonValue.Create(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":42}").GetProperty("field"))));
    }

    [Fact]
    public void StringArrayConverter_CanCreateParameterFromArray()
    {
        // Arrange
        string?[] array = ["Fabrikam", "Contoso"];

        // Act
        var parameter = new OpenIddictParameter([.. array]);

        // Assert
        Assert.Equal<IEnumerable<string?>?>(array, (ImmutableArray<string?>?) parameter);
    }

    [Fact]
    public void StringArrayConverter_CanCreateParameterFromPrimitiveValues()
    {
        // Arrange, act and assert
        Assert.Equal<IEnumerable<string?>?>(["Fabrikam"], (ImmutableArray<string?>?) new OpenIddictParameter("Fabrikam"));
        Assert.Equal<IEnumerable<string?>?>(["false"], (ImmutableArray<string?>?) new OpenIddictParameter(false));
        Assert.Equal<IEnumerable<string?>?>(["42"], (ImmutableArray<string?>?) new OpenIddictParameter(42));
    }

    [Fact]
    public void StringArrayConverter_ReturnsDefaultValueForNullValues()
    {
        // Arrange, act and assert
        Assert.Null((ImmutableArray<string?>?) new OpenIddictParameter());
    }

    [Fact]
    public void StringArrayConverter_ReturnsSingleElementArrayForStringValue()
    {
        // Arrange, act and assert
        Assert.Equal<IEnumerable<string?>?>(["Fabrikam"], (ImmutableArray<string?>?) new OpenIddictParameter("Fabrikam"));
    }

    [Fact]
    public void StringArrayConverter_ReturnsDefaultValueForUnsupportedJsonValues()
    {
        // Arrange, act and assert
        Assert.Empty((ImmutableArray<string?>) new OpenIddictParameter(new JsonElement()));
        Assert.Null((ImmutableArray<string?>?) new OpenIddictParameter(new JsonElement()));

        Assert.Empty((ImmutableArray<string?>) new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"[""value"",[]]")));
        Assert.Null((ImmutableArray<string?>?) new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"[""value"",[]]")));

        Assert.Empty((ImmutableArray<string?>) new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"[""value"",{}]")));
        Assert.Null((ImmutableArray<string?>?) new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"[""value"",{}]")));

        Assert.Empty((ImmutableArray<string?>) new OpenIddictParameter((JsonNode?) null));
        Assert.Null((ImmutableArray<string?>?) new OpenIddictParameter((JsonNode?) null));

        Assert.Empty((ImmutableArray<string?>) new OpenIddictParameter(new JsonArray("value", new JsonArray())));
        Assert.Null((ImmutableArray<string?>?) new OpenIddictParameter(new JsonArray("value", new JsonArray())));

        Assert.Empty((ImmutableArray<string?>) new OpenIddictParameter(new JsonArray("value", new JsonObject())));
        Assert.Null((ImmutableArray<string?>?) new OpenIddictParameter(new JsonArray("value", new JsonObject())));
    }

    [Fact]
    public void StringArrayConverter_CanConvertFromJsonValues()
    {
        // Arrange, act and assert
        Assert.Equal<IEnumerable<string?>?>(["Fabrikam"], (ImmutableArray<string?>?) new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":""Fabrikam""}").GetProperty("field")));
        Assert.Equal<IEnumerable<string?>?>(["false"], (ImmutableArray<string?>?) new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":false}").GetProperty("field")));
        Assert.Equal<IEnumerable<string?>?>(["42"], (ImmutableArray<string?>?) new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":42}").GetProperty("field")));
        Assert.Equal<IEnumerable<string?>?>(["Fabrikam"], (ImmutableArray<string?>?) new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"[""Fabrikam""]")));
        Assert.Equal<IEnumerable<string?>?>(["Contoso", "Fabrikam"], (ImmutableArray<string?>?) new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"[""Contoso"",""Fabrikam""]")));
        Assert.Equal<IEnumerable<string?>?>(["value", "42", "true"], (ImmutableArray<string?>?) new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"[""value"",42,true]")));

        Assert.Equal<IEnumerable<string?>?>(["Fabrikam"], (ImmutableArray<string?>?) new OpenIddictParameter(JsonValue.Create("Fabrikam")));
        Assert.Equal<IEnumerable<string?>?>(["false"], (ImmutableArray<string?>?) new OpenIddictParameter(JsonValue.Create(false)));
        Assert.Equal<IEnumerable<string?>?>(["42"], (ImmutableArray<string?>?) new OpenIddictParameter(JsonValue.Create(42)));
        Assert.Equal<IEnumerable<string?>?>(["42"], (ImmutableArray<string?>?) new OpenIddictParameter(JsonValue.Create(42L)));
        Assert.Equal<IEnumerable<string?>?>(["Fabrikam"], (ImmutableArray<string?>?) new OpenIddictParameter(new JsonArray("Fabrikam")));
        Assert.Equal<IEnumerable<string?>?>(["Contoso", "Fabrikam"], (ImmutableArray<string?>?) new OpenIddictParameter(new JsonArray("Contoso", "Fabrikam")));
        Assert.Equal<IEnumerable<string?>?>(["value", "42", "true"], (ImmutableArray<string?>?) new OpenIddictParameter(new JsonArray("value", 42, true)));
    }

    [Fact]
    public void StringValuesConverter_CanCreateParameterFromArray()
    {
        // Arrange
        string?[] array = ["Fabrikam", "Contoso"];

        // Act
        var parameter = new OpenIddictParameter([.. array]);

        // Assert
        Assert.Equal<IEnumerable<string?>?>(array, (StringValues?) parameter);
    }

    [Fact]
    public void StringValuesConverter_CanCreateParameterFromPrimitiveValues()
    {
        // Arrange, act and assert
        Assert.Equal<IEnumerable<string?>?>(["Fabrikam"], (StringValues?) new OpenIddictParameter("Fabrikam"));
        Assert.Equal<IEnumerable<string?>?>(["false"], (StringValues?) new OpenIddictParameter(false));
        Assert.Equal<IEnumerable<string?>?>(["42"], (StringValues?) new OpenIddictParameter(42));
    }

    [Fact]
    public void StringValuesConverter_ReturnsDefaultValueForNullValues()
    {
        // Arrange, act and assert
        Assert.Null((StringValues?) new OpenIddictParameter());
    }

    [Fact]
    public void StringValuesConverter_ReturnsSingleElementArrayForStringValue()
    {
        // Arrange, act and assert
        Assert.Equal<IEnumerable<string?>?>(["Fabrikam"], (StringValues?) new OpenIddictParameter("Fabrikam"));
    }

    [Fact]
    public void StringValuesConverter_ReturnsDefaultValueForUnsupportedJsonValues()
    {
        // Arrange, act and assert
        Assert.Null((StringValues?) new OpenIddictParameter(new JsonElement()));
        Assert.Null((StringValues?) new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"[""value"",[]]")));

        Assert.Null((StringValues?) new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"[""value"",{}]")));

        Assert.Null((StringValues?) new OpenIddictParameter((JsonNode?) null));
        Assert.Null((StringValues?) new OpenIddictParameter(new JsonArray("value", new JsonArray())));
        Assert.Null((StringValues?) new OpenIddictParameter(new JsonArray("value", new JsonObject())));
    }

    [Fact]
    public void StringValuesConverter_CanConvertFromJsonValues()
    {
        // Arrange, act and assert
        Assert.Equal<IEnumerable<string?>?>(["Fabrikam"], (StringValues?) new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":""Fabrikam""}").GetProperty("field")));
        Assert.Equal<IEnumerable<string?>?>(["false"], (StringValues?) new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":false}").GetProperty("field")));
        Assert.Equal<IEnumerable<string?>?>(["42"], (StringValues?) new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"{""field"":42}").GetProperty("field")));
        Assert.Equal<IEnumerable<string?>?>(["Fabrikam"], (StringValues?) new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"[""Fabrikam""]")));
        Assert.Equal<IEnumerable<string?>?>(["Contoso", "Fabrikam"], (StringValues?) new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"[""Contoso"",""Fabrikam""]")));
        Assert.Equal<IEnumerable<string?>?>(["value", "42", "true"], (StringValues?) new OpenIddictParameter(
            JsonSerializer.Deserialize<JsonElement>(@"[""value"",42,true]")));

        Assert.Equal<IEnumerable<string?>?>(["Fabrikam"], (StringValues?) new OpenIddictParameter(JsonValue.Create("Fabrikam")));
        Assert.Equal<IEnumerable<string?>?>(["false"], (StringValues?) new OpenIddictParameter(JsonValue.Create(false)));
        Assert.Equal<IEnumerable<string?>?>(["42"], (StringValues?) new OpenIddictParameter(JsonValue.Create(42)));
        Assert.Equal<IEnumerable<string?>?>(["42"], (StringValues?) new OpenIddictParameter(JsonValue.Create(42L)));
        Assert.Equal<IEnumerable<string?>?>(["Fabrikam"], (StringValues?) new OpenIddictParameter(new JsonArray("Fabrikam")));
        Assert.Equal<IEnumerable<string?>?>(["Contoso", "Fabrikam"], (StringValues?) new OpenIddictParameter(new JsonArray("Contoso", "Fabrikam")));
        Assert.Equal<IEnumerable<string?>?>(["value", "42", "true"], (StringValues?) new OpenIddictParameter(new JsonArray("value", 42, true)));
    }
}
