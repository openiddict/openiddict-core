/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Primitives;
using OpenIddict.Extensions;

namespace OpenIddict.Abstractions;

/// <summary>
/// Represents an OpenIddict parameter value and provides two-way conversion operators that allow
/// representing it as a primitive value, an immutable array of strings or a JSON element or node.
/// </summary>
public readonly struct OpenIddictParameter : IEquatable<OpenIddictParameter>
{
    private readonly object? _value;

    /// <summary>
    /// Initializes a new parameter using the specified value.
    /// </summary>
    /// <param name="value">The parameter value.</param>
    public OpenIddictParameter(bool value) => _value = value;

    /// <summary>
    /// Initializes a new parameter using the specified value.
    /// </summary>
    /// <param name="value">The parameter value.</param>
    public OpenIddictParameter(bool? value) => _value = value;

    /// <summary>
    /// Initializes a new parameter using the specified value.
    /// </summary>
    /// <param name="value">The parameter value.</param>
    public OpenIddictParameter(JsonElement value) => _value = value;

    /// <summary>
    /// Initializes a new parameter using the specified value.
    /// </summary>
    /// <param name="value">The parameter value.</param>
    public OpenIddictParameter(JsonNode? value) => _value = value switch
    {
        // Clone the node to ensure the stored value cannot be mutated.
        JsonNode node => node.DeepClone(),

        null => null
    };

    /// <summary>
    /// Initializes a new parameter using the specified value.
    /// </summary>
    /// <param name="value">The parameter value.</param>
    public OpenIddictParameter(long value) => _value = value;

    /// <summary>
    /// Initializes a new parameter using the specified value.
    /// </summary>
    /// <param name="value">The parameter value.</param>
    public OpenIddictParameter(long? value) => _value = value;

    /// <summary>
    /// Initializes a new parameter using the specified value.
    /// </summary>
    /// <param name="value">The parameter value.</param>
    public OpenIddictParameter(string? value) => _value = value;

    /// <summary>
    /// Initializes a new parameter using the specified value.
    /// </summary>
    /// <param name="value">The parameter value.</param>
    public OpenIddictParameter(ImmutableArray<string?> value)
        // Note: to avoid boxing, the underlying array is directly stored as the backing value.
        => _value = ImmutableCollectionsMarshal.AsArray(value);

    /// <summary>
    /// Initializes a new parameter using the specified value.
    /// </summary>
    /// <param name="value">The parameter value.</param>
    public OpenIddictParameter(ImmutableArray<string?>? value) => _value = value switch
    {
        // Note: to avoid boxing, the underlying array is directly stored as the backing value.
        ImmutableArray<string?> array => ImmutableCollectionsMarshal.AsArray(array),

        null => null
    };

    /// <summary>
    /// Gets the child item corresponding to the specified index.
    /// </summary>
    /// <param name="index">The index of the child item.</param>
    /// <returns>An <see cref="OpenIddictParameter"/> instance containing the item value.</returns>
    public OpenIddictParameter? this[int index] => GetUnnamedParameter(index);

    /// <summary>
    /// Gets the child item corresponding to the specified name.
    /// </summary>
    /// <param name="name">The name of the child item.</param>
    /// <returns>An <see cref="OpenIddictParameter"/> instance containing the item value.</returns>
    public OpenIddictParameter? this[string name] => GetNamedParameter(name);

    /// <summary>
    /// Gets the number of named or unnamed child items contained in the current parameter or 0
    /// if the parameter doesn't represent an array of strings, a JSON array or a JSON object.
    /// </summary>
    public int Count
    {
        get
        {
            return _value switch
            {
                // If the parameter is an array of strings, return its length.
                string?[] value => value.Length,

                // If the parameter is a JSON array or a JSON object, return its length.
                JsonElement { ValueKind: JsonValueKind.Array or JsonValueKind.Object } element
                    => Count(element),

                // If the parameter is a JsonArray, return its length.
                JsonArray value => value.Count,

                // If the parameter is a JsonObject, return its length.
                JsonObject value => value.Count,

                // If the parameter is a JsonValue wrapping a JsonElement,
                // apply the same logic as with direct JsonElement instances.
                JsonValue value when value.TryGetValue(out JsonElement element)
                    => element.ValueKind is JsonValueKind.Array or JsonValueKind.Object ? Count(element) : 0,

                // If the parameter is a JsonValue wrapping a well-known primitive type
                // (e.g int or string), always return 0 as these types can't have a length.
                JsonValue value when value.TryGetValue(out bool    _) ||
                                     value.TryGetValue(out int     _) ||
                                     value.TryGetValue(out long    _) ||
                                     value.TryGetValue(out string? _) => 0,

                // If the parameter is any other JsonNode (e.g a JsonValue), serialize it
                // to a JsonElement first to determine its actual JSON representation
                // and extract the number of items if the element is a JSON array or object.
                JsonNode value when JsonSerializer.SerializeToElement(value, OpenIddictSerializer.Default.JsonNode)
                    is JsonElement { ValueKind: JsonValueKind.Array or JsonValueKind.Object } element
                    => Count(element),

                // Otherwise, return 0.
                _ => 0
            };

            static int Count(JsonElement element)
            {
                switch (element.ValueKind)
                {
                    case JsonValueKind.Array:
                        return element.GetArrayLength();

                    case JsonValueKind.Object:
#if SUPPORTS_JSON_ELEMENT_PROPERTY_COUNT
                        return element.GetPropertyCount();
#else
                        var count = 0;

                        using (var enumerator = element.EnumerateObject())
                        {
                            checked
                            {
                                while (enumerator.MoveNext())
                                {
                                    count++;
                                }
                            }
                        }

                        return count;
#endif

                    default: return 0;
                }
            }
        }
    }

    /// <summary>
    /// Gets the associated raw value, that can be either a primitive CLR type
    /// (e.g bool, string, long), an immutable array of strings or a complex JSON object.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public object? GetRawValue() => _value switch
    {
        // If the value is backed by an array of strings or a JSON node, return a copy instead of the
        // real instance to ensure mutations made on the returned object don't affect the stored array.
        string?[] array => ImmutableArray.Create(array),
        JsonNode node   => node.DeepClone(),

        object value => value,
        null         => null
    };

    /// <summary>
    /// Determines whether the current <see cref="OpenIddictParameter"/>
    /// instance is equal to the specified <see cref="OpenIddictParameter"/>.
    /// </summary>
    /// <param name="other">The other object to which to compare this instance.</param>
    /// <returns>
    /// <see langword="true"/> if the two instances have both the same representation
    /// (e.g <see cref="string"/>) and value, <see langword="false"/> otherwise.
    /// </returns>
    public bool Equals(OpenIddictParameter other)
    {
        return (_value, other._value) switch
        {
            // If the two parameters reference the same instance, return true.
            //
            // Note: true will also be returned if the two parameters are null.
            var (left, right) when ReferenceEquals(left, right) => true,

            // If one of the two parameters is null, return false.
            (null, _) or (_, null) => false,

            // If the two parameters are booleans, compare them directly.
            (bool left, bool right) => left == right,

            // If the two parameters are integers, compare them directly.
            (long left, long right) => left == right,

            // If the two parameters are strings, use string.Equals().
            (string left, string right) => string.Equals(left, right, StringComparison.Ordinal),

            // If the two parameters are string arrays, use SequenceEqual().
            (string?[] left, string?[] right) => Enumerable.SequenceEqual(left, right),

            // If one of the two parameters is an undefined JsonElement, treat it
            // as a null value and return true if the other parameter is null too.
            (JsonElement { ValueKind: JsonValueKind.Null or JsonValueKind.Undefined }, var right)
                => right is null,

            (var left, JsonElement { ValueKind: JsonValueKind.Null or JsonValueKind.Undefined })
                => left is null,

            // If the two parameters are JsonElement instances, use the custom comparer.
            (JsonElement left, JsonElement right) => DeepEquals(left, right),

            // If the two parameters are JsonNode instances, use JsonNode.DeepEquals().
            (JsonNode left, JsonNode right) => JsonNode.DeepEquals(left, right),

            // When one of the parameters is a JsonElement, compare their underlying values.
            (JsonElement { ValueKind: JsonValueKind.True }, bool right) => right,
            (bool left, JsonElement { ValueKind: JsonValueKind.True })  => left,

            (JsonElement { ValueKind: JsonValueKind.False }, bool right) => !right,
            (bool left, JsonElement { ValueKind: JsonValueKind.False })  => !left,

            (JsonElement { ValueKind: JsonValueKind.Number } left, long right)
                when left.TryGetInt64(out var result) => result == right,

            (long left, JsonElement { ValueKind: JsonValueKind.Number } right)
                when right.TryGetInt64(out var result) => left == result,

            (JsonElement { ValueKind: JsonValueKind.String } left, string right)
                => string.Equals(left.GetString(), right, StringComparison.Ordinal),

            (string left, JsonElement { ValueKind: JsonValueKind.String } right)
                => string.Equals(left, right.GetString(), StringComparison.Ordinal),

            // When one of the parameters is a JsonValue, try to compare their underlying values
            // if the wrapped type is a common CLR primitive type to avoid the less efficient
            // JsonElement-based comparison, that requires doing a full JSON serialization.
            (JsonValue left, bool right) when  left.TryGetValue(out bool result) => result == right,
            (bool left, JsonValue right) when right.TryGetValue(out bool result) => result == left,

            (JsonValue left, long right) when  left.TryGetValue(out int result) => result == right,
            (long left, JsonValue right) when right.TryGetValue(out int result) => result == left,

            (JsonValue left, long right) when  left.TryGetValue(out long result) => result == right,
            (long left, JsonValue right) when right.TryGetValue(out long result) => result == left,

            (JsonValue left, string right) when left.TryGetValue(out string? result)
                => string.Equals(result, right, StringComparison.Ordinal),

            (string left, JsonValue right) when right.TryGetValue(out string? result)
                => string.Equals(left, result, StringComparison.Ordinal),

            // Otherwise, serialize both values to JsonElement and compare them.
            var (left, right) => DeepEquals(
                JsonSerializer.SerializeToElement(left, left.GetType(), OpenIddictSerializer.Default),
                JsonSerializer.SerializeToElement(right, right.GetType(), OpenIddictSerializer.Default))
        };

        static bool DeepEquals(JsonElement left, JsonElement right)
        {
#if !SUPPORTS_JSON_ELEMENT_DEEP_EQUALS
            RuntimeHelpers.EnsureSufficientExecutionStack();
#endif
            switch ((left.ValueKind, right.ValueKind))
            {
                case (JsonValueKind.Undefined, JsonValueKind.Undefined):
                case (JsonValueKind.Null,      JsonValueKind.Null):
                case (JsonValueKind.False,     JsonValueKind.False):
                case (JsonValueKind.True,      JsonValueKind.True):
                    return true;

                // Treat undefined JsonElement instances as null values.
                case (JsonValueKind.Undefined, JsonValueKind.Null):
                case (JsonValueKind.Null, JsonValueKind.Undefined):
                    return true;

#if SUPPORTS_JSON_ELEMENT_DEEP_EQUALS
                default: return JsonElement.DeepEquals(left, right);
#else
                case (JsonValueKind.Number, JsonValueKind.Number):
                    return string.Equals(left.GetRawText(), right.GetRawText(), StringComparison.Ordinal);

                case (JsonValueKind.String, JsonValueKind.String):
                    return string.Equals(left.GetString(), right.GetString(), StringComparison.Ordinal);

                case (JsonValueKind.Array, JsonValueKind.Array):
                {
                    var length = left.GetArrayLength();
                    if (length != right.GetArrayLength())
                    {
                        return false;
                    }

                    for (var index = 0; index < length; index++)
                    {
                        if (!DeepEquals(left[index], right[index]))
                        {
                            return false;
                        }
                    }

                    return true;
                }

                case (JsonValueKind.Object, JsonValueKind.Object):
                {
                    foreach (var property in left.EnumerateObject())
                    {
                        if (!right.TryGetProperty(property.Name, out JsonElement element) ||
                            property.Value.ValueKind != element.ValueKind)
                        {
                            return false;
                        }

                        if (!DeepEquals(property.Value, element))
                        {
                            return false;
                        }
                    }

                    return true;
                }

                default: return false;
#endif
            }
        }
    }

    /// <summary>
    /// Determines whether the current <see cref="OpenIddictParameter"/>
    /// instance is equal to the specified <see cref="object"/>.
    /// </summary>
    /// <param name="obj">The other object to which to compare this instance.</param>
    /// <returns>
    /// <see langword="true"/> if the two instances have both the same representation
    /// (e.g <see cref="string"/>) and value, <see langword="false"/> otherwise.
    /// </returns>
    public override bool Equals(object? obj) => obj is OpenIddictParameter parameter && Equals(parameter);

    /// <summary>
    /// Returns the hash code of the current <see cref="OpenIddictParameter"/> instance.
    /// </summary>
    /// <returns>The hash code for the current instance.</returns>
    public override int GetHashCode()
    {
        return _value switch
        {
            // When the parameter value is null, return 0.
            null => 0,

            // When the parameter is an array of strings, compute the hash code of its items to
            // match the logic used when treating a JsonElement instance representing an array.
            string?[] value => GetHashCodeFromArray(value),

            // When the parameter is a JsonElement, compute its hash code.
            JsonElement value => GetHashCodeFromJsonElement(value),

            // When the parameter is a JsonValue wrapping a JsonElement,
            // apply the same logic as with direct JsonElement instances.
            JsonValue value when value.TryGetValue(out JsonElement element)
                => GetHashCodeFromJsonElement(element),

            // When the parameter is a JsonValue, compute the hash code of its underlying value
            // if the wrapped type is a common CLR primitive type to avoid the less efficient
            // JsonElement-based computation, that requires doing a full JSON serialization.
            JsonValue value when value.TryGetValue(out bool result) => result.GetHashCode(),

            JsonValue value when value.TryGetValue(out int  result) => result.GetHashCode(),
            JsonValue value when value.TryGetValue(out long result) => result.GetHashCode(),

            JsonValue value when value.TryGetValue(out string? result) => result.GetHashCode(),

            // When the parameter is a JsonNode (e.g a JsonValue wrapping a non-primitive type),
            // serialize it to a JsonElement first to determine its actual JSON representation
            // and apply the same logic as with non-wrapped JsonElement instances.
            JsonNode value when JsonSerializer.SerializeToElement(value,
                OpenIddictSerializer.Default.JsonNode) is JsonElement element
                => GetHashCodeFromJsonElement(element),

            // Otherwise, use the default hash code method.
            var value => value.GetHashCode()
        };

        static int GetHashCodeFromArray(string?[] array)
        {
            var hash = new HashCode();

            for (var index = 0; index < array.Length; index++)
            {
                hash.Add(array[index]);
            }

            return hash.ToHashCode();
        }

        static int GetHashCodeFromJsonElement(JsonElement element)
        {
            RuntimeHelpers.EnsureSufficientExecutionStack();

            switch (element.ValueKind)
            {
                case JsonValueKind.Undefined:
                case JsonValueKind.Null:
                    return 0;

                case JsonValueKind.True:
                    return true.GetHashCode();

                case JsonValueKind.False:
                    return false.GetHashCode();

                case JsonValueKind.Number when element.TryGetInt64(out var result):
                    return result.GetHashCode();

                case JsonValueKind.Number:
                    return element.GetRawText().GetHashCode();

                case JsonValueKind.String:
                    return element.GetString()!.GetHashCode();

                case JsonValueKind.Array:
                {
                    var hash = new HashCode();

                    foreach (var item in element.EnumerateArray())
                    {
                        hash.Add(GetHashCodeFromJsonElement(item));
                    }

                    return hash.ToHashCode();
                }

                case JsonValueKind.Object:
                {
                    var hash = new HashCode();

                    foreach (var property in element.EnumerateObject())
                    {
                        hash.Add(property.Name);
                        hash.Add(GetHashCodeFromJsonElement(property.Value));
                    }

                    return hash.ToHashCode();
                }

                default: return 0;
            }
        }
    }

    /// <summary>
    /// Gets the child item corresponding to the specified name.
    /// </summary>
    /// <param name="name">The name of the child item.</param>
    /// <returns>An <see cref="OpenIddictParameter"/> instance containing the item value.</returns>
    public OpenIddictParameter? GetNamedParameter(string name)
        => TryGetNamedParameter(name, out var value) ? value : (OpenIddictParameter?) null;

    /// <summary>
    /// Gets the child item corresponding to the specified index.
    /// </summary>
    /// <param name="index">The index of the child item.</param>
    /// <returns>An <see cref="OpenIddictParameter"/> instance containing the item value.</returns>
    public OpenIddictParameter? GetUnnamedParameter(int index)
        => TryGetUnnamedParameter(index, out var value) ? value : (OpenIddictParameter?) null;

    /// <summary>
    /// Gets the named child items associated with the current parameter, if it represents a JSON object.
    /// Note: if the JSON object contains multiple parameters with the same name, only the last occurrence is returned.
    /// </summary>
    /// <returns>A dictionary of all the parameters associated with the current instance.</returns>
    public IReadOnlyDictionary<string, OpenIddictParameter> GetNamedParameters()
    {
        return _value switch
        {
            // When the parameter is a JsonElement representing an object, return the requested item.
            JsonElement { ValueKind: JsonValueKind.Object } value => GetParametersFromJsonElement(value),

            // When the parameter is a JsonObject, return the requested item.
            JsonObject value => GetParametersFromJsonNode(value),

            // When the parameter is a JsonNode (e.g a JsonValue wrapping a non-primitive type),
            // serialize it to a JsonElement first to determine its actual JSON representation
            // and apply the same logic as with non-wrapped JsonElement instances.
            JsonNode value when JsonSerializer.SerializeToElement(value, OpenIddictSerializer.Default.JsonNode)
                is JsonElement { ValueKind: JsonValueKind.Object } element
                => GetParametersFromJsonElement(element),

            _ => ImmutableDictionary.Create<string, OpenIddictParameter>(StringComparer.Ordinal)
        };

        static IReadOnlyDictionary<string, OpenIddictParameter> GetParametersFromJsonElement(JsonElement element)
        {
            var parameters = new Dictionary<string, OpenIddictParameter>(StringComparer.Ordinal);

            foreach (var property in element.EnumerateObject())
            {
                parameters[property.Name] = new(property.Value);
            }

            return parameters;
        }

        static IReadOnlyDictionary<string, OpenIddictParameter> GetParametersFromJsonNode(JsonObject node)
        {
            var parameters = new Dictionary<string, OpenIddictParameter>(node.Count, StringComparer.Ordinal);

            foreach (var property in node)
            {
                parameters[property.Key] = new(property.Value);
            }

            return parameters;
        }
    }

    /// <summary>
    /// Gets the unnamed child items associated with the current parameter,
    /// if it represents an array of strings or a JSON array.
    /// </summary>
    /// <returns>An enumeration of all the unnamed parameters associated with the current instance.</returns>
    public IReadOnlyList<OpenIddictParameter> GetUnnamedParameters()
    {
        return _value switch
        {
            // When the parameter is an array of strings, return its items.
            string?[] value => GetParametersFromArray(value),

            // When the parameter is a JsonElement representing an array, return its children.
            JsonElement { ValueKind: JsonValueKind.Array } value => GetParametersFromJsonElement(value),

            // When the parameter is a JsonArray, return its children.
            JsonArray value => GetParametersFromJsonNode(value),

            // When the parameter is a JsonNode (e.g a JsonValue wrapping a non-primitive type),
            // serialize it to a JsonElement first to determine its actual JSON representation
            // and apply the same logic as with non-wrapped JsonElement instances.
            JsonNode value when JsonSerializer.SerializeToElement(value, OpenIddictSerializer.Default.JsonNode)
                is JsonElement { ValueKind: JsonValueKind.Array } element
                => GetParametersFromJsonElement(element),

            _ => []
        };

        static IReadOnlyList<OpenIddictParameter> GetParametersFromArray(string?[] array)
        {
            var parameters = new OpenIddictParameter[array.Length];

            for (var index = 0; index < array.Length; index++)
            {
                parameters[index] = new(array[index]);
            }

            return parameters;
        }

        static IReadOnlyList<OpenIddictParameter> GetParametersFromJsonElement(JsonElement element)
        {
            var length = element.GetArrayLength();
            var parameters = new OpenIddictParameter[length];

            for (var index = 0; index < length; index++)
            {
                parameters[index] = new(element[index]);
            }

            return parameters;
        }

        static IReadOnlyList<OpenIddictParameter> GetParametersFromJsonNode(JsonArray node)
        {
            var parameters = new OpenIddictParameter[node.Count];

            for (var index = 0; index < node.Count; index++)
            {
                parameters[index] = new(node[index]);
            }

            return parameters;
        }
    }

    /// <summary>
    /// Returns the <see cref="string"/> representation of the current instance.
    /// </summary>
    /// <returns>The <see cref="string"/> representation associated with the parameter value.</returns>
    public override string? ToString() => _value switch
    {
        null => string.Empty,

        bool value => value ? "true" : "false",
        long value => value.ToString(CultureInfo.InvariantCulture),

        string    value => value,
        string?[] value => string.Join(", ", value),

        JsonElement { ValueKind: JsonValueKind.True  } => "true",
        JsonElement { ValueKind: JsonValueKind.False } => "false",

        JsonElement value => value.ToString(),

        JsonValue value when value.TryGetValue(out JsonElement element) => element.ValueKind switch
        {
            JsonValueKind.True  => "true",
            JsonValueKind.False => "false",

            _ => element.ToString()
        },
        
        JsonValue value when value.TryGetValue(out bool result)
            => result ? "true" : "false",
        
        JsonValue value when value.TryGetValue(out int result)
            => result.ToString(CultureInfo.InvariantCulture),

        JsonValue value when value.TryGetValue(out long result)
            => result.ToString(CultureInfo.InvariantCulture),

        JsonValue value when value.TryGetValue(out string? result) => result,

        JsonNode value when JsonSerializer.SerializeToElement(value, OpenIddictSerializer.Default.JsonNode) is JsonElement element
            => element.ValueKind switch
            {
                JsonValueKind.True  => "true",
                JsonValueKind.False => "false",

                _ => element.ToString()
            },

        _ => string.Empty
    };

    /// <summary>
    /// Tries to get the child item corresponding to the specified name.
    /// </summary>
    /// <param name="name">The name of the child item.</param>
    /// <param name="value">An <see cref="OpenIddictParameter"/> instance containing the item value.</param>
    /// <returns><see langword="true"/> if the parameter could be found, <see langword="false"/> otherwise.</returns>
    public bool TryGetNamedParameter(string name, out OpenIddictParameter value)
    {
        if (string.IsNullOrEmpty(name))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0192), nameof(name));
        }

        var result = _value switch
        {
            // When the parameter is a JsonElement representing an object, return the requested item.
            JsonElement { ValueKind: JsonValueKind.Object } element =>
                element.TryGetProperty(name, out JsonElement property) ? new(property) : null,

            // When the parameter is a JsonObject, return the requested item.
            JsonObject node => node.TryGetPropertyValue(name, out JsonNode? property) ? new(property) : null,

            // When the parameter is a JsonNode (e.g a JsonValue wrapping a non-primitive type),
            // serialize it to a JsonElement first to determine its actual JSON representation
            // and apply the same logic as with non-wrapped JsonElement instances.
            JsonNode node when JsonSerializer.SerializeToElement(node, OpenIddictSerializer.Default.JsonNode)
                is JsonElement { ValueKind: JsonValueKind.Object } element
                => element.TryGetProperty(name, out JsonElement property) ? new(property) : null,

            _ => (OpenIddictParameter?) null
        };

        value = result.GetValueOrDefault();
        return result.HasValue;
    }

    /// <summary>
    /// Tries to get the child item corresponding to the specified index.
    /// </summary>
    /// <param name="index">The index of the child item.</param>
    /// <param name="value">An <see cref="OpenIddictParameter"/> instance containing the item value.</param>
    /// <returns><see langword="true"/> if the parameter could be found, <see langword="false"/> otherwise.</returns>
    public bool TryGetUnnamedParameter(int index, out OpenIddictParameter value)
    {
        if (index < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(index), SR.GetResourceString(SR.ID0193));
        }

        var result = _value switch
        {
            // When the parameter is an array of strings, return the requested item.
            string?[] array => index < array.Length ? new(array[index]) : null,

            // When the parameter is a JsonElement representing an array, return the requested item.
            JsonElement { ValueKind: JsonValueKind.Array } element =>
                index < element.GetArrayLength() ? new(element[index]) : null,

            // When the parameter is a JsonArray, return the requested item.
            JsonArray node => index < node.Count ? new(node[index]) : null,

            // When the parameter is a JsonNode (e.g a JsonValue wrapping a non-primitive type),
            // serialize it to a JsonElement first to determine its actual JSON representation
            // and apply the same logic as with non-wrapped JsonElement instances.
            JsonNode node when JsonSerializer.SerializeToElement(node, OpenIddictSerializer.Default.JsonNode)
                is JsonElement { ValueKind: JsonValueKind.Array } element
                => index < element.GetArrayLength() ? new(element) : null,

            _ => (OpenIddictParameter?) null
        };

        value = result.GetValueOrDefault();
        return result.HasValue;
    }

    /// <summary>
    /// Writes the parameter value to the specified JSON writer.
    /// </summary>
    /// <param name="writer">The UTF-8 JSON writer.</param>
    public void WriteTo(Utf8JsonWriter writer)
    {
        if (writer is null)
        {
            throw new ArgumentNullException(nameof(writer));
        }

        switch (_value)
        {
            // Note: undefined JsonElement values are assimilated to null values.
            case null:
            case JsonElement { ValueKind: JsonValueKind.Null or JsonValueKind.Undefined }:
                writer.WriteNullValue();
                break;

            case bool value:
                writer.WriteBooleanValue(value);
                break;

            case long value:
                writer.WriteNumberValue(value);
                break;

            case string value:
                writer.WriteStringValue(value);
                break;

            case string?[] value:
                writer.WriteStartArray();

                for (var index = 0; index < value.Length; index++)
                {
                    writer.WriteStringValue(value[index]);
                }

                writer.WriteEndArray();
                break;

            case JsonElement value:
                value.WriteTo(writer);
                break;

            case JsonNode value:
                value.WriteTo(writer, OpenIddictSerializer.Default.Options);
                break;
        }
    }

    /// <summary>
    /// Determines whether two <see cref="OpenIddictParameter"/> instances are equal.
    /// </summary>
    /// <param name="left">The first instance.</param>
    /// <param name="right">The second instance.</param>
    /// <returns><see langword="true"/> if the two instances are equal, <see langword="false"/> otherwise.</returns>
    public static bool operator ==(OpenIddictParameter left, OpenIddictParameter right) => left.Equals(right);

    /// <summary>
    /// Determines whether two <see cref="OpenIddictParameter"/> instances are not equal.
    /// </summary>
    /// <param name="left">The first instance.</param>
    /// <param name="right">The second instance.</param>
    /// <returns><see langword="true"/> if the two instances are not equal, <see langword="false"/> otherwise.</returns>
    public static bool operator !=(OpenIddictParameter left, OpenIddictParameter right) => !left.Equals(right);

    /// <summary>
    /// Converts an <see cref="OpenIddictParameter"/> instance to a boolean.
    /// </summary>
    /// <param name="parameter">The parameter to convert.</param>
    /// <returns>The converted value.</returns>
    public static explicit operator bool(OpenIddictParameter? parameter)
        => ((bool?) parameter).GetValueOrDefault();

    /// <summary>
    /// Converts an <see cref="OpenIddictParameter"/> instance to a nullable boolean.
    /// </summary>
    /// <param name="parameter">The parameter to convert.</param>
    /// <returns>The converted value.</returns>
    public static explicit operator bool?(OpenIddictParameter? parameter)
    {
        return parameter?._value switch
        {
            // When the parameter is a null value or a JsonElement representing null, return null.
            null or JsonElement { ValueKind: JsonValueKind.Null or JsonValueKind.Undefined } => null,

            // When the parameter is a boolean value, return it as-is.
            bool value => value,

            // When the parameter is a string value, try to parse it.
            string value => bool.TryParse(value, out var result) ? result : null,

            // When the parameter is a JsonElement, try to convert it if it's of a supported type.
            JsonElement value => ConvertFromJsonElement(value),

            // When the parameter is a JsonValue wrapping a JsonElement,
            // apply the same logic as with direct JsonElement instances.
            JsonValue value when value.TryGetValue(out JsonElement element) => ConvertFromJsonElement(element),

            // When the parameter is a JsonValue wrapping a boolean, return it as-is.
            JsonValue value when value.TryGetValue(out bool result) => result,

            // When the parameter is a JsonValue wrapping a string, try to parse it.
            JsonValue value when value.TryGetValue(out string? text) =>
                bool.TryParse(text, out var result) ? result : null,

            // When the parameter is a JsonNode (e.g a JsonValue wrapping a non-primitive type),
            // serialize it to a JsonElement first to determine its actual JSON representation
            // and apply the same logic as with non-wrapped JsonElement instances.
            JsonNode value when JsonSerializer.SerializeToElement(value, OpenIddictSerializer.Default.JsonNode) is JsonElement element
                => ConvertFromJsonElement(element),

            // If the parameter is of a different type, return null to indicate the conversion failed.
            _ => null
        };

        static bool? ConvertFromJsonElement(JsonElement element) => element.ValueKind switch
        {
            // When the parameter is a JsonElement representing a boolean, return it as-is.
            JsonValueKind.True  => true,
            JsonValueKind.False => false,

            // When the parameter is a JsonElement representing a string, try to parse it.
            JsonValueKind.String => bool.TryParse(element.GetString(), out var result) ? result : null,

            _ => null
        };
    }

    /// <summary>
    /// Converts an <see cref="OpenIddictParameter"/> instance to a <see cref="JsonElement"/>.
    /// </summary>
    /// <param name="parameter">The parameter to convert.</param>
    /// <returns>The converted value.</returns>
    public static explicit operator JsonElement(OpenIddictParameter? parameter)
    {
        return parameter?._value switch
        {
            // When the parameter is a null value, return an undefined JsonElement.
            null => default,

            // When the parameter is already a JsonElement, return it as-is.
            JsonElement value => value,

            // When the parameter is JsonNode, serialize it as a JsonElement.
            JsonNode value => JsonSerializer.SerializeToElement(value, OpenIddictSerializer.Default.JsonNode),

            // When the parameter is a string starting with '{' or '[' (which would correspond
            // to a JSON object or array), try to deserialize it to get a JsonElement instance.
            string { Length: > 0 } value when value[0] is '{' or '[' =>
                DeserializeElement(value) ??
                DeserializeElement(JsonSerializer.Serialize(value, OpenIddictSerializer.Default.String)) ?? default,

            // Otherwise, serialize it to get a JsonElement instance.
            bool value     => JsonSerializer.SerializeToElement(value, OpenIddictSerializer.Default.Boolean),
            long value     => JsonSerializer.SerializeToElement(value, OpenIddictSerializer.Default.Int64),
            string value   => JsonSerializer.SerializeToElement(value, OpenIddictSerializer.Default.String),
            string[] value => JsonSerializer.SerializeToElement(value, OpenIddictSerializer.Default.StringArray),

            _ => default
        };

        static JsonElement? DeserializeElement(string value)
        {
            try
            {
                using var document = JsonDocument.Parse(value);
                return document.RootElement.Clone();
            }

            catch (JsonException)
            {
                return null;
            }
        }
    }

    /// <summary>
    /// Converts an <see cref="OpenIddictParameter"/> instance to a <see cref="JsonNode"/>.
    /// </summary>
    /// <param name="parameter">The parameter to convert.</param>
    /// <returns>The converted value.</returns>
    public static explicit operator JsonNode?(OpenIddictParameter? parameter)
    {
        return parameter?._value switch
        {
            // When the parameter is a null value or a JsonElement representing null, return null.
            null or JsonElement { ValueKind: JsonValueKind.Null or JsonValueKind.Undefined } => null,

            // When the parameter is already a JsonNode, return a clone to ensure mutations
            // made on the returned object do not affect the instance stored by this structure.
            JsonNode value => value.DeepClone(),

            // When the parameter is a boolean, return a JsonValue.
            bool value => JsonValue.Create(value),

            // When the parameter is an integer, return a JsonValue.
            long value => JsonValue.Create(value),

            // When the parameter is a string starting with '{' or '[' (which would correspond
            // to a JSON object or array), try to deserialize it to get a JsonNode instance.
            string { Length: > 0 } value when value[0] is '{' or '[' => DeserializeNode(value),

            // When the parameter is a string, return a JsonValue.
            string value => JsonValue.Create(value),

            // When the parameter is an array of strings, return a JsonArray.
            string?[] value => CreateArray(value),

            // When the parameter is JsonElement, deserialize it as a JsonNode.
            JsonElement value => value.Deserialize(OpenIddictSerializer.Default.JsonNode),

            // If the parameter is of a different type, return null to indicate the conversion failed.
            _ => null
        };

        static JsonNode? DeserializeNode(string value)
        {
            try
            {
                return JsonNode.Parse(value);
            }

            catch (JsonException)
            {
                return null;
            }
        }

        static JsonArray? CreateArray(string?[] values)
        {
            var nodes = new JsonNode?[values.Length];

            for (var index = 0; index < values.Length; index++)
            {
                nodes[index] = values[index];
            }

            return [.. nodes];
        }
    }

    /// <summary>
    /// Converts an <see cref="OpenIddictParameter"/> instance to a <see cref="JsonArray"/>.
    /// </summary>
    /// <param name="parameter">The parameter to convert.</param>
    /// <returns>The converted value.</returns>
    public static explicit operator JsonArray?(OpenIddictParameter? parameter)
        => ((JsonNode?) parameter) as JsonArray;

    /// <summary>
    /// Converts an <see cref="OpenIddictParameter"/> instance to a <see cref="JsonObject"/>.
    /// </summary>
    /// <param name="parameter">The parameter to convert.</param>
    /// <returns>The converted value.</returns>
    public static explicit operator JsonObject?(OpenIddictParameter? parameter)
        => ((JsonNode?) parameter) as JsonObject;

    /// <summary>
    /// Converts an <see cref="OpenIddictParameter"/> instance to a <see cref="JsonValue"/>.
    /// </summary>
    /// <param name="parameter">The parameter to convert.</param>
    /// <returns>The converted value.</returns>
    public static explicit operator JsonValue?(OpenIddictParameter? parameter)
        => ((JsonNode?) parameter) as JsonValue;

    /// <summary>
    /// Converts an <see cref="OpenIddictParameter"/> instance to a long integer.
    /// </summary>
    /// <param name="parameter">The parameter to convert.</param>
    /// <returns>The converted value.</returns>
    public static explicit operator long(OpenIddictParameter? parameter)
        => ((long?) parameter).GetValueOrDefault();

    /// <summary>
    /// Converts an <see cref="OpenIddictParameter"/> instance to a nullable long integer.
    /// </summary>
    /// <param name="parameter">The parameter to convert.</param>
    /// <returns>The converted value.</returns>
    public static explicit operator long?(OpenIddictParameter? parameter)
    {
        return parameter?._value switch
        {
            // When the parameter is a null value or a JsonElement representing null, return null.
            null or JsonElement { ValueKind: JsonValueKind.Null or JsonValueKind.Undefined } => null,

            // When the parameter is an integer, return it as-is.
            long value => value,

            // When the parameter is a string value, try to parse it.
            string value => long.TryParse(value, NumberStyles.Integer,
                CultureInfo.InvariantCulture, out var result) ? result : null,

            // When the parameter is a JsonElement, try to convert it if it's of a supported type.
            JsonElement value => ConvertFromJsonElement(value),

            // When the parameter is a JsonValue wrapping a JsonElement,
            // apply the same logic as with direct JsonElement instances.
            JsonValue value when value.TryGetValue(out JsonElement element) => ConvertFromJsonElement(element),

            // When the parameter is a JsonValue wrapping an integer, return it as-is.
            JsonValue value when value.TryGetValue(out int  result) => result,
            JsonValue value when value.TryGetValue(out long result) => result,

            // When the parameter is a JsonValue wrapping a string, return it as-is.
            JsonValue value when value.TryGetValue(out string? text) =>
                long.TryParse(text, NumberStyles.Integer,
                    CultureInfo.InvariantCulture, out var result) ? result : null,

            // When the parameter is a JsonNode (e.g a JsonValue wrapping a non-primitive type),
            // serialize it to a JsonElement first to determine its actual JSON representation
            // and apply the same logic as with non-wrapped JsonElement instances.
            JsonNode value when JsonSerializer.SerializeToElement(value,
                OpenIddictSerializer.Default.JsonNode) is JsonElement element
                => ConvertFromJsonElement(element),

            // If the parameter is of a different type, return null to indicate the conversion failed.
            _ => null
        };

        static long? ConvertFromJsonElement(JsonElement element) => element.ValueKind switch
        {
            // When the parameter is a JsonElement representing a number, return it as-is.
            JsonValueKind.Number => element.TryGetInt64(out var result) ? result : null,

            // When the parameter is a JsonElement representing a string, try to parse it.
            JsonValueKind.String => long.TryParse(element.GetString(), NumberStyles.Integer,
                CultureInfo.InvariantCulture, out var result) ? result : null,

            _ => null
        };
    }

    /// <summary>
    /// Converts an <see cref="OpenIddictParameter"/> instance to a string.
    /// </summary>
    /// <param name="parameter">The parameter to convert.</param>
    /// <returns>The converted value.</returns>
    public static explicit operator string?(OpenIddictParameter? parameter)
    {
        return parameter?._value switch
        {
            // When the parameter is a null value or a JsonElement representing null, return null.
            null or JsonElement { ValueKind: JsonValueKind.Null or JsonValueKind.Undefined } => null,

            // When the parameter is a string value, return it as-is.
            string value => value,

            // When the parameter is a boolean value, use its string representation.
            bool value => value ? "true" : "false",

            // When the parameter is an integer, use its string representation.
            long value => value.ToString(CultureInfo.InvariantCulture),

            // When the parameter is a JSON boolean value, use its string representation.
            JsonElement { ValueKind: JsonValueKind.True }  => "true",
            JsonElement { ValueKind: JsonValueKind.False } => "false",

            // When the parameter is a JsonElement, try to convert it if it's of a supported type.
            JsonElement value => ConvertFromJsonElement(value),

            // When the parameter is a JsonValue wrapping a JsonElement,
            // apply the same logic as with direct JsonElement instances.
            JsonValue value when value.TryGetValue(out JsonElement element) => ConvertFromJsonElement(element),

            // When the parameter is a JsonValue wrapping a string, return it as-is.
            JsonValue value when value.TryGetValue(out string? result) => result,

            // When the parameter is a JsonValue wrapping a boolean, return its representation.
            JsonValue value when value.TryGetValue(out bool result) => result ? "true" : "false",

            // When the parameter is a JsonValue wrapping a boolean, return its representation.
            JsonValue value when value.TryGetValue(out int result)  => result.ToString(CultureInfo.InvariantCulture),
            JsonValue value when value.TryGetValue(out long result) => result.ToString(CultureInfo.InvariantCulture),

            // When the parameter is a JsonNode (e.g a JsonValue wrapping a non-primitive type),
            // serialize it to a JsonElement first to determine its actual JSON representation
            // and apply the same logic as with non-wrapped JsonElement instances.
            JsonNode value when JsonSerializer.SerializeToElement(value,
                OpenIddictSerializer.Default.JsonNode) is JsonElement element
                => ConvertFromJsonElement(element),

            // If the parameter is of a different type, return null to indicate the conversion failed.
            _ => null
        };

        static string? ConvertFromJsonElement(JsonElement element) => element.ValueKind switch
        {
            // When the parameter is a JsonElement representing
            // a boolean, return its string representation.
            JsonValueKind.True  => "true",
            JsonValueKind.False => "false",

            // When the parameter is a JsonElement representing a
            // string or a number, return its string representation.
            JsonValueKind.String or JsonValueKind.Number => element.ToString(),

            _ => null
        };
    }

    /// <summary>
    /// Converts an <see cref="OpenIddictParameter"/> instance to a <see cref="StringValues"/> instance.
    /// </summary>
    /// <param name="parameter">The parameter to convert.</param>
    /// <returns>The converted value.</returns>
    public static explicit operator StringValues(OpenIddictParameter? parameter)
        => ((StringValues?) parameter).GetValueOrDefault();

    /// <summary>
    /// Converts an <see cref="OpenIddictParameter"/> instance to a <see cref="StringValues"/> instance.
    /// </summary>
    /// <param name="parameter">The parameter to convert.</param>
    /// <returns>The converted value.</returns>
    public static explicit operator StringValues?(OpenIddictParameter? parameter)
    {
        return parameter?._value switch
        {
            // When the parameter is a null value or a JsonElement representing null, return null.
            null or JsonElement { ValueKind: JsonValueKind.Null or JsonValueKind.Undefined } => null,

            // When the parameter is an array of strings, return a StringValues instance wrapping the cloned array.
            string?[] value => new StringValues(value.ToArray().ToArray()),

            // When the parameter is a string value, return a StringValues instance with a single entry.
            string value => new StringValues(value),

            // When the parameter is a boolean value, return a StringValues instance with its string representation.
            bool value => new StringValues(value ? "true" : "false"),

            // When the parameter is an integer, return a StringValues instance with its string representation.
            long value => new StringValues(value.ToString(CultureInfo.InvariantCulture)),

            // When the parameter is a JSON boolean value, return a StringValues instance with its string representation.
            JsonElement { ValueKind: JsonValueKind.True  } => new StringValues("true"),
            JsonElement { ValueKind: JsonValueKind.False } => new StringValues("false"),

            // When the parameter is a JsonElement, try to convert it if it's of a supported type.
            JsonElement value => ConvertFromJsonElement(value),

            // When the parameter is a JsonValue wrapping a JsonElement,
            // apply the same logic as with direct JsonElement instances.
            JsonValue value when value.TryGetValue(out JsonElement element) => ConvertFromJsonElement(element),

            // When the parameter is a JsonValue wrapping a string, return a StringValues instance with a single entry.
            JsonValue value when value.TryGetValue(out string? result) => new StringValues(result),

            // When the parameter is a JsonValue wrapping a boolean, return a StringValues instance with its string representation.
            JsonValue value when value.TryGetValue(out bool result)
                => new StringValues(result ? "true" : "false"),

            // When the parameter is a JsonValue wrapping an integer, return a StringValues instance with its string representation.
            JsonValue value when value.TryGetValue(out int result)
                => new StringValues(result.ToString(CultureInfo.InvariantCulture)),

            JsonValue value when value.TryGetValue(out long result)
                => new StringValues(result.ToString(CultureInfo.InvariantCulture)),

            // When the parameter is a JsonNode (e.g a JsonValue wrapping a non-primitive type),
            // serialize it to a JsonElement first to determine its actual JSON representation
            // and apply the same logic as with non-wrapped JsonElement instances.
            JsonNode value when JsonSerializer.SerializeToElement(value,
                OpenIddictSerializer.Default.JsonNode) is JsonElement element
                => ConvertFromJsonElement(element),

            // If the parameter is of a different type, return null to indicate the conversion failed.
            _ => null
        };

        static StringValues? ConvertFromJsonElement(JsonElement element) => element.ValueKind switch
        {
            // When the parameter is a JsonElement representing a boolean,
            // return a StringValues instance with its string representation.
            JsonValueKind.True  => new StringValues("true"),
            JsonValueKind.False => new StringValues("false"),

            // When the parameter is a JsonElement representing a string or a
            // number, return a StringValues instance with its string representation.
            JsonValueKind.String or JsonValueKind.Number => new StringValues(element.ToString()),

            // When the parameter is a JsonElement representing an array, return the elements as strings.
            JsonValueKind.Array => CreateArrayFromJsonElement(element),

            _ => null
        };

        static StringValues? CreateArrayFromJsonElement(JsonElement element)
        {
            var length = element.GetArrayLength();
            var array = new string[length];

            for (var index = 0; index < length; index++)
            {
                var item = element[index];
                if (item.ValueKind is JsonValueKind.True)
                {
                    array[index] = "true";
                }

                else if (item.ValueKind is JsonValueKind.False)
                {
                    array[index] = "false";
                }

                else if (item.ValueKind is JsonValueKind.String or JsonValueKind.Number)
                {
                    array[index] = item.ToString();
                }

                // Always return a null array if one of the items is a not string, a number or a boolean.
                else
                {
                    return null;
                }
            }

            return new StringValues(array);
        }
    }

    /// <summary>
    /// Converts an <see cref="OpenIddictParameter"/> instance to an immutable array of strings.
    /// </summary>
    /// <param name="parameter">The parameter to convert.</param>
    /// <returns>The converted value.</returns>
    public static explicit operator ImmutableArray<string?>(OpenIddictParameter? parameter)
        => ((ImmutableArray<string?>?) parameter).GetValueOrDefault();

    /// <summary>
    /// Converts an <see cref="OpenIddictParameter"/> instance to an immutable array of strings.
    /// </summary>
    /// <param name="parameter">The parameter to convert.</param>
    /// <returns>The converted value.</returns>
    public static explicit operator ImmutableArray<string?>?(OpenIddictParameter? parameter)
    {
        return parameter?._value switch
        {
            // When the parameter is a null value or a JsonElement representing null, return null.
            null or JsonElement { ValueKind: JsonValueKind.Null or JsonValueKind.Undefined } => null,

            // When the parameter is already an array of strings, return it as-is.
            string?[] value => ImmutableCollectionsMarshal.AsImmutableArray(value),

            // When the parameter is a string value, return an array with a single entry.
            string value => [value],

            // When the parameter is a boolean value, return an array with its string representation.
            bool value => [value ? "true" : "false"],

            // When the parameter is an integer, return an array with its string representation.
            long value => [value.ToString(CultureInfo.InvariantCulture)],

            // When the parameter is a JSON boolean value, return an array with its string representation.
            JsonElement { ValueKind: JsonValueKind.True  } => ["true"],
            JsonElement { ValueKind: JsonValueKind.False } => ["false"],

            // When the parameter is a JsonElement, try to convert it if it's of a supported type.
            JsonElement value => ConvertFromJsonElement(value),

            // When the parameter is a JsonValue wrapping a JsonElement,
            // apply the same logic as with direct JsonElement instances.
            JsonValue value when value.TryGetValue(out JsonElement element) => ConvertFromJsonElement(element),

            // When the parameter is a JsonValue wrapping a string, return an array with a single entry.
            JsonValue value when value.TryGetValue(out string? result) => [result],

            // When the parameter is a JsonValue wrapping a boolean, return an array with its string representation.
            JsonValue value when value.TryGetValue(out bool result) => [result ? "true" : "false"],

            // When the parameter is a JsonValue wrapping an integer, return an array with its string representation.
            JsonValue value when value.TryGetValue(out int result)
                => [result.ToString(CultureInfo.InvariantCulture)],

            JsonValue value when value.TryGetValue(out long result)
                => [result.ToString(CultureInfo.InvariantCulture)],

            // When the parameter is a JsonNode (e.g a JsonValue wrapping a non-primitive type),
            // serialize it to a JsonElement first to determine its actual JSON representation
            // and apply the same logic as with non-wrapped JsonElement instances.
            JsonNode value when JsonSerializer.SerializeToElement(value,
                OpenIddictSerializer.Default.JsonNode) is JsonElement element
                => ConvertFromJsonElement(element),

            // If the parameter is of a different type, return null to indicate the conversion failed.
            _ => null
        };

        static ImmutableArray<string?>? ConvertFromJsonElement(JsonElement element) => element.ValueKind switch
        {
            // When the parameter is a JsonElement representing a boolean,
            // return an 1-item array with its string representation.
            JsonValueKind.True  => ["true"],
            JsonValueKind.False => ["false"],

            // When the parameter is a JsonElement representing a string or a
            // number, return an 1-item array with its string representation.
            JsonValueKind.String or JsonValueKind.Number => [element.ToString()],

            // When the parameter is a JsonElement representing an array, return the elements as strings.
            JsonValueKind.Array => CreateArrayFromJsonElement(element),

            _ => null
        };

        static ImmutableArray<string?>? CreateArrayFromJsonElement(JsonElement element)
        {
            var length = element.GetArrayLength();
            var builder = ImmutableArray.CreateBuilder<string?>(length);

            for (var index = 0; index < length; index++)
            {
                var item = element[index];
                if (item.ValueKind is JsonValueKind.True)
                {
                    builder.Add("true");
                }

                else if (item.ValueKind is JsonValueKind.False)
                {
                    builder.Add("false");
                }

                else if (item.ValueKind is JsonValueKind.String or JsonValueKind.Number)
                {
                    builder.Add(item.ToString());
                }

                // Always return a null array if one of the items is a not string, a number or a boolean.
                else
                {
                    return null;
                }
            }

            return builder.ToImmutable();
        }
    }

    /// <summary>
    /// Converts a boolean to an <see cref="OpenIddictParameter"/> instance.
    /// </summary>
    /// <param name="value">The value to convert.</param>
    /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
    public static implicit operator OpenIddictParameter(bool value) => new(value);

    /// <summary>
    /// Converts a nullable boolean to an <see cref="OpenIddictParameter"/> instance.
    /// </summary>
    /// <param name="value">The value to convert.</param>
    /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
    public static implicit operator OpenIddictParameter(bool? value) => new(value);

    /// <summary>
    /// Converts a <see cref="JsonElement"/> to an <see cref="OpenIddictParameter"/> instance.
    /// </summary>
    /// <param name="value">The value to convert.</param>
    /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
    public static implicit operator OpenIddictParameter(JsonElement value) => new(value);

    /// <summary>
    /// Converts a <see cref="JsonNode"/> to an <see cref="OpenIddictParameter"/> instance.
    /// </summary>
    /// <param name="value">The value to convert.</param>
    /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
    public static implicit operator OpenIddictParameter(JsonNode? value) => new(value);

    /// <summary>
    /// Converts a long integer to an <see cref="OpenIddictParameter"/> instance.
    /// </summary>
    /// <param name="value">The value to convert.</param>
    /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
    public static implicit operator OpenIddictParameter(long value) => new(value);

    /// <summary>
    /// Converts a nullable long integer to an <see cref="OpenIddictParameter"/> instance.
    /// </summary>
    /// <param name="value">The value to convert.</param>
    /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
    public static implicit operator OpenIddictParameter(long? value) => new(value);

    /// <summary>
    /// Converts a string to an <see cref="OpenIddictParameter"/> instance.
    /// </summary>
    /// <param name="value">The value to convert.</param>
    /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
    public static implicit operator OpenIddictParameter(string? value) => new(value);

    /// <summary>
    /// Converts a string to an <see cref="OpenIddictParameter"/> instance.
    /// </summary>
    /// <param name="value">The value to convert.</param>
    /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
    public static implicit operator OpenIddictParameter(StringValues? value) => value?.Count switch
    {
        null or 0 => default,
        1         => new OpenIddictParameter(value.GetValueOrDefault()[0]),
        _         => new(ImmutableCollectionsMarshal.AsImmutableArray(value.GetValueOrDefault().ToArray()))
    };

    /// <summary>
    /// Converts a string to an <see cref="OpenIddictParameter"/> instance.
    /// </summary>
    /// <param name="value">The value to convert.</param>
    /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
    public static implicit operator OpenIddictParameter(StringValues value) => value.Count switch
    {
        0 => default,
        1 => new OpenIddictParameter(value[0]),
        _ => new(ImmutableCollectionsMarshal.AsImmutableArray(value.ToArray()))
    };

    /// <summary>
    /// Converts an array of strings to an <see cref="OpenIddictParameter"/> instance.
    /// </summary>
    /// <param name="value">The value to convert.</param>
    /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
    public static implicit operator OpenIddictParameter(ImmutableArray<string?> value) => new(value);

    /// <summary>
    /// Converts an array of strings to an <see cref="OpenIddictParameter"/> instance.
    /// </summary>
    /// <param name="value">The value to convert.</param>
    /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
    public static implicit operator OpenIddictParameter(ImmutableArray<string?>? value) => new(value);

    /// <summary>
    /// Determines whether a parameter is null or empty.
    /// </summary>
    /// <param name="parameter">The parameter.</param>
    /// <returns><see langword="true"/> if the parameter is null or empty, <see langword="false"/> otherwise.</returns>
    public static bool IsNullOrEmpty(OpenIddictParameter parameter)
    {
        return parameter._value switch
        {
            null or JsonElement { ValueKind: JsonValueKind.Null or JsonValueKind.Undefined } => true,

            string value    => value.Length is 0,
            string?[] value => value.Length is 0,

            JsonElement value => OpenIddictHelpers.IsNullOrEmpty(value),

            JsonArray  value => value.Count is 0,
            JsonObject value => value.Count is 0,

            JsonValue value when value.TryGetValue(out string? result) => string.IsNullOrEmpty(result),

            JsonValue value when value.TryGetValue(out JsonElement element)
                => OpenIddictHelpers.IsNullOrEmpty(element),

            JsonNode value when JsonSerializer.SerializeToElement(value,
                OpenIddictSerializer.Default.JsonNode) is JsonElement element
                => OpenIddictHelpers.IsNullOrEmpty(element),

            _ => false
        };
    }
}
