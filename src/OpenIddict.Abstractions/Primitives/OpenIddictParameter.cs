/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace OpenIddict.Abstractions;

/// <summary>
/// Represents an OpenIddict parameter value, that can be either a primitive value,
/// an array of strings or a complex JSON representation containing child nodes.
/// </summary>
public readonly struct OpenIddictParameter : IEquatable<OpenIddictParameter>
{
    /// <summary>
    /// Initializes a new parameter using the specified value.
    /// </summary>
    /// <param name="value">The parameter value.</param>
    public OpenIddictParameter(bool value) => Value = value;

    /// <summary>
    /// Initializes a new parameter using the specified value.
    /// </summary>
    /// <param name="value">The parameter value.</param>
    public OpenIddictParameter(bool? value) => Value = value;

    /// <summary>
    /// Initializes a new parameter using the specified value.
    /// </summary>
    /// <param name="value">The parameter value.</param>
    public OpenIddictParameter(JsonElement value) => Value = value;

    /// <summary>
    /// Initializes a new parameter using the specified value.
    /// </summary>
    /// <param name="value">The parameter value.</param>
    public OpenIddictParameter(long value) => Value = value;

    /// <summary>
    /// Initializes a new parameter using the specified value.
    /// </summary>
    /// <param name="value">The parameter value.</param>
    public OpenIddictParameter(long? value) => Value = value;

    /// <summary>
    /// Initializes a new parameter using the specified value.
    /// </summary>
    /// <param name="value">The parameter value.</param>
    public OpenIddictParameter(string? value) => Value = value;

    /// <summary>
    /// Initializes a new parameter using the specified value.
    /// </summary>
    /// <param name="value">The parameter value.</param>
    public OpenIddictParameter(string?[]? value) => Value = value;

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
    /// Gets the number of unnamed child items contained in the current parameter or
    /// <c>0</c> if the parameter doesn't represent an array of strings or a JSON array.
    /// </summary>
    public int Count => Value switch
    {
        // If the parameter is a primitive array of strings, return its length.
        string?[] value => value.Length,

        // If the parameter is a JSON array, return its length.
        JsonElement { ValueKind: JsonValueKind.Array } value => value.GetArrayLength(),

        // Otherwise, return 0.
        _ => 0
    };

    /// <summary>
    /// Gets the associated value, that can be either a primitive CLR type
    /// (e.g bool, string, long), an array of strings or a complex JSON object.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public object? Value { get; }

    /// <summary>
    /// Determines whether the current <see cref="OpenIddictParameter"/>
    /// instance is equal to the specified <see cref="OpenIddictParameter"/>.
    /// </summary>
    /// <param name="other">The other object to which to compare this instance.</param>
    /// <returns><c>true</c> if the two instances are equal, <c>false</c> otherwise.</returns>
    public bool Equals(OpenIddictParameter other)
    {
        return (left: Value, right: other.Value) switch
        {
            // If the two parameters reference the same instance, return true.
            // Note: true will also be returned if the two parameters are null.
            var (left, right) when ReferenceEquals(left, right) => true,

            // If one of the two parameters is null, return false.
            (null, _) or (_, null) => false,

            // If the two parameters are string arrays, use SequenceEqual().
            (string?[] left, string?[] right) => left.SequenceEqual(right),

            // If the two parameters are JsonElement instances, use the custom comparer.
            (JsonElement left, JsonElement right) => Equals(left, right),

            // When one of the parameters is a bool, compare them as booleans.
            (JsonElement { ValueKind: JsonValueKind.True  }, bool right) => right,
            (JsonElement { ValueKind: JsonValueKind.False }, bool right) => !right,

            (bool left, JsonElement { ValueKind: JsonValueKind.True  }) => left,
            (bool left, JsonElement { ValueKind: JsonValueKind.False }) => !left,

            // When one of the parameters is a number, compare them as integers.
            (JsonElement { ValueKind: JsonValueKind.Number } left, long right)
                => right == left.GetInt64(),

            (long left, JsonElement { ValueKind: JsonValueKind.Number } right)
                => left == right.GetInt64(),

            // When one of the parameters is a string, compare them as texts.
            (JsonElement { ValueKind: JsonValueKind.String } left, string right)
                => string.Equals(left.GetString(), right, StringComparison.Ordinal),

            (string left, JsonElement { ValueKind: JsonValueKind.String } right)
                => string.Equals(left, right.GetString(), StringComparison.Ordinal),

            // Otherwise, use direct CLR comparison.
            var (left, right) => left.Equals(right)
        };

        static bool Equals(JsonElement left, JsonElement right)
        {
            switch (left.ValueKind)
            {
                case JsonValueKind.Undefined:
                    return right.ValueKind is JsonValueKind.Undefined;

                case JsonValueKind.Null:
                    return right.ValueKind is JsonValueKind.Null;

                case JsonValueKind.False:
                    return right.ValueKind is JsonValueKind.False;

                case JsonValueKind.True:
                    return right.ValueKind is JsonValueKind.True;

                case JsonValueKind.Number when right.ValueKind is JsonValueKind.Number:
                    return left.GetInt64() == right.GetInt64();

                case JsonValueKind.String when right.ValueKind is JsonValueKind.String:
                    return string.Equals(left.GetString(), right.GetString(), StringComparison.Ordinal);

                case JsonValueKind.Array when right.ValueKind is JsonValueKind.Array:
                    if (left.GetArrayLength() != right.GetArrayLength())
                    {
                        return false;
                    }

                    using (var enumerator = left.EnumerateArray())
                    {
                        for (var index = 0; enumerator.MoveNext(); index++)
                        {
                            if (!Equals(left[index], right[index]))
                            {
                                return false;
                            }
                        }
                    }

                    return true;

                case JsonValueKind.Object when right.ValueKind is JsonValueKind.Object:
                    foreach (var property in left.EnumerateObject())
                    {
                        if (!right.TryGetProperty(property.Name, out JsonElement element) ||
                            property.Value.ValueKind != element.ValueKind)
                        {
                            return false;
                        }

                        if (!Equals(property.Value, element))
                        {
                            return false;
                        }
                    }

                    return true;

                default: return false;
            }
        }
    }

    /// <summary>
    /// Determines whether the current <see cref="OpenIddictParameter"/>
    /// instance is equal to the specified <see cref="object"/>.
    /// </summary>
    /// <param name="obj">The other object to which to compare this instance.</param>
    /// <returns><c>true</c> if the two instances are equal, <c>false</c> otherwise.</returns>
    public override bool Equals(object? obj) => obj is OpenIddictParameter parameter && Equals(parameter);

    /// <summary>
    /// Returns the hash code of the current <see cref="OpenIddictParameter"/> instance.
    /// </summary>
    /// <returns>The hash code for the current instance.</returns>
    public override int GetHashCode()
    {
        return Value switch
        {
            // When the parameter value is null, return 0.
            null => 0,

            // When the parameter is a JsonElement, compute its hash code.
            JsonElement value => GetHashCode(value),

            // Otherwise, use the default hash code method.
            var value => value.GetHashCode()
        };

        static int GetHashCode(JsonElement value)
        {
            switch (value.ValueKind)
            {
                case JsonValueKind.Undefined:
                case JsonValueKind.Null:
                    return 0;

                case JsonValueKind.False:
                    return false.GetHashCode();

                case JsonValueKind.True:
                    return true.GetHashCode();

                case JsonValueKind.Number:
                    return value.GetInt64().GetHashCode();

                case JsonValueKind.String:
                    return value.GetString()!.GetHashCode();

                case JsonValueKind.Array:
                {
                    var hash = new HashCode();

                    foreach (var element in value.EnumerateArray())
                    {
                        hash.Add(GetHashCode(element));
                    }

                    return hash.ToHashCode();
                }

                case JsonValueKind.Object:
                {
                    var hash = new HashCode();

                    foreach (var property in value.EnumerateObject())
                    {
                        hash.Add(property.Name);
                        hash.Add(GetHashCode(property.Value));
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
    {
        if (string.IsNullOrEmpty(name))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0192), nameof(name));
        }

        if (Value is JsonElement { ValueKind: JsonValueKind.Object } element)
        {
            if (element.TryGetProperty(name, out JsonElement value))
            {
                return new OpenIddictParameter(value);
            }

            // If the item doesn't exist, return a null parameter.
            return null;
        }

        return null;
    }

    /// <summary>
    /// Gets the child item corresponding to the specified index.
    /// </summary>
    /// <param name="index">The index of the child item.</param>
    /// <returns>An <see cref="OpenIddictParameter"/> instance containing the item value.</returns>
    public OpenIddictParameter? GetUnnamedParameter(int index)
    {
        if (index < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(index), SR.GetResourceString(SR.ID0193));
        }

        if (Value is string?[] array)
        {
            // If the specified index goes beyond the
            // number of items in the array, return null.
            if (index >= array.Length)
            {
                return null;
            }

            return new OpenIddictParameter(array[index]);
        }

        if (Value is JsonElement { ValueKind: JsonValueKind.Array } element)
        {
            // If the specified index goes beyond the
            // number of items in the array, return null.
            if (index >= element.GetArrayLength())
            {
                return null;
            }

            return new OpenIddictParameter(element[index]);
        }

        // If the value is not a JSON array, return null.
        return null;
    }

    /// <summary>
    /// Gets the named child items associated with the current parameter, if it represents a JSON object.
    /// Note: if the JSON object contains multiple parameters with the same name, only the last occurrence is returned.
    /// </summary>
    /// <returns>A dictionary of all the parameters associated with the current instance.</returns>
    public IReadOnlyDictionary<string, OpenIddictParameter> GetNamedParameters()
    {
        if (Value is JsonElement { ValueKind: JsonValueKind.Object } element)
        {
            var parameters = new Dictionary<string, OpenIddictParameter>(StringComparer.Ordinal);

            foreach (var property in element.EnumerateObject())
            {
                parameters[property.Name] = property.Value;
            }

            return parameters;
        }

        return ImmutableDictionary.Create<string, OpenIddictParameter>(StringComparer.Ordinal);
    }

    /// <summary>
    /// Gets the unnamed child items associated with the current parameter,
    /// if it represents an array of strings or a JSON array.
    /// </summary>
    /// <returns>An enumeration of all the unnamed parameters associated with the current instance.</returns>
    public IReadOnlyList<OpenIddictParameter> GetUnnamedParameters()
    {
        if (Value is string?[] array)
        {
            var parameters = new List<OpenIddictParameter>();

            for (var index = 0; index < array.Length; index++)
            {
                parameters.Add(array[index]);
            }

            return parameters;
        }

        else if (Value is JsonElement { ValueKind: JsonValueKind.Array } element)
        {
            var parameters = new List<OpenIddictParameter>();

            foreach (var value in element.EnumerateArray())
            {
                parameters.Add(value);
            }

            return parameters;
        }

        return ImmutableList.Create<OpenIddictParameter>();
    }

    /// <summary>
    /// Returns the <see cref="string"/> representation of the current instance.
    /// </summary>
    /// <returns>The <see cref="string"/> representation associated with the parameter value.</returns>
    public override string? ToString() => Value switch
    {
        null => string.Empty,

        bool value => value ? bool.TrueString : bool.FalseString,
        long value => value.ToString(CultureInfo.InvariantCulture),

        string    value => value,
        string?[] value => string.Join(", ", value),

        JsonElement value => value.ToString(),

        _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0194))
    };

    /// <summary>
    /// Tries to get the child item corresponding to the specified name.
    /// </summary>
    /// <param name="name">The name of the child item.</param>
    /// <param name="value">An <see cref="OpenIddictParameter"/> instance containing the item value.</param>
    /// <returns><c>true</c> if the parameter could be found, <c>false</c> otherwise.</returns>
    public bool TryGetNamedParameter(string name, out OpenIddictParameter value)
    {
        if (string.IsNullOrEmpty(name))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0192), nameof(name));
        }

        if (Value is JsonElement { ValueKind: JsonValueKind.Object } element &&
            element.TryGetProperty(name, out JsonElement property))
        {
            value = new OpenIddictParameter(property);

            return true;
        }

        value = default;

        return false;
    }

    /// <summary>
    /// Tries to get the child item corresponding to the specified index.
    /// </summary>
    /// <param name="index">The index of the child item.</param>
    /// <param name="value">An <see cref="OpenIddictParameter"/> instance containing the item value.</param>
    /// <returns><c>true</c> if the parameter could be found, <c>false</c> otherwise.</returns>
    public bool TryGetUnnamedParameter(int index, out OpenIddictParameter value)
    {
        if (index < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(index), SR.GetResourceString(SR.ID0193));
        }

        if (Value is string?[] array)
        {
            if (index >= array.Length)
            {
                value = default;

                return false;
            }

            value = new OpenIddictParameter(array[index]);

            return true;
        }

        if (Value is JsonElement { ValueKind: JsonValueKind.Array } element)
        {
            if (index >= element.GetArrayLength())
            {
                value = default;

                return false;
            }

            value = new OpenIddictParameter(element[index]);

            return true;
        }

        value = default;

        return false;
    }

    /// <summary>
    /// Writes the parameter value to the specified JSON writer.
    /// </summary>
    /// <param name="writer">The UTF-8 JSON writer.</param>
    public void WriteTo(Utf8JsonWriter writer!!)
    {
        switch (Value)
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

            default: throw new InvalidOperationException(SR.GetResourceString(SR.ID0194));
        }
    }

    /// <summary>
    /// Determines whether two <see cref="OpenIddictParameter"/> instances are equal.
    /// </summary>
    /// <param name="left">The first instance.</param>
    /// <param name="right">The second instance.</param>
    /// <returns><c>true</c> if the two instances are equal, <c>false</c> otherwise.</returns>
    public static bool operator ==(OpenIddictParameter left, OpenIddictParameter right) => left.Equals(right);

    /// <summary>
    /// Determines whether two <see cref="OpenIddictParameter"/> instances are not equal.
    /// </summary>
    /// <param name="left">The first instance.</param>
    /// <param name="right">The second instance.</param>
    /// <returns><c>true</c> if the two instances are not equal, <c>false</c> otherwise.</returns>
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
    public static explicit operator bool?(OpenIddictParameter? parameter) => parameter?.Value switch
    {
        // When the parameter is a null value or a JsonElement representing null, return null.
        null or JsonElement { ValueKind: JsonValueKind.Null or JsonValueKind.Undefined } => null,

        // When the parameter is a boolean value, return it as-is.
        bool value => value,

        // When the parameter is a string value, try to parse it.
        string value => bool.TryParse(value, out var result) ? (bool?) result : null,

        // When the parameter is a JsonElement representing a boolean, return it as-is.
        JsonElement { ValueKind: JsonValueKind.False } => false,
        JsonElement { ValueKind: JsonValueKind.True  } => true,

        // When the parameter is a JsonElement representing a string, try to parse it.
        JsonElement { ValueKind: JsonValueKind.String } value
            => bool.TryParse(value.GetString(), out var result) ? (bool?) result : null,

        // If the parameter is of a different type, return null to indicate the conversion failed.
        _ => null
    };

    /// <summary>
    /// Converts an <see cref="OpenIddictParameter"/> instance to a <see cref="JsonElement"/>.
    /// </summary>
    /// <param name="parameter">The parameter to convert.</param>
    /// <returns>The converted value.</returns>
    public static explicit operator JsonElement(OpenIddictParameter? parameter)
    {
        return parameter?.Value switch
        {
            // When the parameter is a null value, return default.
            null => default,

            // When the parameter is already a JsonElement, return it as-is.
            JsonElement value => value,

            // When the parameter is a string starting with '{' or '[' (which would correspond
            // to a JSON object or array), try to deserialize it to get a JsonElement instance.
            string { Length: > 0 } value when value[0] is '{' or '[' =>
                DeserializeElement(value) ??
                DeserializeElement(SerializeObject(value)) ?? default,

            // Otherwise, serialize it to get a JsonElement instance.
            var value => DeserializeElement(SerializeObject(value)) ?? default
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

        static string SerializeObject(object instance)
        {
            using var stream = new MemoryStream();
            using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
            {
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                Indented = false
            });

            switch (instance)
            {
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

                default: throw new InvalidOperationException(SR.GetResourceString(SR.ID0194));
            }

            writer.Flush();

            return Encoding.UTF8.GetString(stream.ToArray());
        }
    }

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
    public static explicit operator long?(OpenIddictParameter? parameter) => parameter?.Value switch
    {
        // When the parameter is a null value or a JsonElement representing null, return null.
        null or JsonElement { ValueKind: JsonValueKind.Null or JsonValueKind.Undefined } => null,

        // When the parameter is an integer, return it as-is.
        long value => value,

        // When the parameter is a string value, try to parse it.
        string value
            => long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var result) ? (long?) result : null,

        // When the parameter is a JsonElement representing a number, return it as-is.
        JsonElement { ValueKind: JsonValueKind.Number } value
            => value.TryGetInt64(out var result) ? (long?) result : null,

        // When the parameter is a JsonElement representing a string, try to parse it.
        JsonElement { ValueKind: JsonValueKind.String } value
            => long.TryParse(value.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var result) ? (long?) result : null,

        // If the parameter is of a different type, return null to indicate the conversion failed.
        _ => null
    };

    /// <summary>
    /// Converts an <see cref="OpenIddictParameter"/> instance to a string.
    /// </summary>
    /// <param name="parameter">The parameter to convert.</param>
    /// <returns>The converted value.</returns>
    public static explicit operator string?(OpenIddictParameter? parameter) => parameter?.Value switch
    {
        // When the parameter is a null value or a JsonElement representing null, return null.
        null or JsonElement { ValueKind: JsonValueKind.Null or JsonValueKind.Undefined } => null,

        // When the parameter is a string value, return it as-is.
        string value => value,

        // When the parameter is a boolean value, use its string representation.
        bool value => value.ToString(),

        // When the parameter is an integer, use its string representation.
        long value => value.ToString(CultureInfo.InvariantCulture),

        // When the parameter is a JsonElement representing a string, return it as-is.
        JsonElement { ValueKind: JsonValueKind.String } value => value.GetString(),

        // When the parameter is a JsonElement representing a number, return its representation.
        JsonElement { ValueKind: JsonValueKind.Number } value
            => value.GetInt64().ToString(CultureInfo.InvariantCulture),

        // When the parameter is a JsonElement representing a boolean, return its representation.
        JsonElement { ValueKind: JsonValueKind.False } => bool.FalseString,
        JsonElement { ValueKind: JsonValueKind.True  } => bool.TrueString,

        // If the parameter is of a different type, return null to indicate the conversion failed.
        _ => null
    };

    /// <summary>
    /// Converts an <see cref="OpenIddictParameter"/> instance to an array of strings.
    /// </summary>
    /// <param name="parameter">The parameter to convert.</param>
    /// <returns>The converted value.</returns>
    public static explicit operator string?[]?(OpenIddictParameter? parameter)
    {
        return parameter?.Value switch
        {
            // When the parameter is a null value or a JsonElement representing null, return null.
            null or JsonElement { ValueKind: JsonValueKind.Null or JsonValueKind.Undefined } => null,

            // When the parameter is already an array of strings, return it as-is.
            string?[] value => value,

            // When the parameter is a string value, return an array with a single entry.
            string value => new string?[] { value },

            // When the parameter is a boolean value, return an array with its string representation.
            bool value => new string?[] { value.ToString() },

            // When the parameter is an integer, return an array with its string representation.
            long value => new string?[] { value.ToString(CultureInfo.InvariantCulture) },

            // When the parameter is a JsonElement representing a string, return an array with a single entry.
            JsonElement { ValueKind: JsonValueKind.String } value => new string?[] { value.GetString() },

            // When the parameter is a JsonElement representing a number, return an array with a single entry.
            JsonElement { ValueKind: JsonValueKind.Number } value
                => new string?[] { value.GetInt64().ToString(CultureInfo.InvariantCulture) },

            // When the parameter is a JsonElement representing a boolean, return an array with a single entry.
            JsonElement { ValueKind: JsonValueKind.False } => new string?[] { bool.FalseString },
            JsonElement { ValueKind: JsonValueKind.True  } => new string?[] { bool.TrueString  },

            // When the parameter is a JsonElement representing an array of strings, return it.
            JsonElement { ValueKind: JsonValueKind.Array } value => CreateArray(value),

            // If the parameter is of a different type, return null to indicate the conversion failed.
            _ => null
        };

        static string?[]? CreateArray(JsonElement value)
        {
            var array = new string?[value.GetArrayLength()];
            using var enumerator = value.EnumerateArray();

            for (var index = 0; enumerator.MoveNext(); index++)
            {
                var element = enumerator.Current;
                if (element.ValueKind is not JsonValueKind.String)
                {
                    return null;
                }

                array[index] = element.GetString();
            }

            return array;
        }
    }

    /// <summary>
    /// Converts a boolean to an <see cref="OpenIddictParameter"/> instance.
    /// </summary>
    /// <param name="value">The value to convert</param>
    /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
    public static implicit operator OpenIddictParameter(bool value) => new(value);

    /// <summary>
    /// Converts a nullable boolean to an <see cref="OpenIddictParameter"/> instance.
    /// </summary>
    /// <param name="value">The value to convert</param>
    /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
    public static implicit operator OpenIddictParameter(bool? value) => new(value);

    /// <summary>
    /// Converts a <see cref="JsonElement"/> to an <see cref="OpenIddictParameter"/> instance.
    /// </summary>
    /// <param name="value">The value to convert</param>
    /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
    public static implicit operator OpenIddictParameter(JsonElement value) => new(value);

    /// <summary>
    /// Converts a long integer to an <see cref="OpenIddictParameter"/> instance.
    /// </summary>
    /// <param name="value">The value to convert</param>
    /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
    public static implicit operator OpenIddictParameter(long value) => new(value);

    /// <summary>
    /// Converts a nullable long integer to an <see cref="OpenIddictParameter"/> instance.
    /// </summary>
    /// <param name="value">The value to convert</param>
    /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
    public static implicit operator OpenIddictParameter(long? value) => new(value);

    /// <summary>
    /// Converts a string to an <see cref="OpenIddictParameter"/> instance.
    /// </summary>
    /// <param name="value">The value to convert</param>
    /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
    public static implicit operator OpenIddictParameter(string? value) => new(value);

    /// <summary>
    /// Converts an array of strings to an <see cref="OpenIddictParameter"/> instance.
    /// </summary>
    /// <param name="value">The value to convert</param>
    /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
    public static implicit operator OpenIddictParameter(string?[]? value) => new(value);

    /// <summary>
    /// Determines whether a parameter is null or empty.
    /// </summary>
    /// <param name="parameter">The parameter.</param>
    /// <returns><c>true</c> if the parameter is null or empty, <c>false</c> otherwise.</returns>
    public static bool IsNullOrEmpty(OpenIddictParameter parameter)
    {
        return parameter.Value switch
        {
            null or JsonElement { ValueKind: JsonValueKind.Null or JsonValueKind.Undefined } => true,

            string value    => string.IsNullOrEmpty(value),
            string?[] value => value.Length == 0,

            JsonElement { ValueKind: JsonValueKind.String } value => string.IsNullOrEmpty(value.GetString()),
            JsonElement { ValueKind: JsonValueKind.Array  } value => value.GetArrayLength() == 0,
            JsonElement { ValueKind: JsonValueKind.Object } value => IsEmptyNode(value),

            _ => false
        };

        static bool IsEmptyNode(JsonElement value)
        {
            using var enumerator = value.EnumerateObject();
            return !enumerator.MoveNext();
        }
    }
}
