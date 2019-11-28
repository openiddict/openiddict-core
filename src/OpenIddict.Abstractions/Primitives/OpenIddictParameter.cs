/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Text.Encodings.Web;
using System.Text.Json;
using JetBrains.Annotations;

namespace OpenIddict.Abstractions
{
    /// <summary>
    /// Represents an OpenIddict parameter value, that can be either a primitive value,
    /// an array of strings or a complex JSON representation containing child nodes.
    /// </summary>
    public readonly struct OpenIddictParameter : IEquatable<OpenIddictParameter>
    {
        /// <summary>
        /// Initializes a new OpenID Connect
        /// parameter using the specified value.
        /// </summary>
        /// <param name="value">The parameter value.</param>
        public OpenIddictParameter(bool value) => Value = value;

        /// <summary>
        /// Initializes a new OpenID Connect
        /// parameter using the specified value.
        /// </summary>
        /// <param name="value">The parameter value.</param>
        public OpenIddictParameter(bool? value) => Value = value;

        /// <summary>
        /// Initializes a new OpenID Connect
        /// parameter using the specified value.
        /// </summary>
        /// <param name="value">The parameter value.</param>
        public OpenIddictParameter(JsonElement value) => Value = value;

        /// <summary>
        /// Initializes a new OpenID Connect
        /// parameter using the specified value.
        /// </summary>
        /// <param name="value">The parameter value.</param>
        public OpenIddictParameter(JsonElement? value) => Value = value;

        /// <summary>
        /// Initializes a new OpenID Connect
        /// parameter using the specified value.
        /// </summary>
        /// <param name="value">The parameter value.</param>
        public OpenIddictParameter(long value) => Value = value;

        /// <summary>
        /// Initializes a new OpenID Connect
        /// parameter using the specified value.
        /// </summary>
        /// <param name="value">The parameter value.</param>
        public OpenIddictParameter(long? value) => Value = value;

        /// <summary>
        /// Initializes a new OpenID Connect
        /// parameter using the specified value.
        /// </summary>
        /// <param name="value">The parameter value.</param>
        public OpenIddictParameter(string value) => Value = value;

        /// <summary>
        /// Initializes a new OpenID Connect
        /// parameter using the specified value.
        /// </summary>
        /// <param name="value">The parameter value.</param>
        public OpenIddictParameter(string[] value) => Value = value;

        /// <summary>
        /// Gets the child item corresponding to the specified index.
        /// </summary>
        /// <param name="index">The index of the child item.</param>
        /// <returns>An <see cref="OpenIddictParameter"/> instance containing the item value.</returns>
        public OpenIddictParameter? this[int index] => GetParameter(index);

        /// <summary>
        /// Gets the child item corresponding to the specified name.
        /// </summary>
        /// <param name="name">The name of the child item.</param>
        /// <returns>An <see cref="OpenIddictParameter"/> instance containing the item value.</returns>
        public OpenIddictParameter? this[string name] => GetParameter(name);

        /// <summary>
        /// Gets the associated value, that can be either a primitive CLR type
        /// (e.g bool, string, long), an array of strings or a complex JSON object.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public object Value { get; }

        /// <summary>
        /// Determines whether the current <see cref="OpenIddictParameter"/>
        /// instance is equal to the specified <see cref="OpenIddictParameter"/>.
        /// </summary>
        /// <param name="parameter">The other object to which to compare this instance.</param>
        /// <returns><c>true</c> if the two instances are equal, <c>false</c> otherwise.</returns>
        public bool Equals(OpenIddictParameter parameter)
        {
            return Value switch
            {
                // If the two parameters reference the same instance, return true.
                // Note: true will also be returned if the two parameters are null.
                var value when ReferenceEquals(value, parameter.Value) => true,

                // If one of the two parameters is null, return false.
                null => false,
                var _ when parameter.Value == null => false,

                // If the two parameters are string arrays, use SequenceEqual().
                string[] value when parameter.Value is string[] array => value.SequenceEqual(array),

                // If the two parameters are JsonElement instances, use the custom comparer.
                JsonElement value when parameter.Value is JsonElement element => Equals(value, element),

                // When one of the parameters is a bool, compare them as booleans.
                JsonElement value when value.ValueKind == JsonValueKind.True
                                    && parameter.Value is bool boolean => boolean,
                JsonElement value when value.ValueKind == JsonValueKind.False
                                    && parameter.Value is bool boolean => !boolean,

                bool value when parameter.Value is JsonElement element
                             && element.ValueKind == JsonValueKind.True => value,
                bool value when parameter.Value is JsonElement element
                             && element.ValueKind == JsonValueKind.False => !value,

                // When one of the parameters is a number, compare them as integers.
                JsonElement value when value.ValueKind == JsonValueKind.Number
                                    && parameter.Value is long integer
                    => integer == value.GetInt64(),

                long value when parameter.Value is JsonElement element
                             && element.ValueKind == JsonValueKind.Number
                    => value == element.GetInt64(),

                // When one of the parameters is a string, compare them as texts.
                JsonElement value when value.ValueKind == JsonValueKind.String
                                    && parameter.Value is string text
                    => string.Equals(value.GetString(), text, StringComparison.Ordinal),

                string value when parameter.Value is JsonElement element
                               && element.ValueKind == JsonValueKind.String
                    => string.Equals(value, element.GetString(), StringComparison.Ordinal),

                // Otherwise, use direct CLR comparison.
                var value => value.Equals(parameter.Value)
            };

            static bool Equals(JsonElement left, JsonElement right)
            {
                switch (left.ValueKind)
                {
                    case JsonValueKind.Undefined:
                        return right.ValueKind == JsonValueKind.Undefined;

                    case JsonValueKind.Null:
                        return right.ValueKind == JsonValueKind.Null;

                    case JsonValueKind.False:
                        return right.ValueKind == JsonValueKind.False;

                    case JsonValueKind.True:
                        return right.ValueKind == JsonValueKind.True;

                    case JsonValueKind.Number when right.ValueKind == JsonValueKind.Number:
                        return left.GetInt64() == right.GetInt64();

                    case JsonValueKind.String when right.ValueKind == JsonValueKind.String:
                        return string.Equals(left.GetString(), right.GetString(), StringComparison.Ordinal);

                    case JsonValueKind.Array when right.ValueKind == JsonValueKind.Array:
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

                    case JsonValueKind.Object when right.ValueKind == JsonValueKind.Object:
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
        /// <param name="value">The other object to which to compare this instance.</param>
        /// <returns><c>true</c> if the two instances are equal, <c>false</c> otherwise.</returns>
        public override bool Equals(object value)
            => value is OpenIddictParameter parameter && Equals(parameter);

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
                        return value.GetString().GetHashCode();

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
        /// Gets the child item corresponding to the specified index.
        /// </summary>
        /// <param name="index">The index of the child item.</param>
        /// <returns>An <see cref="OpenIddictParameter"/> instance containing the item value.</returns>
        public OpenIddictParameter? GetParameter(int index)
        {
            if (index < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(index), "The item index cannot be negative.");
            }

            if (Value is string[] array)
            {
                // If the specified index goes beyond the
                // number of items in the array, return null.
                if (index >= array.Length)
                {
                    return null;
                }

                return new OpenIddictParameter(array[index]);
            }

            if (Value is JsonElement element && element.ValueKind == JsonValueKind.Array)
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
        /// Gets the child item corresponding to the specified name.
        /// </summary>
        /// <param name="name">The name of the child item.</param>
        /// <returns>An <see cref="OpenIddictParameter"/> instance containing the item value.</returns>
        public OpenIddictParameter? GetParameter([NotNull] string name)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("The item name cannot be null or empty.", nameof(name));
            }

            if (Value is JsonElement element && element.ValueKind == JsonValueKind.Object)
            {
                if (element.TryGetProperty(name, out JsonElement value) && value.ValueKind != JsonValueKind.Null)
                {
                    return new OpenIddictParameter(value);
                }

                // If the item doesn't exist, return a null parameter.
                return null;
            }

            return null;
        }

        /// <summary>
        /// Gets the child items associated with the current parameter.
        /// </summary>
        /// <returns>An enumeration of all the parameters associated with the current instance.</returns>
        public IEnumerable<KeyValuePair<string, OpenIddictParameter>> GetParameters()
        {
            if (Value is string[] array)
            {
                for (var index = 0; index < array.Length; index++)
                {
                    yield return new KeyValuePair<string, OpenIddictParameter>(null, array[index]);
                }
            }

            if (Value is JsonElement element)
            {
                switch (element.ValueKind)
                {
                    case JsonValueKind.Array:
                        foreach (var value in element.EnumerateArray())
                        {
                            yield return new KeyValuePair<string, OpenIddictParameter>(null, value);
                        }

                        break;

                    case JsonValueKind.Object:
                        foreach (var property in element.EnumerateObject())
                        {
                            yield return new KeyValuePair<string, OpenIddictParameter>(property.Name, property.Value);
                        }

                        break;
                }
            }

            yield break;
        }

        /// <summary>
        /// Returns the <see cref="string"/> representation of the current instance.
        /// </summary>
        /// <returns>The <see cref="string"/> representation associated with the parameter value.</returns>
        public override string ToString() => Value switch
        {
            null => string.Empty,

            string value   => value,
            string[] value => string.Join(", ", value),

            JsonElement value when value.ValueKind == JsonValueKind.Undefined => string.Empty,
            JsonElement value when value.ValueKind == JsonValueKind.Null      => string.Empty,

            JsonElement value when value.ValueKind != JsonValueKind.Array &&
                                   value.ValueKind != JsonValueKind.Object => value.GetString(),

            JsonElement value => value.ToString(),

            _ => Value.ToString()
        };

        /// <summary>
        /// Tries to get the child item corresponding to the specified name.
        /// </summary>
        /// <param name="name">The name of the child item.</param>
        /// <param name="value">An <see cref="OpenIddictParameter"/> instance containing the item value.</param>
        /// <returns><c>true</c> if the parameter could be found, <c>false</c> otherwise.</returns>
        public bool TryGetParameter([NotNull] string name, out OpenIddictParameter value)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("The parameter name cannot be null or empty.", nameof(name));
            }

            if (Value is JsonElement element && element.ValueKind == JsonValueKind.Object &&
                element.TryGetProperty(name, out JsonElement property))
            {
                value = new OpenIddictParameter(property);

                return true;
            }

            value = default;

            return false;
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
            // When the parameter is a null value, return null.
            null => null,

            // When the parameter is a boolean value, return it as-is.
            bool value => value,

            // When the parameter is a string value, try to parse it.
            string value => bool.TryParse(value, out var result) ? (bool?) result : null,

            // When the parameter is a JsonElement representing null, return null.
            JsonElement value when value.ValueKind == JsonValueKind.Undefined => null,
            JsonElement value when value.ValueKind == JsonValueKind.Null      => null,

            // When the parameter is a JsonElement representing a boolean, return it as-is.
            JsonElement value when value.ValueKind == JsonValueKind.False => false,
            JsonElement value when value.ValueKind == JsonValueKind.True  => true,

            // When the parameter is a JsonElement representing a string, try to parse it.
            JsonElement value when value.ValueKind == JsonValueKind.String
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
            => ((JsonElement?) parameter).GetValueOrDefault();

        /// <summary>
        /// Converts an <see cref="OpenIddictParameter"/> instance to a nullale <see cref="JsonElement"/>.
        /// </summary>
        /// <param name="parameter">The parameter to convert.</param>
        /// <returns>The converted value.</returns>
        public static explicit operator JsonElement?(OpenIddictParameter? parameter)
        {
            return parameter?.Value switch
            {
                // When the parameter is a null value, return null.
                null => default(JsonElement?),

                // When the parameter is a JsonElement representing null, return null.
                JsonElement value when value.ValueKind == JsonValueKind.Undefined => null,
                JsonElement value when value.ValueKind == JsonValueKind.Null => null,

                // When the parameter is already a JsonElement, return it as-is.
                JsonElement value => value,

                // When the parameter is a string, try to derialize it to get a JsonElement instance.
                string value => DeserializeElement(value) ?? DeserializeElement(JsonSerializer.Serialize(value, new JsonSerializerOptions
                {
                    Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                    WriteIndented = false
                })),

                // Otherwise, serialize it to get a JsonElement instance.
                var value => DeserializeElement(JsonSerializer.Serialize(value, new JsonSerializerOptions
                {
                    Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                    WriteIndented = false
                }))
            };

            static JsonElement? DeserializeElement(string value)
            {
                try { return JsonSerializer.Deserialize<JsonElement>(value); }
                catch (JsonException) { return null; }
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
            // When the parameter is a null value, return null.
            null => null,

            // When the parameter is an integer, return it as-is.
            long value => value,

            // When the parameter is a string value, try to parse it.
            string value
                => long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var result) ? (long?) result : null,

            // When the parameter is a JsonElement representing null, return null.
            JsonElement value when value.ValueKind == JsonValueKind.Undefined => null,
            JsonElement value when value.ValueKind == JsonValueKind.Null      => null,

            // When the parameter is a JsonElement representing a number, return it as-is.
            JsonElement value when value.ValueKind == JsonValueKind.Number
                => value.TryGetInt64(out var result) ? (long?) result : null,

            // When the parameter is a JsonElement representing a string, try to parse it.
            JsonElement value when value.ValueKind == JsonValueKind.String
                => long.TryParse(value.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var result) ? (long?) result : null,

            // If the parameter is of a different type, return null to indicate the conversion failed.
            _ => null
        };

        /// <summary>
        /// Converts an <see cref="OpenIddictParameter"/> instance to a string.
        /// </summary>
        /// <param name="parameter">The parameter to convert.</param>
        /// <returns>The converted value.</returns>
        public static explicit operator string(OpenIddictParameter? parameter) => parameter?.Value switch
        {
            // When the parameter is a null value, return null.
            null => null,

            // When the parameter is a string value, return it as-is.
            string value => value,

            // When the parameter is a boolean value, use its string representation.
            bool value => value.ToString(),

            // When the parameter is an integer, use its string representation.
            long value => value.ToString(CultureInfo.InvariantCulture),

            // When the parameter is a JsonElement representing null, return null.
            JsonElement value when value.ValueKind == JsonValueKind.Undefined => null,
            JsonElement value when value.ValueKind == JsonValueKind.Null      => null,

            // When the parameter is a JsonElement representing a string, return it as-is.
            JsonElement value when value.ValueKind == JsonValueKind.String => value.GetString(),

            // When the parameter is a JsonElement that doesn't represent a string, serialize it.
            JsonElement value => JsonSerializer.Serialize(value, new JsonSerializerOptions
            {
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                WriteIndented = false
            }),

            // If the parameter is of a different type, return null to indicate the conversion failed.
            _ => null
        };

        /// <summary>
        /// Converts an <see cref="OpenIddictParameter"/> instance to an array of strings.
        /// </summary>
        /// <param name="parameter">The parameter to convert.</param>
        /// <returns>The converted value.</returns>
        public static explicit operator string[](OpenIddictParameter? parameter)
        {
            return parameter?.Value switch
            {
                // When the parameter is a null value, return a null array.
                null => null,

                // When the parameter is already an array of strings, return it as-is.
                string[] value => value,

                // When the parameter is a string value, return an array with a single entry.
                string value => new string[] { value },

                // When the parameter is a boolean value, return an array with its string representation.
                bool value => new string[] { value.ToString() },

                // When the parameter is an integer, return an array with its string representation.
                long value => new string[] { value.ToString(CultureInfo.InvariantCulture) },

                // When the parameter is a JsonElement representing null, return null.
                JsonElement value when value.ValueKind == JsonValueKind.Undefined => null,
                JsonElement value when value.ValueKind == JsonValueKind.Null      => null,

                // When the parameter is a JsonElement representing a string, return an array with a single entry.
                JsonElement value when value.ValueKind == JsonValueKind.String
                    => new string[] { value.GetString() },

                // When the parameter is a JsonElement representing a number, return an array with a single entry.
                JsonElement value when value.ValueKind == JsonValueKind.Number
                    => new string[] { value.GetInt64().ToString(CultureInfo.InvariantCulture) },

                // When the parameter is a JsonElement representing a boolean, return an array with a single entry.
                JsonElement value when value.ValueKind == JsonValueKind.False => new string[] { bool.FalseString },
                JsonElement value when value.ValueKind == JsonValueKind.True  => new string[] { bool.TrueString },

                // When the parameter is a JsonElement representing an array of strings, return it.
                JsonElement value when value.ValueKind == JsonValueKind.Array => CreateArray(value),

                // If the parameter is of a different type, return null to indicate the conversion failed.
                _ => null
            };

            static string[] CreateArray(JsonElement value)
            {
                var array = new string[value.GetArrayLength()];
                using var enumerator = value.EnumerateArray();

                for (var index = 0; enumerator.MoveNext(); index++)
                {
                    var element = enumerator.Current;
                    if (element.ValueKind != JsonValueKind.String)
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
        public static implicit operator OpenIddictParameter(bool value) => new OpenIddictParameter(value);

        /// <summary>
        /// Converts a nullable boolean to an <see cref="OpenIddictParameter"/> instance.
        /// </summary>
        /// <param name="value">The value to convert</param>
        /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
        public static implicit operator OpenIddictParameter(bool? value) => new OpenIddictParameter(value);

        /// <summary>
        /// Converts a <see cref="JsonElement"/> to an <see cref="OpenIddictParameter"/> instance.
        /// </summary>
        /// <param name="value">The value to convert</param>
        /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
        public static implicit operator OpenIddictParameter(JsonElement value) => new OpenIddictParameter(value);

        /// <summary>
        /// Converts a long integer to an <see cref="OpenIddictParameter"/> instance.
        /// </summary>
        /// <param name="value">The value to convert</param>
        /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
        public static implicit operator OpenIddictParameter(long value) => new OpenIddictParameter(value);

        /// <summary>
        /// Converts a nullable long integer to an <see cref="OpenIddictParameter"/> instance.
        /// </summary>
        /// <param name="value">The value to convert</param>
        /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
        public static implicit operator OpenIddictParameter(long? value) => new OpenIddictParameter(value);

        /// <summary>
        /// Converts a string to an <see cref="OpenIddictParameter"/> instance.
        /// </summary>
        /// <param name="value">The value to convert</param>
        /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
        public static implicit operator OpenIddictParameter(string value) => new OpenIddictParameter(value);

        /// <summary>
        /// Converts an array of strings to an <see cref="OpenIddictParameter"/> instance.
        /// </summary>
        /// <param name="value">The value to convert</param>
        /// <returns>An <see cref="OpenIddictParameter"/> instance.</returns>
        public static implicit operator OpenIddictParameter(string[] value) => new OpenIddictParameter(value);

        /// <summary>
        /// Determines whether an OpenID Connect parameter is null or empty.
        /// </summary>
        /// <param name="parameter">The OpenID Connect parameter.</param>
        /// <returns><c>true</c> if the parameter is null or empty, <c>false</c> otherwise.</returns>
        public static bool IsNullOrEmpty(OpenIddictParameter parameter)
        {
            return parameter.Value switch
            {
                null => true,

                string value   => string.IsNullOrEmpty(value),
                string[] value => value.Length == 0,

                JsonElement value when value.ValueKind == JsonValueKind.Undefined => true,
                JsonElement value when value.ValueKind == JsonValueKind.Null      => true,

                JsonElement value when value.ValueKind == JsonValueKind.String
                    => string.IsNullOrEmpty(value.GetString()),

                JsonElement value when value.ValueKind == JsonValueKind.Array     => value.GetArrayLength() == 0,
                JsonElement value when value.ValueKind == JsonValueKind.Object    => IsEmptyNode(value),

                _ => false
            };

            static bool IsEmptyNode(JsonElement value)
            {
                using var enumerator = value.EnumerateObject();
                return !enumerator.MoveNext();
            }
        }
    }
}
