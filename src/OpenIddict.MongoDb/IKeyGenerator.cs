/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.MongoDb
{
    /// <summary>
    /// Implement this class to generate keys.
    /// </summary>
    /// <typeparam name="TKey">The type of the key.</typeparam>
    /// <remarks>
    /// The keys must support ToString() so that they can be parsed later.
    /// </remarks>
    public interface IKeyGenerator<TKey> where TKey : notnull
    {
        /// <summary>
        /// Generate a new random key.
        /// </summary>
        /// <returns>The generated random key.</returns>
        TKey Generate();

        /// <summary>
        /// Generate a new empty key to unset a value.
        /// </summary>
        /// <returns>The generated empty key.</returns>
        TKey GenerateEmpty();

        /// <summary>
        /// Parse a key from a given string.
        /// </summary>
        /// <param name="input">The key to parse.</param>
        /// <returns>The parsed key.</returns>
        TKey Parse(string input);

        /// <summary>
        /// Checks whether a key is empty or undefined.
        /// </summary>
        /// <param name="input">The key to check.</param>
        /// <returns>
        /// True, when the key is undefined or false otherwise.
        /// </returns>
        bool IsUndefined(TKey input);
    }
}
