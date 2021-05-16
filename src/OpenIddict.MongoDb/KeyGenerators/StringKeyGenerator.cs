/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;

namespace OpenIddict.MongoDb.KeyGenerators
{
    public sealed class StringKeyGenerator : IKeyGenerator<string>
    {
        public static readonly IKeyGenerator<string> Default = new StringKeyGenerator();

        private StringKeyGenerator()
        {
        }

        /// <inheritdoc />
        public string Generate()
        {
            return Guid.NewGuid().ToString();
        }

        /// <inheritdoc />
        public string GenerateEmpty()
        {
            return null!;
        }

        /// <inheritdoc />
        public string Parse(string input)
        {
            return input;
        }

        /// <inheritdoc />
        public bool IsUndefined(string input)
        {
            return string.IsNullOrWhiteSpace(input);
        }
    }
}
