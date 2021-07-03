/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;

namespace OpenIddict.MongoDb.KeyGenerators
{
    public sealed class GuidKeyGenerator : IKeyGenerator<Guid>
    {
        public static readonly IKeyGenerator<Guid> Default = new GuidKeyGenerator();

        private GuidKeyGenerator()
        {
        }

        /// <inheritdoc />
        public Guid Generate()
        {
            return Guid.NewGuid();
        }

        /// <inheritdoc />
        public Guid GenerateEmpty()
        {
            return Guid.Empty;
        }

        /// <inheritdoc />
        public Guid Parse(string input)
        {
            return Guid.Parse(input);
        }

        /// <inheritdoc />
        public bool IsUndefined(Guid input)
        {
            return input == Guid.Empty;
        }
    }
}
