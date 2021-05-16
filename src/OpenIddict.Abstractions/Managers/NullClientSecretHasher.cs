using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace OpenIddict.Abstractions
{
    /// <summary>
    /// Implements the <see cref="IOpenIddictClientSecretHasher"/> with a null implementation tht does not hash the secret.
    /// </summary>
    /// <remarks>
    /// Only use this class for custom implementations of the <see cref="IOpenIddictApplicationStore{TApplication}"/> interface when your secret is already hashed.
    /// </remarks>
    public class NullClientSecretHasher : IOpenIddictClientSecretHasher
    {
        /// <inheritdoc />
        public ValueTask<string> ObfuscateClientSecretAsync(string secret, CancellationToken cancellationToken = default)
        {
            return new ValueTask<string>(secret);
        }

        /// <inheritdoc />
        public ValueTask<bool> ValidateClientSecretAsync(string secret, string comparand, CancellationToken cancellationToken = default)
        {
            var equals = string.Equals(secret, comparand);

            return new ValueTask<bool>(equals);
        }
    }
}
