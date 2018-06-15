using AspNet.Security.OAuth.Validation;
using JetBrains.Annotations;

namespace OpenIddict.Validation
{
    /// <summary>
    /// Contains common events used by the OpenIddict validation handler.
    /// </summary>
    public static class OpenIddictValidationEvents
    {
        /// <summary>
        /// Invoked when a challenge response is returned to the caller.
        /// </summary>
        public sealed class ApplyChallenge : OpenIddictValidationEvent<ApplyChallengeContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="ApplyChallenge"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public ApplyChallenge([NotNull] ApplyChallengeContext context) : base(context) { }
        }

        /// <summary>
        /// Invoked when a ticket is to be created from an introspection response.
        /// </summary>
        public sealed class CreateTicket : OpenIddictValidationEvent<CreateTicketContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="CreateTicket"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public CreateTicket([NotNull] CreateTicketContext context) : base(context) { }
        }

        /// <summary>
        /// Invoked when a token is to be decrypted.
        /// </summary>
        public sealed class DecryptToken : OpenIddictValidationEvent<DecryptTokenContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="DecryptToken"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public DecryptToken([NotNull] DecryptTokenContext context) : base(context) { }
        }

        /// <summary>
        /// Invoked when a token is to be parsed from a newly-received request.
        /// </summary>
        public sealed class RetrieveToken : OpenIddictValidationEvent<RetrieveTokenContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="RetrieveToken"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public RetrieveToken([NotNull] RetrieveTokenContext context) : base(context) { }
        }

        /// <summary>
        /// Invoked when a token is to be validated, before final processing.
        /// </summary>
        public sealed class ValidateToken : OpenIddictValidationEvent<ValidateTokenContext>
        {
            /// <summary>
            /// Creates a new instance of <see cref="ValidateToken"/>.
            /// </summary>
            /// <param name="context">The context instance associated with the notification.</param>
            public ValidateToken([NotNull] ValidateTokenContext context) : base(context) { }
        }
    }
}
