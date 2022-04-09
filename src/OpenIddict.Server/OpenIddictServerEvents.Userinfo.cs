/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Security.Claims;
using System.Text.Json;

namespace OpenIddict.Server;

public static partial class OpenIddictServerEvents
{
    /// <summary>
    /// Represents an event called for each request to the userinfo endpoint to give the user code
    /// a chance to manually extract the userinfo request from the ambient HTTP context.
    /// </summary>
    public class ExtractUserinfoRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ExtractUserinfoRequestContext"/> class.
        /// </summary>
        public ExtractUserinfoRequestContext(OpenIddictServerTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the request, or <see langword="null"/> if it wasn't extracted yet.
        /// </summary>
        public OpenIddictRequest? Request
        {
            get => Transaction.Request;
            set => Transaction.Request = value;
        }
    }

    /// <summary>
    /// Represents an event called for each request to the userinfo endpoint
    /// to determine if the request is valid and should continue to be processed.
    /// </summary>
    public class ValidateUserinfoRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ValidateUserinfoRequestContext"/> class.
        /// </summary>
        public ValidateUserinfoRequestContext(OpenIddictServerTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the request.
        /// </summary>
        public OpenIddictRequest Request
        {
            get => Transaction.Request!;
            set => Transaction.Request = value;
        }

        /// <summary>
        /// Gets or sets the security principal extracted from the access token, if available.
        /// </summary>
        public ClaimsPrincipal? Principal { get; set; }
    }

    /// <summary>
    /// Represents an event called for each validated userinfo request
    /// to allow the user code to decide how the request should be handled.
    /// </summary>
    public class HandleUserinfoRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="HandleUserinfoRequestContext"/> class.
        /// </summary>
        public HandleUserinfoRequestContext(OpenIddictServerTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the request.
        /// </summary>
        public OpenIddictRequest Request
        {
            get => Transaction.Request!;
            set => Transaction.Request = value;
        }

        /// <summary>
        /// Gets or sets the security principal extracted from the access token.
        /// </summary>
        public ClaimsPrincipal Principal { get; set; } = default!;

        /// <summary>
        /// Gets the additional claims returned to the client application.
        /// </summary>
        public Dictionary<string, OpenIddictParameter> Claims { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Gets or sets the value used for the "address" claim.
        /// Note: this value should only be populated if the "address"
        /// scope was requested and accepted by the resource owner.
        /// </summary>
        public JsonElement Address { get; set; }

        /// <summary>
        /// Gets or sets the values used for the "aud" claim.
        /// </summary>
        public HashSet<string> Audiences { get; } = new HashSet<string>(StringComparer.Ordinal);

        /// <summary>
        /// Gets or sets the value used for the "birthdate" claim.
        /// Note: this value should only be populated if the "profile"
        /// scope was requested and accepted by the resource owner.
        /// </summary>
        public string? BirthDate { get; set; }

        /// <summary>
        /// Gets or sets the value used for the "email" claim.
        /// Note: this value should only be populated if the "email"
        /// scope was requested and accepted by the resource owner.
        /// </summary>
        public string? Email { get; set; }

        /// <summary>
        /// Gets or sets the value used for the "email_verified" claim.
        /// Note: this value should only be populated if the "email"
        /// scope was requested and accepted by the resource owner.
        /// </summary>
        public bool? EmailVerified { get; set; }

        /// <summary>
        /// Gets or sets the value used for the "family_name" claim.
        /// Note: this value should only be populated if the "profile"
        /// scope was requested and accepted by the resource owner.
        /// </summary>
        public string? FamilyName { get; set; }

        /// <summary>
        /// Gets or sets the value used for the "given_name" claim.
        /// Note: this value should only be populated if the "profile"
        /// scope was requested and accepted by the resource owner.
        /// </summary>
        public string? GivenName { get; set; }

        /// <summary>
        /// Gets or sets the value used for the "phone_number" claim.
        /// Note: this value should only be populated if the "phone"
        /// scope was requested and accepted by the resource owner.
        /// </summary>
        public string? PhoneNumber { get; set; }

        /// <summary>
        /// Gets or sets the value used for the "phone_number_verified" claim.
        /// Note: this value should only be populated if the "phone"
        /// scope was requested and accepted by the resource owner.
        /// </summary>
        public bool? PhoneNumberVerified { get; set; }

        /// <summary>
        /// Gets or sets the value used for the "preferred_username" claim.
        /// Note: this value should only be populated if the "profile"
        /// scope was requested and accepted by the resource owner.
        /// </summary>
        public string? PreferredUsername { get; set; }

        /// <summary>
        /// Gets or sets the value used for the "profile" claim.
        /// Note: this value should only be populated if the "profile"
        /// scope was requested and accepted by the resource owner.
        /// </summary>
        public string? Profile { get; set; }

        /// <summary>
        /// Gets or sets the unique value
        /// used for the mandatory "sub" claim.
        /// </summary>
        public string? Subject { get; set; }

        /// <summary>
        /// Gets or sets the value used for the "website" claim.
        /// Note: this value should only be populated if the "profile"
        /// scope was requested and accepted by the resource owner.
        /// </summary>
        public string? Website { get; set; }
    }

    /// <summary>
    /// Represents an event called before the userinfo response is returned to the caller.
    /// </summary>
    public class ApplyUserinfoResponseContext : BaseRequestContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ApplyUserinfoResponseContext"/> class.
        /// </summary>
        public ApplyUserinfoResponseContext(OpenIddictServerTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the request, or <see langword="null"/> if it couldn't be extracted.
        /// </summary>
        public OpenIddictRequest? Request
        {
            get => Transaction.Request;
            set => Transaction.Request = value;
        }

        /// <summary>
        /// Gets or sets the response.
        /// </summary>
        public OpenIddictResponse Response
        {
            get => Transaction.Response!;
            set => Transaction.Response = value;
        }

        /// <summary>
        /// Gets the error code returned to the client application.
        /// When the response indicates a successful response,
        /// this property returns <see langword="null"/>.
        /// </summary>
        public string? Error => Response.Error;
    }
}
