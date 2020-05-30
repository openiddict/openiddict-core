using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Moq;
using OpenIddict.Abstractions;
using Xunit;

namespace OpenIddict.Validation.AspNetCore.Tests
{
    public class OpenIddictValidationAspNetCoreHandlersTests
    {
        public class InferIssuerFromHostTests
        {
            [Fact]
            public async Task HandleAsyncShouldThrowWhenContextIsNull()
            {
                //arrange
                var handler = new OpenIddictValidationAspNetCoreHandlers.InferIssuerFromHost();
                OpenIddictValidationEvents.ProcessRequestContext context = null;
                string expectedErrorMessage = "";
#if NETCOREAPP3_1
    expectedErrorMessage = "Value cannot be null. (Parameter '{0}')";
#elif NETCOREAPP2_1 || NET461
    expectedErrorMessage = "Value cannot be null.\r\nParameter name: {0}";
#endif

                //act
                var exception = await Assert.ThrowsAsync<ArgumentNullException>(() => handler.HandleAsync(context).AsTask());

                //assert
                Assert.Equal(string.Format(expectedErrorMessage, nameof(context)), exception.Message);
            }

            [Fact]
            public async Task HandleAsyncShouldThrowWhenTheRequestCanNotBeResolved()
            {
                //arrange
                var handler = new OpenIddictValidationAspNetCoreHandlers.InferIssuerFromHost();
                var transaction = new OpenIddictValidationTransaction();

                var context = new OpenIddictValidationEvents.ProcessRequestContext(transaction);

                string expectedErrorMessage = "The ASP.NET Core HTTP request cannot be resolved.";

                //act
                var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => handler.HandleAsync(context).AsTask());

                //assert
                Assert.Equal(expectedErrorMessage, exception.Message);
            }

            [Fact]
            public async Task HandleAsyncShouldNotChangeIssuerWhenAnIssuerAlreadyExists()
            {
                //arrange
                var handler = new OpenIddictValidationAspNetCoreHandlers.InferIssuerFromHost();
                var transaction = new OpenIddictValidationTransaction();

                var request = new Mock<HttpRequest>();
                UseRequest(transaction, request.Object);

                var context = new OpenIddictValidationEvents.ProcessRequestContext(transaction);
                var expectedIssuer = new Uri("https://localhost/oidc");
                context.Issuer = expectedIssuer;

                //act
                await handler.HandleAsync(context);

                //assert
                Assert.Equal(expectedIssuer, context.Issuer);
            }

            private void UseRequest(OpenIddictValidationTransaction transaction, HttpRequest request)
            {
                transaction.Properties.Add(typeof(HttpRequest).FullName, new WeakReference<HttpRequest>(request));
            }

            private void AssertRejection(OpenIddictValidationEvents.ProcessRequestContext context, string error, string errorDescription)
            {
                Assert.True(context.IsRejected);
                Assert.Equal(error, context.Error);
                Assert.Equal(errorDescription, context.ErrorDescription);
            }

            [Fact]
            public async Task HandleAsyncShouldRejectTheRequestWhenThereIsNoHost()
            {
                //arrange
                var handler = new OpenIddictValidationAspNetCoreHandlers.InferIssuerFromHost();
                var transaction = new OpenIddictValidationTransaction();

                var request = new Mock<HttpRequest>();
                request.SetupGet(x => x.Host).Returns(new HostString(null));
                UseRequest(transaction, request.Object);

                var context = new OpenIddictValidationEvents.ProcessRequestContext(transaction);
                
                //act
                await handler.HandleAsync(context);

                //assert
                AssertRejection(context, 
                    OpenIddictConstants.Errors.InvalidRequest, 
                    "The mandatory 'Host' header is missing.");
            }

            [Fact]
            public async Task HandleAsyncShouldRejectTheRequestWhenTheRequestIsNotValid()
            {
                //arrange
                var handler = new OpenIddictValidationAspNetCoreHandlers.InferIssuerFromHost();
                var transaction = new OpenIddictValidationTransaction();

                var request = new Mock<HttpRequest>();
                request.SetupGet(x => x.Host).Returns(new HostString("localhost"));
                request.SetupGet(x => x.Scheme).Returns("https");

                //using a super long uri was the simplest way to trigger the invalid uri condition
                //0xFFF0 found in the internals of the Uri code
                //see: Uri.c_MaxUriBufferSize
                var invalidPathString = new PathString("/oidc/" + new string(Enumerable.Repeat('a', 0xFFF0).ToArray()));
                request.SetupGet(x => x.PathBase).Returns(invalidPathString);
                UseRequest(transaction, request.Object);

                var context = new OpenIddictValidationEvents.ProcessRequestContext(transaction);

                //act
                await handler.HandleAsync(context);

                //assert
                AssertRejection(context,
                    OpenIddictConstants.Errors.InvalidRequest,
                    "The specified 'Host' header is invalid.");
            }

            [Fact]
            public async Task HandleAsyncShouldSetTheIssuerToTheRequestedUri()
            {
                //arrange
                var handler = new OpenIddictValidationAspNetCoreHandlers.InferIssuerFromHost();
                var transaction = new OpenIddictValidationTransaction();

                var request = new Mock<HttpRequest>();
                request.SetupGet(x => x.Host).Returns(new HostString("localhost"));
                request.SetupGet(x => x.Scheme).Returns("https");
                request.SetupGet(x => x.PathBase).Returns(new PathString("/oidc"));
                UseRequest(transaction, request.Object);

                var context = new OpenIddictValidationEvents.ProcessRequestContext(transaction);

                var expectedIssuer = new Uri("https://localhost/oidc");

                //act
                await handler.HandleAsync(context);

                //assert
                Assert.Equal(expectedIssuer, context.Issuer);
            }
        }
    }
}