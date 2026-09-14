/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace OpenIddict.Server.SystemNetHttp.Tests;

public class OpenIddictServerSystemNetHttpRequestObjectFetcherTests
{
    private const string ContentType = "application/oauth-authz-req+jwt";
    private static readonly Uri RequestUri = new("https://www.fabrikam.com/request_objects/1", UriKind.Absolute);

    [Theory]
    [InlineData("0.1.2.3", false)]
    [InlineData("10.0.0.1", false)]
    [InlineData("100.64.0.1", false)]
    [InlineData("127.0.0.1", false)]
    [InlineData("169.254.169.254", false)]
    [InlineData("172.16.0.1", false)]
    [InlineData("172.31.255.255", false)]
    [InlineData("192.168.1.1", false)]
    [InlineData("198.18.0.1", false)]
    [InlineData("224.0.0.1", false)]
    [InlineData("255.255.255.255", false)]
    [InlineData("::", false)]
    [InlineData("::1", false)]
    [InlineData("::ffff:127.0.0.1", false)]
    [InlineData("::ffff:10.0.0.1", false)]
    [InlineData("64:ff9b::a00:1", false)]
    [InlineData("2002:a00:1::", false)]
    [InlineData("2001:db8::1", false)]
    [InlineData("fc00::1", false)]
    [InlineData("fd12:3456::1", false)]
    [InlineData("fe80::1", false)]
    [InlineData("ff02::1", false)]
    [InlineData("8.8.8.8", true)]
    [InlineData("172.32.0.1", true)]
    [InlineData("100.128.0.1", true)]
    [InlineData("::ffff:8.8.8.8", true)]
    [InlineData("64:ff9b::808:808", true)]
    [InlineData("2606:4700:4700::1111", true)]
    public void IsPublicAddress_ReturnsExpectedResult(string address, bool result)
        => Assert.Equal(result, OpenIddictServerSystemNetHttpHelpers.IsPublicAddress(IPAddress.Parse(address)));

    [Fact]
    public async Task FetchAsync_ReturnsRequestObject()
    {
        // Arrange
        HttpRequestMessage? message = null;

        using var fetcher = CreateFetcher(request =>
        {
            message = request;
            return CreateResponse("eyJhbGciOiJSUzI1NiJ9.e30.c2ln");
        });

        // Act
        var result = await fetcher.FetchAsync(new Uri(RequestUri.AbsoluteUri + "#hash"), CancellationToken.None);

        // Assert
        Assert.Equal("eyJhbGciOiJSUzI1NiJ9.e30.c2ln", result);
        Assert.NotNull(message);
        Assert.Equal(HttpMethod.Get, message.Method);
        Assert.Equal(RequestUri, message.RequestUri);
        Assert.Contains(message.Headers.Accept, header => string.Equals(header.MediaType, ContentType, StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("http://www.fabrikam.com/request_objects/1")]
    [InlineData("https://user:password@www.fabrikam.com/request_objects/1")]
    public async Task FetchAsync_ReturnsNullForInvalidUris(string uri)
    {
        // Arrange
        var sent = false;

        using var fetcher = CreateFetcher(_ =>
        {
            sent = true;
            return CreateResponse("token");
        });

        // Act and assert
        Assert.Null(await fetcher.FetchAsync(new Uri(uri, UriKind.Absolute), CancellationToken.None));
        Assert.False(sent);
    }

    [Theory]
    [InlineData(HttpStatusCode.Found)]
    [InlineData(HttpStatusCode.MovedPermanently)]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.InternalServerError)]
    public async Task FetchAsync_ReturnsNullForNonSuccessfulResponses(HttpStatusCode status)
    {
        // Arrange
        using var fetcher = CreateFetcher(_ =>
        {
            var response = CreateResponse("token");
            response.StatusCode = status;
            response.Headers.Location = new Uri("https://www.fabrikam.com/other");
            return response;
        });

        // Act and assert
        Assert.Null(await fetcher.FetchAsync(RequestUri, CancellationToken.None));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("application/json")]
    [InlineData("text/html")]
    [InlineData("application/jwt")]
    public async Task FetchAsync_ReturnsNullForInvalidContentTypes(string? type)
    {
        // Arrange
        using var fetcher = CreateFetcher(_ =>
        {
            var response = CreateResponse("token");
            response.Content.Headers.ContentType = type is null ? null : new MediaTypeHeaderValue(type);
            return response;
        });

        // Act and assert
        Assert.Null(await fetcher.FetchAsync(RequestUri, CancellationToken.None));
    }

    [Fact]
    public async Task FetchAsync_AcceptsAdditionalContentTypes()
    {
        // Arrange
        using var fetcher = CreateFetcher(_ =>
        {
            var response = CreateResponse("token");
            response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/jwt") { CharSet = "utf-8" };
            return response;
        }, options => options.RequestObjectContentTypes.Add("application/jwt"));

        // Act and assert
        Assert.Equal("token", await fetcher.FetchAsync(RequestUri, CancellationToken.None));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FetchAsync_ReturnsNullForOversizedResponses(bool length)
    {
        // Arrange
        using var fetcher = CreateFetcher(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = length ? new ByteArrayContent(new byte[1025]) : new StreamContent(new UnseekableStream(new byte[1025]))
            };

            response.Content.Headers.ContentType = new MediaTypeHeaderValue(ContentType);
            return response;
        }, options => options.MaximumRequestObjectSize = 1024);

        // Act and assert
        Assert.Null(await fetcher.FetchAsync(RequestUri, CancellationToken.None));
    }

    [Fact]
    public async Task FetchAsync_ReturnsNullForInvalidUtf8Content()
    {
        // Arrange
        using var fetcher = CreateFetcher(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent([0xC3, 0x28]) };
            response.Content.Headers.ContentType = new MediaTypeHeaderValue(ContentType);
            return response;
        });

        // Act and assert
        Assert.Null(await fetcher.FetchAsync(RequestUri, CancellationToken.None));
    }

    [Fact]
    public async Task FetchAsync_ReturnsNullWhenTimeoutExpires()
    {
        // Arrange
        using var fetcher = new OpenIddictServerSystemNetHttpRequestObjectFetcher(
            CreateOptions(options => options.RequestObjectTimeout = TimeSpan.FromMilliseconds(50)),
            NullLogger<OpenIddictServerSystemNetHttpRequestObjectFetcher>.Instance,
            new DelayingHandler());

        // Act and assert
        Assert.Null(await fetcher.FetchAsync(RequestUri, CancellationToken.None));
    }

    [Fact]
    public async Task FetchAsync_ThrowsWhenCallerCancelsOperation()
    {
        // Arrange
        using var fetcher = new OpenIddictServerSystemNetHttpRequestObjectFetcher(
            CreateOptions(), NullLogger<OpenIddictServerSystemNetHttpRequestObjectFetcher>.Instance, new DelayingHandler());

        using var source = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));

        // Act and assert
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await fetcher.FetchAsync(RequestUri, source.Token));
    }

    [Fact]
    public async Task FetchAsync_CachesResponsesAccordingToCacheControlHeaders()
    {
        // Arrange
        var provider = new MutableTimeProvider(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var count = 0;

        using var fetcher = CreateFetcher(_ =>
        {
            var response = CreateResponse("token" + (++count).ToString(CultureInfo.InvariantCulture));
            response.Headers.CacheControl = new CacheControlHeaderValue { MaxAge = TimeSpan.FromMinutes(1) };
            return response;
        }, options => options.TimeProvider = provider);

        // Act and assert
        Assert.Equal("token1", await fetcher.FetchAsync(RequestUri, CancellationToken.None));
        Assert.Equal("token1", await fetcher.FetchAsync(RequestUri, CancellationToken.None));

        // Note: the fragment is part of the cache key.
        Assert.Equal("token2", await fetcher.FetchAsync(new Uri(RequestUri.AbsoluteUri + "#hash"), CancellationToken.None));

        provider.Now += TimeSpan.FromMinutes(2);

        Assert.Equal("token3", await fetcher.FetchAsync(RequestUri, CancellationToken.None));
    }

    [Fact]
    public async Task FetchAsync_CacheLifetimeIsCappedByMaximumCacheLifetime()
    {
        // Arrange
        var provider = new MutableTimeProvider(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var count = 0;

        using var fetcher = CreateFetcher(_ =>
        {
            var response = CreateResponse("token" + (++count).ToString(CultureInfo.InvariantCulture));
            response.Headers.CacheControl = new CacheControlHeaderValue { MaxAge = TimeSpan.FromDays(1) };
            return response;
        }, options =>
        {
            options.MaximumRequestObjectCacheLifetime = TimeSpan.FromMinutes(1);
            options.TimeProvider = provider;
        });

        // Act and assert
        Assert.Equal("token1", await fetcher.FetchAsync(RequestUri, CancellationToken.None));

        provider.Now += TimeSpan.FromMinutes(2);

        Assert.Equal("token2", await fetcher.FetchAsync(RequestUri, CancellationToken.None));
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(false, false)]
    public async Task FetchAsync_DoesNotCacheResponsesThatDisallowCaching(bool store, bool cache)
    {
        // Arrange
        var count = 0;

        using var fetcher = CreateFetcher(_ =>
        {
            var response = CreateResponse("token" + (++count).ToString(CultureInfo.InvariantCulture));

            if (store || cache)
            {
                response.Headers.CacheControl = new CacheControlHeaderValue
                {
                    MaxAge = TimeSpan.FromMinutes(1),
                    NoCache = cache,
                    NoStore = store
                };
            }

            return response;
        });

        // Act and assert
        Assert.Equal("token1", await fetcher.FetchAsync(RequestUri, CancellationToken.None));
        Assert.Equal("token2", await fetcher.FetchAsync(RequestUri, CancellationToken.None));
    }

    [Theory]
    [InlineData("https://127.0.0.1/request_objects/1")]
    [InlineData("https://[::1]/request_objects/1")]
    [InlineData("https://10.0.0.1/request_objects/1")]
    [InlineData("https://169.254.169.254/latest/meta-data")]
    [InlineData("https://localhost/request_objects/1")]
    public async Task FetchAsync_RejectsDisallowedRemoteAddresses(string uri)
    {
        // Arrange
        using var fetcher = new OpenIddictServerSystemNetHttpRequestObjectFetcher(
            CreateOptions(), NullLogger<OpenIddictServerSystemNetHttpRequestObjectFetcher>.Instance);

        // Act and assert
        Assert.Null(await fetcher.FetchAsync(new Uri(uri, UriKind.Absolute), CancellationToken.None));
    }

    [Fact]
    public void UseSystemNetHttp_RegistersFetcher()
    {
        // Arrange
        var services = new ServiceCollection().AddLogging();

        // Act
        services.AddOpenIddict().AddServer().UseSystemNetHttp(options => options
            .AddRequestObjectContentType("application/jwt")
            .SetMaximumRequestObjectSize(1024)
            .SetMaximumRequestObjectCacheLifetime(TimeSpan.Zero)
            .SetRequestObjectTimeout(TimeSpan.FromSeconds(1)));

        // Assert
        using var provider = services.BuildServiceProvider();

        Assert.IsType<OpenIddictServerSystemNetHttpRequestObjectFetcher>(provider.GetRequiredService<IOpenIddictServerRequestObjectFetcher>());

        var options = provider.GetRequiredService<IOptions<OpenIddictServerSystemNetHttpOptions>>().Value;
        Assert.Contains("application/jwt", options.RequestObjectContentTypes);
        Assert.Contains(ContentType, options.RequestObjectContentTypes);
        Assert.Equal(1024, options.MaximumRequestObjectSize);
        Assert.Equal(TimeSpan.Zero, options.MaximumRequestObjectCacheLifetime);
        Assert.Equal(TimeSpan.FromSeconds(1), options.RequestObjectTimeout);
    }

    [Fact]
    public void Builder_RejectsInvalidValues()
    {
        // Arrange
        var builder = new OpenIddictServerSystemNetHttpBuilder(new ServiceCollection());

        // Act and assert
        Assert.Throws<ArgumentOutOfRangeException>(() => builder.SetRequestObjectTimeout(TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() => builder.SetMaximumRequestObjectSize(0));
        Assert.Throws<ArgumentOutOfRangeException>(() => builder.SetMaximumRequestObjectCacheLifetime(TimeSpan.FromSeconds(-1)));
    }

    private static OpenIddictServerSystemNetHttpRequestObjectFetcher CreateFetcher(
        Func<HttpRequestMessage, HttpResponseMessage> handler, Action<OpenIddictServerSystemNetHttpOptions>? configuration = null)
        => new(CreateOptions(configuration), NullLogger<OpenIddictServerSystemNetHttpRequestObjectFetcher>.Instance, new InlineHandler(handler));

    private static IOptionsMonitor<OpenIddictServerSystemNetHttpOptions> CreateOptions(
        Action<OpenIddictServerSystemNetHttpOptions>? configuration = null)
    {
        var services = new ServiceCollection();
        services.Configure(configuration ?? (static _ => { }));

        return services.BuildServiceProvider().GetRequiredService<IOptionsMonitor<OpenIddictServerSystemNetHttpOptions>>();
    }

    private static HttpResponseMessage CreateResponse(string content)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(Encoding.UTF8.GetBytes(content)) };
        response.Content.Headers.ContentType = new MediaTypeHeaderValue(ContentType);

        return response;
    }

    private sealed class InlineHandler(Func<HttpRequestMessage, HttpResponseMessage> handler) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(handler(request));
    }

    private sealed class DelayingHandler : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);

            return CreateResponse("token");
        }
    }

    private sealed class MutableTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = now;

        public override DateTimeOffset GetUtcNow() => Now;
    }

    private sealed class UnseekableStream(byte[] buffer) : MemoryStream(buffer)
    {
        public override bool CanSeek => false;
    }
}
