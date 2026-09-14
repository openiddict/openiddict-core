/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Patterns;

namespace OpenIddict.Server.AspNetCore.AdminUI;

/// <summary>
/// Detects the endpoints registered on the same route builder that would make the admin UI routes ambiguous
/// (e.g the admin API mapped with the same prefix), which would otherwise only be reported at request time.
/// </summary>
internal sealed class OpenIddictServerAspNetCoreAdminUIConflictDetector
{
    // Note: building the endpoints of the other data sources may (indirectly) build the endpoints
    // of another admin UI instance, whose detector must not recursively inspect this instance.
    [ThreadStatic] private static bool _detecting;

    private readonly IEndpointRouteBuilder _endpoints;
    private readonly EndpointDataSource _source;
    private readonly string _prefix;
    private readonly List<(string Method, RoutePattern Pattern)> _routes = [];
    private readonly Lazy<(string Method, RoutePattern Pattern, Endpoint Endpoint)?> _conflict;

    public OpenIddictServerAspNetCoreAdminUIConflictDetector(
        IEndpointRouteBuilder endpoints, EndpointDataSource source, string prefix)
    {
        _endpoints = endpoints;
        _source = source;
        _prefix = prefix;
        _conflict = new(FindConflict, LazyThreadSafetyMode.ExecutionAndPublication);
    }

    public void Add(string method, string path)
        => _routes.Add((method, RoutePatternFactory.Parse(_prefix.TrimEnd('/') + "/" + path)));

    public void EnsureNoConflict()
    {
        if (_detecting)
        {
            return;
        }

        if (_conflict.Value is var (method, pattern, endpoint))
        {
            throw new InvalidOperationException(SR.FormatID0684(method, pattern.RawText,
                endpoint.DisplayName ?? (endpoint as RouteEndpoint)?.RoutePattern.RawText));
        }
    }

    private (string Method, RoutePattern Pattern, Endpoint Endpoint)? FindConflict()
    {
        _detecting = true;

        try
        {
            foreach (var source in _endpoints.DataSources.ToArray())
            {
                if (ReferenceEquals(source, _source))
                {
                    continue;
                }

                foreach (var endpoint in source.Endpoints.OfType<RouteEndpoint>())
                {
                    var methods = endpoint.Metadata.GetMetadata<IHttpMethodMetadata>()?.HttpMethods;

                    foreach (var (method, pattern) in _routes)
                    {
                        if ((methods is null or { Count: 0 } || methods.Contains(method, StringComparer.OrdinalIgnoreCase)) &&
                            AreEquivalent(pattern, endpoint.RoutePattern))
                        {
                            return (method, pattern, endpoint);
                        }
                    }
                }
            }

            return null;
        }

        finally
        {
            _detecting = false;
        }
    }

    // Note: two routes are only considered ambiguous when they have the same precedence and match the same paths:
    // the literal segments must be identical (routing is case-insensitive) and the parameter segments must be
    // simple parameters without constraints, default values or catch-all semantics (that could disambiguate them).
    private static bool AreEquivalent(RoutePattern left, RoutePattern right)
    {
        if (left.PathSegments.Count != right.PathSegments.Count)
        {
            return false;
        }

        for (var index = 0; index < left.PathSegments.Count; index++)
        {
            if (left.PathSegments[index] is not { IsSimple: true, Parts: [var first] } ||
                right.PathSegments[index] is not { IsSimple: true, Parts: [var second] })
            {
                return false;
            }

            switch ((first, second))
            {
                case (RoutePatternLiteralPart a, RoutePatternLiteralPart b)
                    when string.Equals(a.Content, b.Content, StringComparison.OrdinalIgnoreCase):
                    continue;

                case (RoutePatternParameterPart a, RoutePatternParameterPart b)
                    when IsUnconstrained(left, a) && IsUnconstrained(right, b):
                    continue;

                default:
                    return false;
            }
        }

        return true;

        static bool IsUnconstrained(RoutePattern pattern, RoutePatternParameterPart parameter)
            => !parameter.IsCatchAll && !parameter.IsOptional && parameter.Default is null && parameter.ParameterPolicies.Count is 0 &&
               (!pattern.ParameterPolicies.TryGetValue(parameter.Name, out var policies) || policies.Count is 0);
    }
}
