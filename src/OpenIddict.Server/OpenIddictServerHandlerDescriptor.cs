/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.ComponentModel;
using System.Diagnostics;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Extensions.DependencyInjection;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Server
{
    /// <summary>
    /// Represents an immutable descriptor of an OpenIddict server event handler.
    /// </summary>
    [DebuggerDisplay("{ServiceDescriptor?.ServiceType}")]
    public class OpenIddictServerHandlerDescriptor
    {
        /// <summary>
        /// Creates a new instance of the <see cref="OpenIddictServerHandlerDescriptor"/> class.
        /// </summary>
        private OpenIddictServerHandlerDescriptor() { }

        /// <summary>
        /// Gets the context type associated with the event.
        /// </summary>
        public Type ContextType { get; private set; }

        /// <summary>
        /// Gets the list of filters responsible of excluding the handler
        /// from the activated handlers if it doesn't meet the criteria.
        /// </summary>
        public ImmutableArray<Type> FilterTypes { get; private set; } = ImmutableArray.Create<Type>();

        /// <summary>
        /// Gets the order assigned to the handler.
        /// </summary>
        public int Order { get; private set; }

        /// <summary>
        /// Gets the service descriptor associated with the handler.
        /// </summary>
        public ServiceDescriptor ServiceDescriptor { get; private set; }

        /// <summary>
        /// Gets the type associated with the handler.
        /// </summary>
        public OpenIddictServerHandlerType Type { get; private set; }

        /// <summary>
        /// Creates a builder allowing to initialize an immutable descriptor.
        /// </summary>
        /// <typeparam name="TContext">The event context type.</typeparam>
        /// <returns>A new descriptor builder.</returns>
        public static Builder<TContext> CreateBuilder<TContext>() where TContext : BaseContext
            => new Builder<TContext>();

        /// <summary>
        /// Contains methods allowing to build a descriptor instance.
        /// </summary>
        /// <typeparam name="TContext">The event context type.</typeparam>
        public class Builder<TContext> where TContext : BaseContext
        {
            private ServiceDescriptor _descriptor;
            private readonly List<Type> _filterTypes = new List<Type>();
            private int _order;
            private OpenIddictServerHandlerType _type;

            /// <summary>
            /// Adds the type of a handler filter to the filters list.
            /// </summary>
            /// <param name="type">The event handler filter type.</param>
            /// <returns>The builder instance, so that calls can be easily chained.</returns>
            public Builder<TContext> AddFilter([NotNull] Type type)
            {
                if (type == null)
                {
                    throw new ArgumentNullException(nameof(type));
                }

                if (!typeof(IOpenIddictServerHandlerFilter<>).MakeGenericType(typeof(TContext)).IsAssignableFrom(type))
                {
                    throw new InvalidOperationException("The specified service type is not valid.");
                }

                _filterTypes.Add(type);

                return this;
            }

            /// <summary>
            /// Adds the type of a handler filter to the filters list.
            /// </summary>
            /// <typeparam name="TFilter">The event handler filter type.</typeparam>
            /// <returns>The builder instance, so that calls can be easily chained.</returns>
            public Builder<TContext> AddFilter<TFilter>()
                where TFilter : IOpenIddictServerHandlerFilter<TContext>
                => AddFilter(typeof(TFilter));

            /// <summary>
            /// Sets the service descriptor.
            /// </summary>
            /// <param name="descriptor">The service descriptor.</param>
            /// <returns>The builder instance, so that calls can be easily chained.</returns>
            public Builder<TContext> SetServiceDescriptor([NotNull] ServiceDescriptor descriptor)
            {
                if (descriptor == null)
                {
                    throw new ArgumentNullException(nameof(descriptor));
                }

                var type = descriptor.ServiceType;
                if (!typeof(IOpenIddictServerHandler<>).MakeGenericType(typeof(TContext)).IsAssignableFrom(type))
                {
                    throw new InvalidOperationException("The specified service type is not valid.");
                }

                _descriptor = descriptor;

                return this;
            }

            /// <summary>
            /// Sets the order in which the event handler will be invoked.
            /// </summary>
            /// <param name="order">The handler order.</param>
            /// <returns>The builder instance, so that calls can be easily chained.</returns>
            public Builder<TContext> SetOrder(int order)
            {
                _order = order;

                return this;
            }

            /// <summary>
            /// Sets the type associated to the handler.
            /// </summary>
            /// <param name="type">The handler type.</param>
            /// <returns>The builder instance, so that calls can be easily chained.</returns>
            public Builder<TContext> SetType(OpenIddictServerHandlerType type)
            {
                if (!Enum.IsDefined(typeof(OpenIddictServerHandlerType), type))
                {
                    throw new InvalidEnumArgumentException(nameof(type), (int) type, typeof(OpenIddictServerHandlerType));
                }

                _type = type;

                return this;
            }

            /// <summary>
            /// Configures the descriptor to use the specified inline handler.
            /// </summary>
            /// <param name="handler">The handler instance.</param>
            /// <returns>The builder instance, so that calls can be easily chained.</returns>
            public Builder<TContext> UseInlineHandler([NotNull] Func<TContext, ValueTask> handler)
            {
                if (handler == null)
                {
                    throw new ArgumentNullException(nameof(handler));
                }

                return UseSingletonHandler(new OpenIddictServerHandler<TContext>(handler));
            }

            /// <summary>
            /// Configures the descriptor to use the specified scoped handler.
            /// </summary>
            /// <typeparam name="THandler">The handler type.</typeparam>
            /// <returns>The builder instance, so that calls can be easily chained.</returns>
            public Builder<TContext> UseScopedHandler<THandler>()
                where THandler : IOpenIddictServerHandler<TContext>
                => SetServiceDescriptor(new ServiceDescriptor(
                    typeof(THandler), typeof(THandler), ServiceLifetime.Scoped));

            /// <summary>
            /// Configures the descriptor to use the specified singleton handler.
            /// </summary>
            /// <typeparam name="THandler">The handler type.</typeparam>
            /// <returns>The builder instance, so that calls can be easily chained.</returns>
            public Builder<TContext> UseSingletonHandler<THandler>()
                where THandler : IOpenIddictServerHandler<TContext>
                => SetServiceDescriptor(new ServiceDescriptor(
                    typeof(THandler), typeof(THandler), ServiceLifetime.Singleton));

            /// <summary>
            /// Configures the descriptor to use the specified singleton handler.
            /// </summary>
            /// <typeparam name="THandler">The handler type.</typeparam>
            /// <param name="handler">The handler instance.</param>
            /// <returns>The builder instance, so that calls can be easily chained.</returns>
            public Builder<TContext> UseSingletonHandler<THandler>([NotNull] THandler handler)
                where THandler : IOpenIddictServerHandler<TContext>
            {
                if (handler == null)
                {
                    throw new ArgumentNullException(nameof(handler));
                }

                return SetServiceDescriptor(new ServiceDescriptor(typeof(THandler), handler));
            }

            /// <summary>
            /// Build a new descriptor instance, based on the parameters that were previously set.
            /// </summary>
            /// <returns>The builder instance, so that calls can be easily chained.</returns>
            public OpenIddictServerHandlerDescriptor Build() => new OpenIddictServerHandlerDescriptor
            {
                ContextType = typeof(TContext),
                FilterTypes = _filterTypes.ToImmutableArray(),
                Order = _order,
                ServiceDescriptor = _descriptor ?? throw new InvalidOperationException("No service descriptor was set."),
                Type = _type
            };
        }
    }
}
