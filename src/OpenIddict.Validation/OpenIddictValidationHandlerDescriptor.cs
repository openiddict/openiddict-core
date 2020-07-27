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
using Microsoft.Extensions.DependencyInjection;
using static OpenIddict.Validation.OpenIddictValidationEvents;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.Validation
{
    /// <summary>
    /// Represents an immutable descriptor of an OpenIddict validation event handler.
    /// </summary>
    [DebuggerDisplay("{ServiceDescriptor?.ServiceType}")]
    public class OpenIddictValidationHandlerDescriptor
    {
        /// <summary>
        /// Creates a new instance of the <see cref="OpenIddictValidationHandlerDescriptor"/> class.
        /// </summary>
        private OpenIddictValidationHandlerDescriptor() { }

        /// <summary>
        /// Gets the context type associated with the event.
        /// </summary>
        public Type ContextType { get; private set; } = default!;

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
        public ServiceDescriptor ServiceDescriptor { get; private set; } = default!;

        /// <summary>
        /// Gets the type associated with the handler.
        /// </summary>
        public OpenIddictValidationHandlerType Type { get; private set; }

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
            private ServiceDescriptor? _descriptor;
            private readonly List<Type> _filterTypes = new List<Type>();
            private int _order;
            private OpenIddictValidationHandlerType _type;

            /// <summary>
            /// Adds the type of a handler filter to the filters list.
            /// </summary>
            /// <param name="type">The event handler filter type.</param>
            /// <returns>The builder instance, so that calls can be easily chained.</returns>
            public Builder<TContext> AddFilter(Type type)
            {
                if (type == null)
                {
                    throw new ArgumentNullException(nameof(type));
                }

                if (!typeof(IOpenIddictValidationHandlerFilter<>).MakeGenericType(typeof(TContext)).IsAssignableFrom(type))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1103));
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
                where TFilter : IOpenIddictValidationHandlerFilter<TContext>
                => AddFilter(typeof(TFilter));

            /// <summary>
            /// Sets the service descriptor.
            /// </summary>
            /// <param name="descriptor">The service descriptor.</param>
            /// <returns>The builder instance, so that calls can be easily chained.</returns>
            public Builder<TContext> SetServiceDescriptor(ServiceDescriptor descriptor)
            {
                if (descriptor == null)
                {
                    throw new ArgumentNullException(nameof(descriptor));
                }

                var type = descriptor.ServiceType;
                if (!typeof(IOpenIddictValidationHandler<>).MakeGenericType(typeof(TContext)).IsAssignableFrom(type))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1103));
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
            public Builder<TContext> SetType(OpenIddictValidationHandlerType type)
            {
                if (!Enum.IsDefined(typeof(OpenIddictValidationHandlerType), type))
                {
                    throw new InvalidEnumArgumentException(nameof(type), (int) type, typeof(OpenIddictValidationHandlerType));
                }

                _type = type;

                return this;
            }

            /// <summary>
            /// Configures the descriptor to use the specified inline handler.
            /// </summary>
            /// <param name="handler">The handler instance.</param>
            /// <returns>The builder instance, so that calls can be easily chained.</returns>
            public Builder<TContext> UseInlineHandler(Func<TContext, ValueTask> handler)
            {
                if (handler == null)
                {
                    throw new ArgumentNullException(nameof(handler));
                }

                return UseSingletonHandler(new OpenIddictValidationHandler<TContext>(handler));
            }

            /// <summary>
            /// Configures the descriptor to use the specified scoped handler.
            /// </summary>
            /// <typeparam name="THandler">The handler type.</typeparam>
            /// <returns>The builder instance, so that calls can be easily chained.</returns>
            public Builder<TContext> UseScopedHandler<THandler>()
                where THandler : IOpenIddictValidationHandler<TContext>
                => SetServiceDescriptor(new ServiceDescriptor(
                    typeof(THandler), typeof(THandler), ServiceLifetime.Scoped));

            /// <summary>
            /// Configures the descriptor to use the specified singleton handler.
            /// </summary>
            /// <typeparam name="THandler">The handler type.</typeparam>
            /// <returns>The builder instance, so that calls can be easily chained.</returns>
            public Builder<TContext> UseSingletonHandler<THandler>()
                where THandler : IOpenIddictValidationHandler<TContext>
                => SetServiceDescriptor(new ServiceDescriptor(
                    typeof(THandler), typeof(THandler), ServiceLifetime.Singleton));

            /// <summary>
            /// Configures the descriptor to use the specified singleton handler.
            /// </summary>
            /// <typeparam name="THandler">The handler type.</typeparam>
            /// <param name="handler">The handler instance.</param>
            /// <returns>The builder instance, so that calls can be easily chained.</returns>
            public Builder<TContext> UseSingletonHandler<THandler>(THandler handler)
                where THandler : IOpenIddictValidationHandler<TContext>
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
            public OpenIddictValidationHandlerDescriptor Build() => new OpenIddictValidationHandlerDescriptor
            {
                ContextType = typeof(TContext),
                FilterTypes = _filterTypes.ToImmutableArray(),
                Order = _order,
                ServiceDescriptor = _descriptor ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID1104)),
                Type = _type
            };
        }
    }
}
