using System.Collections.Immutable;
using System.Runtime.CompilerServices;

#if !SUPPORTS_IMMUTABLE_COLLECTIONS_MARSHAL
namespace System.Runtime.InteropServices;

internal static class ImmutableCollectionsMarshal
{
    public static ImmutableArray<T> AsImmutableArray<T>(T[] array) => Unsafe.As<T[], ImmutableArray<T>>(ref array);
}
#endif