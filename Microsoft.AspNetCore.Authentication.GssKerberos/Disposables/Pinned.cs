using System;
using System.Runtime.InteropServices;

namespace Microsoft.AspNetCore.Authentication.GssKerberos.Disposables
{
    /// <summary>
    /// Memory pinned object
    /// </summary>
    internal static class Pinned
    {
        /// <summary>
        /// Create memory pinned object from <paramref name="value"/>
        /// </summary>
        /// <typeparam name="T">Any class type</typeparam>
        /// <param name="value">Value to pin</param>
        /// <returns>Pinned value</returns>
        internal static Pinned<T> From<T>(T value) where T : class => new Pinned<T>(value);
    }

    /// <summary>
    /// Memory pinned object
    /// </summary>
    /// <typeparam name="T">Any class type</typeparam>
    internal sealed class Pinned<T> : IDisposable where T : class
    {
        /// <summary>
        /// Original object value, can be used with <code>ref</code>
        /// </summary>
        internal readonly T Value;
        
        /// <summary>
        /// In memory address of the object
        /// </summary>
        internal IntPtr Address { get; }

        private GCHandle _handle;

        /// <summary>
        /// Create memory pinned object from <paramref name="value"/>
        /// </summary>
        /// <param name="value">Value to pin</param>
        internal Pinned(T value)
        {
            Value = value;
            _handle = GCHandle.Alloc(value, GCHandleType.Pinned);
            Address = _handle.AddrOfPinnedObject();
        }

        /// <summary>
        /// Returns address of object in memory
        /// </summary>
        public static implicit operator IntPtr(Pinned<T> p)
        {
            return p.Address;
        }

        /// <summary>
        /// Returns original object value
        /// </summary>
        public static implicit operator T(Pinned<T> p)
        {
            return p.Value;
        }

        public void Dispose()
        {
            _handle.Free();
        }
    }
}