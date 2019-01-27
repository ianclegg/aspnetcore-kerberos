using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Collections.Concurrent;
using System.Threading;

namespace Microsoft.AspNetCore.Authentication.GssKerberos
{
    internal class SecurityBufferMarshaler : ICustomMarshaler
    {
        private int _cb;
        private IntPtr _heap;
        private SecurityBufferDescription _reference;
        
        private static readonly ConcurrentDictionary<(int, string), ICustomMarshaler> Instances
            = new ConcurrentDictionary<(int, string), ICustomMarshaler>();

        private static int Id => Thread.CurrentThread.ManagedThreadId;

        public static ICustomMarshaler GetInstance(string cookie)
        {
            // We need to marshal two different structures when making a call to AcceptSecurityContext, obiously these
            // will be on the same thread, so we use the cookie to distinugsh betwen the two, we'll also need the thread
            // id to prevent corruption from concurrent calls.
            return Instances.GetOrAdd((Id, cookie), _ => new SecurityBufferMarshaler());
        }

        public IntPtr MarshalManagedToNative(object value)
        {
            // Take a reference to the object that was passed into the Marshaler, we'll need this because we need to
            // update it 'in place' when we marshal back. We'll also allocate a single contiguous block using the HGLOBAL
            // heap manager to store the description structure, the array of buffer structures and all the buffers.
            // A single allocation is faster, leads to less fragmentation and it's easier to free afterwards.
            _reference = (SecurityBufferDescription) value;

            _cb = Marshal.SizeOf<SecBufferDesc>() +
                  _reference.Buffers.Sum(b => Marshal.SizeOf<SecBuffer>() + b.Buffer.Length);
            _heap = Marshal.AllocHGlobal(_cb);

            // Write the top-level SecBufferDesc first
            Marshal.WriteInt32(_heap, 0, _reference.Version);
            Marshal.WriteInt32(_heap, 4, _reference.Buffers.Length);
            Marshal.WriteIntPtr(_heap, 8, IntPtr.Add(_heap, Marshal.SizeOf<IntPtr>() + 8));

            // These offsets track the location we need to write the next sec buffer and their data
            var arrayoffset = Marshal.SizeOf<SecBufferDesc>();
            var dataoffset = IntPtr.Add(_heap, arrayoffset + Marshal.SizeOf<SecBuffer>() * _reference.Buffers.Length);

            foreach (var bufferdescription in _reference.Buffers)
            {
                Marshal.WriteInt32(_heap, arrayoffset, bufferdescription.Buffer.Length);
                Marshal.WriteInt32(_heap, arrayoffset + 4, (int) bufferdescription.BufferType);
                Marshal.WriteIntPtr(_heap, arrayoffset + 8, dataoffset);
                Marshal.Copy(bufferdescription.Buffer, 0, dataoffset, bufferdescription.Buffer.Length);

                arrayoffset += Marshal.SizeOf<SecBuffer>();
                dataoffset += bufferdescription.Buffer.Length;
            }

            return _heap;
        }

        public object MarshalNativeToManaged(IntPtr native)
        {
            var description = Marshal.PtrToStructure<SecBufferDesc>(native);

            var buffers = new SecurityBuffer[description.cBuffers];
            var cb = Marshal.SizeOf<SecBuffer>();

            for (var i = 0; i < description.cBuffers; i++)
            {
                var buffer = Marshal.PtrToStructure<SecBuffer>(description.Buffers + cb * i);
                var bytes = new byte[buffer.cbBuffer];
                Marshal.Copy(buffer.pvBuffer, bytes, 0, buffer.cbBuffer);
                buffers[i] = new SecurityBuffer
                {
                    Buffer = bytes,
                    BufferType = (SecurityBufferType) buffer.cbBufferType
                };
            }

            _reference.Version = description.ulVersion;
            _reference.Buffers = buffers;

            return _reference;
        }

        
        public void CleanUpNativeData(IntPtr native)
        {
            Marshal.FreeHGlobal(_heap);
        }

        public void CleanUpManagedData(object value)
        {

        }

        public int GetNativeDataSize() => _cb;

        [StructLayout(LayoutKind.Sequential)]
        internal struct SecBufferDesc
        {
            public int ulVersion;
            public int cBuffers;
            public IntPtr Buffers;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SecBuffer
        {
            public int cbBuffer;
            public int cbBufferType;
            public IntPtr pvBuffer;
        }
    }
}
