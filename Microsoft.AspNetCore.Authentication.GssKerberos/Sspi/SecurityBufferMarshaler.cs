using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Collections.Concurrent;
using System.Threading;
using System.Collections.Generic;

namespace Microsoft.AspNetCore.Authentication.GssKerberos
{
    internal class SecurityBufferMarshaler : ICustomMarshaler
    {
        private static int sizeOfSecBuffer = Marshal.SizeOf<SecBuffer>();
        private static int sizeOfSecBufferDesc = Marshal.SizeOf<SecBufferDesc>();

        private static SecurityBufferMarshaler instance = new SecurityBufferMarshaler();
        private static readonly Dictionary<IntPtr, SecurityBufferDescription> objects
            = new Dictionary<IntPtr, SecurityBufferDescription>();


        public static ICustomMarshaler GetInstance(string cookie)
            => instance;

        public IntPtr MarshalManagedToNative(object value)
        {
            if (!(value is SecurityBufferDescription description))
                throw new ArgumentException(nameof(value));

            var size = sizeOfSecBufferDesc + description.Buffers.Sum(buffer => sizeOfSecBuffer + buffer.Buffer.Length);
            var heap = Marshal.AllocHGlobal(size);

            // Write the top-level SecBufferDesc first
            Marshal.WriteInt32(heap, 0, description.Version);
            Marshal.WriteInt32(heap, 4, description.Buffers.Length);
            Marshal.WriteIntPtr(heap, 8, IntPtr.Add(heap, sizeOfSecBufferDesc));

            // These offsets track the location we need to write the next sec buffer and their data
            var arrayoffset = sizeOfSecBufferDesc;
            var dataoffset = IntPtr.Add(heap, arrayoffset + sizeOfSecBuffer * description.Buffers.Length);

            foreach (var bufferdescription in description.Buffers)
            {
                Marshal.WriteInt32(heap, arrayoffset, bufferdescription.Buffer.Length);
                Marshal.WriteInt32(heap, arrayoffset + 4, (int) bufferdescription.BufferType);
                Marshal.WriteIntPtr(heap, arrayoffset + 8, dataoffset);
                Marshal.Copy(bufferdescription.Buffer, 0, dataoffset, bufferdescription.Buffer.Length);

                arrayoffset += sizeOfSecBuffer;
                dataoffset += bufferdescription.Buffer.Length;
            }

            // store a reference to the managed object keyed by the address of the native object we created for
            // it. We will use this key to marshal the data back to the same object reference
            lock (objects)
            {
                objects[heap] = description;
            }

            return heap;
        }

        public object MarshalNativeToManaged(IntPtr native)
        {
            // fetch the managed object that corresponds to the native objects address and remove the object
            // from the dictionary, we have marshalled it back now
            SecurityBufferDescription reference;
            lock (objects)
            {
                reference = objects[native];
                objects.Remove(native);
            }

            // update the managed object with the data from the native object
            var description = Marshal.PtrToStructure<SecBufferDesc>(native);
            reference.Buffers = new SecurityBuffer[description.cBuffers];
            for (var i = 0; i < description.cBuffers; i++)
            {
                var buffer = Marshal.PtrToStructure<SecBuffer>(description.Buffers + sizeOfSecBuffer * i);
                var bytes = new byte[buffer.cbBuffer];
                Marshal.Copy(buffer.pvBuffer, bytes, 0, buffer.cbBuffer);
                reference.Buffers[i] = new SecurityBuffer
                {
                    Buffer = bytes,
                    BufferType = (SecurityBufferType) buffer.cbBufferType
                };
            }
            return reference;
        }

        
        public void CleanUpNativeData(IntPtr native)
        {
            Marshal.FreeHGlobal(native);
        }

        public void CleanUpManagedData(object value)
        {
            // no-op
        }

        public int GetNativeDataSize() => -1;

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
