// ReSharper disable InconsistentNaming
namespace Microsoft.AspNetCore.Authentication.GssKerberos.Sspi
{
    enum SecurityBufferType : uint
    {
        SECBUFFER_EMPTY = 0,
        SECBUFFER_DATA = 1,
        SECBUFFER_TOKEN = 2,
        SECBUFFER_READONLY = 0x80000000
    }

    internal struct SecurityBuffer
    {
        public byte[] Buffer;
        public SecurityBufferType BufferType;
    }

    internal class SecurityBufferDescription
    {
        public int Version;
        public SecurityBuffer[] Buffers;
    }
}
