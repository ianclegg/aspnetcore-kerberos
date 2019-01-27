using System;
using System.Linq;
using System.Runtime.InteropServices;
using Microsoft.AspNetCore.Authentication.GssKerberos.Native;

// ReSharper disable InconsistentNaming
namespace Microsoft.AspNetCore.Authentication.GssKerberos
{
    public struct SecNameInfo
    {
        public string sClientName;
        public string sServerName;
    }

    public class SspiAcceptor : IAcceptor
    {
        private SecurityHandle _credentials;
        private SecurityHandle _context;
        private long _expiryTime;

        private const uint HTTP_SECURITY_ATTRIBUTES =
            SspiInterop.ISC_REQ_REPLAY_DETECT |
            SspiInterop.ISC_REQ_SEQUENCE_DETECT |
            SspiInterop.ISC_REQ_CONNECTION;

        public bool IsEstablished { get; private set; }

        /// <summary>
        /// The UPN of the context initiator
        /// </summary>
        public string Principal { get; private set; }

        /// <summary>
        /// The final negotiated flags
        /// </summary>
        public uint Flags { get; private set; }

        /// <summary>
        /// The time the token expires
        /// </summary>
        public uint Expiry { get; private set; }


        public SspiAcceptor(SspiCredentials credentials)
        {
            _credentials = credentials.Credentials;
        }

        public byte[] Accept(byte[] token)
        {
            // TODO: A SecBufferDesc builder would be nice
            var incomingToken = new SecurityBufferDescription
            {
                Version = 0,
                Buffers = new[]
                {
                    new SecurityBuffer
                    {
                        Buffer = token,
                        BufferType = SecurityBufferType.SECBUFFER_TOKEN
                    }
                }
            };

            var outgoingToken = new SecurityBufferDescription
            {
                Version = 0,
                Buffers = new[]
                {
                    new SecurityBuffer
                    {
                        Buffer = new byte[64000],
                        BufferType = SecurityBufferType.SECBUFFER_TOKEN
                    }
                }
            };

            var result = SspiInterop.AcceptSecurityContext(
                ref _credentials,
                IntPtr.Zero, 
                incomingToken,
                HTTP_SECURITY_ATTRIBUTES,
                SspiInterop.SECURITY_NETWORK_DREP,
                ref _context,
                outgoingToken,
                out var attributes,
                out var expiry);

            if (result == SspiInterop.SEC_I_CONTINUE_NEEDED ||
                result == SspiInterop.SEC_I_COMPLETE_AND_CONTINUE ||
                result == SspiInterop.SEC_E_OK)
            {
                var nameinfo = new SecNameInfo();
                var ptr = Marshal.AllocHGlobal(Marshal.SizeOf(nameinfo));
                Marshal.StructureToPtr(nameinfo, ptr, false);

                var status = SspiInterop.QueryContextAttributes(ref _context, 13, ptr);
                Console.WriteLine($"QueryContextAttributes: {status}");
                var nameinfo2 = Marshal.PtrToStructure<SecNameInfo>(ptr);

               // var username = Marshal.PtrToStringAnsi(nameinfo2.cbMaxSignature);

                //CompleteContext("ok", outgoingToken, attributes, expiry);

                return outgoingToken.Buffers
                    .FirstOrDefault(buffer => buffer.BufferType == SecurityBufferType.SECBUFFER_TOKEN)
                    .Buffer;
            }

            throw new Exception($"The SSPI Negotiate package was unable to accept the supplied authentication token (SSPI Status: {result})");
        }

        private void CompleteContext(string username , SecurityBufferDescription description, uint attributes, long expiry)
        {
            IsEstablished = true;
            Principal = username;
        }

        public void Dispose()
        {
        }
    }
}
