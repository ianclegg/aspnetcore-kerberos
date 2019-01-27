using System;
using System.Linq;
using Microsoft.AspNetCore.Authentication.GssKerberos.Native;

namespace Microsoft.AspNetCore.Authentication.GssKerberos
{
    public class SspiInitiator
    {
        private readonly string _target;
        private SecurityHandle _credentials;
        private SecurityHandle _context;
        private long _expiryTime;

        public SspiInitiator(SspiCredentials credentials, string target)
        {
            _target = target;
            _credentials = credentials.Credentials;
        }

        public byte[] Initiate(byte[] token)
        {
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

            //var att = SspiInterop.ISC_REQ_USE_SUPPLIED_CREDS;
            var result = SspiInterop.InitializeSecurityContext(
                ref _credentials,
                IntPtr.Zero,
                _target,
                0,
                0,
                0,
                IntPtr.Zero, 
                0,
                ref _context,
                outgoingToken,
                out var attribute,
                out var expiry);

            if (result != 0)
            {
                Console.WriteLine($"InitializeSecurityContext returned {result}");
                Console.WriteLine(BitConverter.ToString(outgoingToken.Buffers[0].Buffer));
            }

            return outgoingToken.Buffers
                .FirstOrDefault(buffer => buffer.BufferType == SecurityBufferType.SECBUFFER_TOKEN)
                .Buffer;
        }
    }
}
