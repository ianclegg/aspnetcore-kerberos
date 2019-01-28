using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.AspNetCore.Authentication.GssKerberos.Native;

// ReSharper disable InconsistentNaming
namespace Microsoft.AspNetCore.Authentication.GssKerberos
{
    public struct SecAccessToken
    {
        public IntPtr AccessToken;
    }
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
        /// The Groups SID's the Principal is a member of in Active Directory
        /// </summary>
        public string[] Roles { get; private set;}

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
                // Query the context to obtain the display name of the principal that was authenticated
                var nameinfo = new SecNameInfo();
                var ptr = Marshal.AllocHGlobal(Marshal.SizeOf(nameinfo));
                Marshal.StructureToPtr(nameinfo, ptr, false);

                var status = SspiInterop.QueryContextAttributes(ref _context, 13, ptr);
                Console.WriteLine($"QueryContextAttributes: {status}");
                var nameinfo2 = Marshal.PtrToStructure<SecNameInfo>(ptr);

                // Query the context to obtain the Win32 Access Token, this will enable us to get the list of SID's that
                // represent group membership for the principal, we will use these to populate the Roles property
                var accessToken = new SecAccessToken();
                var accessTokenPtr = Marshal.AllocHGlobal(Marshal.SizeOf(accessToken));
                Marshal.StructureToPtr(token, accessTokenPtr, false);
                if (SspiInterop.QueryContextAttributes(ref _context, SspiInterop.SECPKG_ATTR_ACCESS_TOKEN, accessTokenPtr) != SspiInterop.SEC_E_OK)
                {
                    throw new Exception("Error getting the access token");
                }
                // need to free the buffer with FreeContextBuffer()

                CompleteContext("ok", outgoingToken, attributes, expiry, accessTokenPtr);

                return outgoingToken.Buffers
                    .FirstOrDefault(buffer => buffer.BufferType == SecurityBufferType.SECBUFFER_TOKEN)
                    .Buffer;
            }

            throw new Exception($"The SSPI Negotiate package was unable to accept the supplied authentication token (SSPI Status: {result})");
        }

        private void CompleteContext(string username , SecurityBufferDescription description, uint attributes, long expiry, IntPtr token)
        {
            IsEstablished = true;
            Principal = username;
            Roles = GetMemebershipSids(IntPtr.Zero).ToArray();
        }

        private IEnumerable<string> GetMemebershipSids(IntPtr token)
        {
            var length = 0;
            if (!SspiInterop.GetTokenInformation(token, TokenInformationClass.TokenGroups, IntPtr.Zero, length,
                out length))
                throw new Exception("An SSPI Error Occurred getting group membership");

            var buffer = Marshal.AllocHGlobal(length);
            if (SspiInterop.GetTokenInformation(token, TokenInformationClass.TokenGroups, buffer, length, out length))
            {
                var groups = Marshal.PtrToStructure<TOKEN_GROUPS>(buffer);
                var sidAndAttrSize = Marshal.SizeOf(new SID_AND_ATTRIBUTES());
                for (var i = 0; i < groups.GroupCount; i++)
                {
                    var sidAndAttributes = Marshal.PtrToStructure<SID_AND_ATTRIBUTES>(
                        new IntPtr(buffer.ToInt64() + i * sidAndAttrSize + IntPtr.Size));

                    SspiInterop.ConvertSidToStringSid(sidAndAttributes.Sid, out var pstr);
                    var sidString = Marshal.PtrToStringAuto(pstr);
                    SspiInterop.LocalFree(pstr);
                    yield return sidString;
                }
            }
            Marshal.FreeHGlobal(buffer);
        }

        public void Dispose()
        {
        }
    }
}
