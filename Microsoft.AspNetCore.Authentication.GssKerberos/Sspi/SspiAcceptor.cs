using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Principal;
using Microsoft.AspNetCore.Authentication.GssKerberos.Native;

// ReSharper disable InconsistentNaming
namespace Microsoft.AspNetCore.Authentication.GssKerberos
{
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
                        // we need should query the sec package for them
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

            if (result == SspiInterop.SEC_E_OK || result == SspiInterop.SEC_I_COMPLETE_AND_CONTINUE)
            {
                IsEstablished = true;
                Principal = GetPrincipalNameFromContext(_context);
                Roles = GetGroupMembershipFromContext(_context);

                if (result == SspiInterop.SEC_E_OK)
                {
                    return new byte[0];
                }
            }
            if (result == SspiInterop.SEC_I_COMPLETE_AND_CONTINUE || result == SspiInterop.SEC_I_CONTINUE_NEEDED)
            {
                return outgoingToken.Buffers
                    .FirstOrDefault(buffer => buffer.BufferType == SecurityBufferType.SECBUFFER_TOKEN)
                    .Buffer;
            }
            throw new AuthenticationException($"The SSPI Negotiate package was unable to accept the supplied authentication token (SSPI Status: {result})");
        }

        private static string GetPrincipalNameFromContext(SecurityHandle context)
        {
            // We must pass SSPI a pointer to a structure, where upon SSPI will allocate additional memory for the
            // fields of the structure. We have to call back into SSPI to free the buffers it allocated, this code is
            // pretty verbose, probably should be refactored
            var name = new SecurityContextNamesBuffer();
            var namePtr = Marshal.AllocHGlobal(Marshal.SizeOf(name));
            Marshal.StructureToPtr(name, namePtr, false);
            var status = SspiInterop.QueryContextAttributes(ref context, SspiInterop.SECPKG_ATTR_NATIVE_NAMES, namePtr);
            if (status != SspiInterop.SEC_E_OK)
            {
                Marshal.FreeHGlobal(namePtr);
                throw new AuthenticationException($"An unhandled exception occurred obtaining the username from the context (QueryContextAttributes returned: {status})");
            }
            var usernamePtr = Marshal.PtrToStructure<SecurityContextNamesBuffer>(namePtr).clientname;
            var servernamePtr = Marshal.PtrToStructure<SecurityContextNamesBuffer>(namePtr).servername;
            var username = Marshal.PtrToStringUni(usernamePtr);
            SspiInterop.FreeContextBuffer(usernamePtr);
            SspiInterop.FreeContextBuffer(servernamePtr);
            Marshal.FreeHGlobal(namePtr);

            return username;
        }

        private static string[] GetGroupMembershipFromContext(SecurityHandle context)
        {
            // Query the context to obtain the Win32 Access Token, this will enable us to get the list of SID's that
            // represent group membership for the principal, we will use these to populate the Roles property
            var accessToken = new SecurityContextBuffer();
            var accessTokenPtr = Marshal.AllocHGlobal(Marshal.SizeOf(accessToken));
            Marshal.StructureToPtr(accessToken, accessTokenPtr, false);

            var status = SspiInterop.QueryContextAttributes(ref context, SspiInterop.SECPKG_ATTR_ACCESS_TOKEN, accessTokenPtr);
            if (status != SspiInterop.SEC_E_OK)
            {
                Marshal.FreeHGlobal(accessTokenPtr);
                throw new AuthenticationException($"An unhandled exception occurred obtaining the access token from the context (QueryContextAttributes returned: {status})");
            }
            // who closes the access token, I assume when we delete the context
            var tokenPtr = Marshal.PtrToStructure<SecurityContextBuffer>(accessTokenPtr).Buffer;
            var groups = GetMemebershipSids(tokenPtr).ToArray();
            Marshal.FreeHGlobal(accessTokenPtr);

            return groups;
        }

        private static IEnumerable<string> GetMemebershipSids(IntPtr token)
        {
            var length = 0;
            SspiInterop.GetTokenInformation(token, TokenInformationClass.TokenGroups, IntPtr.Zero, length, out length);
            
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
            else
            {
                throw new AuthenticationException($"An unhandled exception occurred obtaining group membership from the context (Win32 error {Marshal.GetLastWin32Error()})");
            }
            Marshal.FreeHGlobal(buffer);
        }

        public void Dispose()
        {
        }
    }
}
