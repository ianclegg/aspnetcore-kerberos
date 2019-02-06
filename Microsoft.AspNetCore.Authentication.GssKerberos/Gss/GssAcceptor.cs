using System;
using System.Linq;
using System.Runtime.InteropServices;
using Microsoft.AspNetCore.Authentication.GssKerberos.Disposables;
using Microsoft.AspNetCore.Authentication.GssKerberos.Pac;
using static Microsoft.AspNetCore.Authentication.GssKerberos.Native.Krb5Interop;

namespace Microsoft.AspNetCore.Authentication.GssKerberos
{
    public class GssAcceptor : IAcceptor
    {
        private readonly IntPtr _acceptorCredentials;
        private IntPtr _context;
        private IntPtr _sourceName;
        private uint _flags;
        private uint _expiryTime;

        public bool IsEstablished { get; private set; }

        /// <summary>
        /// The UPN of the context initiator
        /// </summary>
        public string Principal { get; private set; }

        /// <summary>
        /// The Groups SID's the Principal is a member of in Active Directory
        /// </summary>
        public string[] Roles { get; private set; }

        /// <summary>
        /// The final negotiated flags
        /// </summary>
        public uint Flags { get; private set; }

        public GssAcceptor(GssCredential credential) => 
            _acceptorCredentials = credential.Credentials;

        public byte[] Accept(byte[] token)
        {
            var mechBytes = new byte[GssSpnegoMechOidDesc.length];
            Marshal.Copy(GssSpnegoMechOidDesc.elements, mechBytes, 0, (int) GssSpnegoMechOidDesc.length);
            Console.WriteLine("Accepting with Mechanism: " + BitConverter.ToString(mechBytes));

            using (var inputBuffer = GssBuffer.FromBytes(token))
            {
                // decrypt and verify the incoming service ticket
                var majorStatus = gss_accept_sec_context(
                    out var minorStatus,
                    ref _context,
                    _acceptorCredentials,
                    ref inputBuffer.Value,
                    IntPtr.Zero,        // no support for channel binding
                    out _sourceName,
                    ref GssSpnegoMechOidDesc,
                    out var output,
                    out _flags, out _expiryTime, IntPtr.Zero
                );

                switch (majorStatus)
                {
                    case GSS_S_COMPLETE:
                        CompleteContext(_sourceName);
                        return MarshalOutputToken(output);

                    case GSS_S_CONTINUE_NEEDED:
                        return MarshalOutputToken(output);

                    default:
                        throw new GssException("The GSS Provider was unable to accept the supplied authentication token",
                            majorStatus, minorStatus, GssSpnegoMechOidDesc);
                }
            }
        }

        private static byte[] MarshalOutputToken(GssBufferStruct gssToken)
        {
            if (gssToken.length > 0)
            {
                // copy the output token to a managed buffer and release the gss buffer
                var buffer = new byte[gssToken.length];
                Marshal.Copy(gssToken.value, buffer, 0, (int)gssToken.length);

                var majorStatus = gss_release_buffer(out var minorStatus, ref gssToken);
                if (majorStatus != GSS_S_COMPLETE)
                    throw new GssException("An error occurred releasing the token buffer allocated by the GSS provider",
                        majorStatus, minorStatus, GssSpnegoMechOidDesc);

                return buffer;
            }
            return new byte[0];
        }

        private void CompleteContext(IntPtr sourceName)
        {
            // Use GSS to translate the opaque name to an ASCII 'display' name
            var majorStatus = gss_display_name(
                out var minorStatus,
                sourceName,
                out var nameBuffer,
                out var nameType);

            if (majorStatus != GSS_S_COMPLETE)
                throw new GssException("An error occurred getting the display name of the principal",
                    majorStatus, minorStatus, GssSpnegoMechOidDesc);

            // Set the context properties on the acceptor
            Flags = _flags;
            IsEstablished = true;
            Principal = Marshal.PtrToStringAnsi(nameBuffer.value, (int)nameBuffer.length);

            // release the GSS allocated buffers
            majorStatus = gss_release_buffer(out minorStatus, ref nameBuffer);
            if (majorStatus != GSS_S_COMPLETE)
                throw new GssException("An error occurred releasing the display name of the principal",
                    majorStatus, minorStatus, GssSpnegoMechOidDesc);

            // The Windows AD-WIN2K-PAC certificate is located in the Authzdata, MIT Kerberos provides an API to enable
            // us to a get the decrypted bytes for well known buffers, the 'urn:mspac:logon-info' contains the group sids
            // the principal is a member of in ActiveDirectory
            using (var inputBuffer = GssBuffer.FromString("urn:mspac:logon-info"))
            {
                var hasMore = -1;
                majorStatus = gss_get_name_attribute(out minorStatus,
                    sourceName,
                    ref inputBuffer.Value,
                    out var authenticated,
                    out var complete,
                    out var value,
                    out var displayValue,
                    ref hasMore);
                
                if (majorStatus != GSS_S_COMPLETE)
                    throw new GssException("An error occurred obtaining the Privilege Attribute Certificate Data (PAC) from the Kerberos Ticket",
                        majorStatus, minorStatus, GssSpnegoMechOidDesc);

                // TODO: investigate the scenarios where this may occur
                //if (authenticated == 0 || complete == 0)
                //    throw new GssException("The Privilege Attribute Certificate Data was not authenticated or is incomplete", 0);
                
                // Allocate a managed buffer and copy the raw bytes of the NDR encoded logon-info strcuture
                var pacLogonBuffer = new byte[value.length];
                Marshal.Copy(value.value, pacLogonBuffer, 0, (int)value.length);

                // Free the buffers allocated by MIT GSS
                gss_release_buffer(out minorStatus, ref value);
                gss_release_buffer(out minorStatus, ref displayValue);

                // Decode the PAC buffer and extract the group membership SID's
                var logoninfo = new PacLogonInfo(pacLogonBuffer);
                Roles = logoninfo.GroupSids.Select(sid => sid.ToString()).ToArray();
            }
        }
        
        public void Dispose()
        {
            if (_sourceName != IntPtr.Zero)
            {
                var majorStatus = gss_release_name(out var minorStatus, ref _sourceName);
                if (majorStatus != GSS_S_COMPLETE)
                    throw new GssException("An error occurred releasing the gss source name",
                        majorStatus, minorStatus, GssNtHostBasedService);
            }

            if (_context != IntPtr.Zero)
            {
                var majorStatus = gss_delete_sec_context(out var minorStatus, ref _context);
                if (majorStatus != GSS_S_COMPLETE)
                    throw new GssException("The GSS provider returned an error while attempting to delete the GSS Context",
                        majorStatus, minorStatus, GssSpnegoMechOidDesc);
            }
        }
    }
}
