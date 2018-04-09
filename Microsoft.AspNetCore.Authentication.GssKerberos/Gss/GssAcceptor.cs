using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication.GssKerberos.Disposables;
using static Microsoft.AspNetCore.Authentication.GssKerberos.Native.Krb5Interop;
using Microsoft.AspNetCore.Authentication.GssKerberos.Gss;

namespace Microsoft.AspNetCore.Authentication.GssKerberos
{
    public class GssAcceptor : IDisposable
    {
        private readonly IntPtr acceptorCredentials;
        private IntPtr context;
        private IntPtr sourceName;
        private uint flags;
        private uint expiryTime;

        public bool IsEstablished { get; private set; }

        /// <summary>
        /// The UPN of the context initiator
        /// </summary>
        public string Principal { get; private set; }

        /// <summary>
        /// The logon-info
        /// </summary>
        internal byte[] Pac { get; private set; }

        /// <summary>
        /// The final negotiated flags
        /// </summary>
        public uint Flags { get; private set; }

        public GssAcceptor(GssCredential credential) => 
            acceptorCredentials = (credential.Credentials);

        public byte[] Accept(byte[] token)
        {
            uint minorStatus = 0;
            uint majorStatus = 0;

            using (var inputBuffer = GssBuffer.FromBytes(token))
            {
                // decrypt and verify the incoming service ticket
                majorStatus = gss_accept_sec_context(
                    out minorStatus,
                    ref context,
                    acceptorCredentials,
                    ref inputBuffer.Value,
                    IntPtr.Zero,        // no support for channel binding
                    out sourceName,
                    ref GssSpnegoMechOidDesc,
                    out var output,
                    out flags, out expiryTime, IntPtr.Zero
                );

                switch (majorStatus)
                {
                    case GSS_S_COMPLETE:
                        CompleteContext(sourceName);
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
                // Allocate a clr byte arry and copy the token data over
                var buffer = new byte[gssToken.length];
                Marshal.Copy(gssToken.value, buffer, 0, (int)gssToken.length);

                // Finally, release the underlying gss buffer
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

            // Copy the display name to a CLR string
            Flags = flags;
            IsEstablished = true;
            Principal = Marshal.PtrToStringAnsi(nameBuffer.value, (int)nameBuffer.length);

            // Release the GSS allocated buffer
            majorStatus = gss_release_buffer(out minorStatus, ref nameBuffer);
            if (majorStatus != GSS_S_COMPLETE)
                throw new GssException("An error occurred releasing the display name of the principal",
                    majorStatus, minorStatus, GssSpnegoMechOidDesc);

            // The Windows AD-WIN2K-PAC certificate is located in the Authzdata
            // we can get the raw authzdata and parse it, looking for the PAC
            // ...or use the preferred krb5_gss_get_name_attribute("urn:mspac:")
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
                    throw new GssException("An error occurred obtaining the Windows PAC data from the Kerberos Ticket",
                        majorStatus, minorStatus, GssSpnegoMechOidDesc);
                
                // Allocate a clr byte arry and copy the Pac data over
                Pac = new byte[value.length];
                Marshal.Copy(value.value, Pac, 0, (int)value.length);
                
                AsnEncodedData d = new AsnEncodedData(Pac);
                var data = d.Format(true);
            }
        }
        
        public void Dispose()
        {
            var majorStatus = gss_delete_sec_context(out var minorStatus, ref context, GSS_C_NO_BUFFER);
            if (majorStatus != GSS_S_COMPLETE)
                throw new GssException("The GSS provider returned an error while attempting to delete the GSS Context",
                    majorStatus, minorStatus, GssSpnegoMechOidDesc);
        }
    }
}
