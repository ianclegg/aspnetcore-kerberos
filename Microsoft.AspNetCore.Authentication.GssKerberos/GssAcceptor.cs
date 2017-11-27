using System;
using System.Runtime.InteropServices;
using Microsoft.AspNetCore.Authentication.GssKerberos.Disposables;
using static Microsoft.AspNetCore.Authentication.GssKerberos.Native.NativeMethods;

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

        public string Principal { get; private set; }

        public uint Flags { get; private set; }

        public GssAcceptor(string principal, uint expiry = GSS_C_INDEFINITE)
        {
            // aloocate a gss buffer amd copy the principal name to it
            using (var gssNameBuffer = GssBuffer.FromString(principal))
            { 
                uint minorStatus = 0;
                uint majorStatus = 0;

                // use the buffer to import the name into a gss_name
                majorStatus = gss_import_name(
                    out minorStatus,
                    ref gssNameBuffer.Value,
                    ref GssNtPrincipalName,
                    out var acceptorName
                );
                if (majorStatus != GSS_S_COMPLETE)
                    throw new GssException("The GSS provider was unable to import the supplied principal name",
                        majorStatus, minorStatus, GssNtHostBasedService);

                // use the name to attempt to obtain the servers credentials, this is usually from a keytab file. The
                // server credentials are required to decrypt and verify incoming service tickets
                var actualMechanims = default(GssOidDesc);
                
                majorStatus = gss_acquire_cred( 
                    out minorStatus,
                    acceptorName,
                    expiry,
                    ref GssSpnegoMechOidSet,
                    (int)CredentialUsage.Accept,
                    ref acceptorCredentials,
                    ref actualMechanims,
                    out var actualExpiry);

                // release the gss_name allocated by gss, the gss_buffer we allocated is free'd by the using block
                gss_release_name(out minorStatus, ref acceptorName);

                if (majorStatus != GSS_S_COMPLETE)
                    throw new GssException("The GSS Provider was unable aquire credentials for authentication",
                        majorStatus, minorStatus, GssSpnegoMechOidDesc);
            }
        }

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
                    out GssBufferDescStruct output,
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

        private static byte[] MarshalOutputToken(GssBufferDescStruct gssToken)
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

            // Finally, release the GSS allocated buffer
            majorStatus = gss_release_buffer(out minorStatus, ref nameBuffer);
            if (majorStatus != GSS_S_COMPLETE)
                throw new GssException("An error occurred releasing the display name of the principal",
                    majorStatus, minorStatus, GssSpnegoMechOidDesc);
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
