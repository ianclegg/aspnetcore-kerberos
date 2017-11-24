using System;
using System.Linq;

using System.Runtime.InteropServices;
using Microsoft.AspNetCore.Authentication.GssKerberos.Disposables;
using static Microsoft.AspNetCore.Authentication.GssKerberos.Native.NativeMethods;

namespace Microsoft.AspNetCore.Authentication.GssKerberos
{
    public class GssAcceptor
    {
        private IntPtr acceptorName;
        private IntPtr acceptorCredentials;
        private IntPtr context;
        private IntPtr sourceName;
        

        public GssAcceptor(string principal, uint expiry)
        {
            // copy the principal name to a gss_buffer
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
                if (majorStatus != 0)
                    throw new GssException(majorStatus, minorStatus, GssNtHostBasedService);

                // use the name to attempt to obtain the servers credentials, this is usually from a keytab file. The
                // server credentials are required to decrypt and verify incoming service tickets
                var actualMechanims = default(GssOidDesc);
                uint actualExpiry = 0;
                
                majorStatus = gss_acquire_cred( 
                    out minorStatus,
                    acceptorName,
                    0xffffffff,
                    ref GssSpnegoMechOidSet,
                    (int)CredentialUsage.Accept,
                    ref acceptorCredentials,
                    ref actualMechanims,
                    out actualExpiry);
                
                Console.WriteLine("ok");

                if (majorStatus != 0)
                    throw new GssException(majorStatus, minorStatus, GssSpnegoMechOidDesc);
            }
        }

        public byte[] Accept(byte[] token)
        {
            uint minorStatus = 0;
            uint majorStatus = 0;

            GssBufferDescStruct outputToken;
            GssOidDesc mech;
            using (var inputBuffer = GssBuffer.FromBytes(token))
            {
                // decrypt and verify the incoming service ticket
                majorStatus = gss_accept_sec_context(
                    out minorStatus,
                    ref context,
                    acceptorCredentials,
                    ref inputBuffer.Value,
                    IntPtr.Zero,
                    out sourceName,
                    ref GssSpnegoMechOidDesc,
                    out outputToken,
                    IntPtr.Zero, IntPtr.Zero, IntPtr.Zero
                    );

                if (majorStatus != 0)
                    throw new GssException(majorStatus, minorStatus, GssSpnegoMechOidDesc);

                GssBufferDescStruct nameBuffer;
                GssOidDesc nameType;

                majorStatus = gss_display_name(
                    out minorStatus,
                    sourceName,
                    out nameBuffer,
                    out nameType);

                Marshal.PtrToStringUni(nameBuffer.value, (int)nameBuffer.length);

            }
            return null;
        }


    }
}
