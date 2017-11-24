using System;
using Microsoft.AspNetCore.Authentication.GssKerberos.Disposables;
using static Microsoft.AspNetCore.Authentication.GssKerberos.Native.NativeMethods;

namespace Microsoft.AspNetCore.Authentication.GssKerberos
{
    public class GssInitiator
    {
        private IntPtr initiatorCredentials;
        private IntPtr context;

        public GssInitiator(string username, string password, string spn)
        {
            uint minorStatus = 0;
            uint majorStatus = 0;

            // copy the principal name to a gss_buffer
            using (var gssUsernameBuffer = GssBuffer.FromString(username))
            using (var gssPasswordBuffer = GssBuffer.FromString(password))
            using (var gssTargetNameBuffer = GssBuffer.FromString(spn))
            {
                // use the buffer to import the name into a gss_name
                majorStatus = gss_import_name(
                    out minorStatus,
                    ref gssUsernameBuffer.Value,
                    ref GssNtHostBasedService,
                    out var gssUsername
                );
                if (majorStatus != 0)
                    throw new GssException(majorStatus, minorStatus, GssNtHostBasedService);

                // use the buffer to import the name into a gss_name
                majorStatus = gss_import_name(
                    out minorStatus,
                    ref gssTargetNameBuffer.Value,
                    ref GssNtHostBasedService,
                    out var gssTargetName
                );
                if (majorStatus != 0)
                    throw new GssException(majorStatus, minorStatus, GssNtHostBasedService);

                // attempt to obtain a TGT from the KDC using the supplied username and password
                var actualMechanims = default(GssOidDesc);
                uint actualExpiry = 0;

                majorStatus = gss_acquire_cred_with_password(
                    out minorStatus,
                    gssUsername,
                    ref gssPasswordBuffer.Value,
                    0xffffffff,
                    ref GssSpnegoMechOidSet,
                    (int)CredentialUsage.Accept,
                    ref initiatorCredentials,
                    ref actualMechanims,
                    out actualExpiry);

                if (majorStatus != 0)
                    throw new GssException(majorStatus, minorStatus, GssSpnegoMechOidDesc);

            }
        }

        public byte[] Initiate(Byte[] token)
        {
            //uint minorStatus = 0;
            //uint majorStatus = 0;


            //majorStatus = NativeMethods.gss_init_sec_context(
            //    out minorStatus,
            //    initiatorCredentials,
            //    ref context,
            //    IntPtr targetName, 

            return null;
        }
    }
}
