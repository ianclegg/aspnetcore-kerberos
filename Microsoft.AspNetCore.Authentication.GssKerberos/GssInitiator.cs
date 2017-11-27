using System;
using System.Runtime.InteropServices;
using Microsoft.AspNetCore.Authentication.GssKerberos.Disposables;
using Microsoft.AspNetCore.Authentication.GssKerberos.Native;
using static Microsoft.AspNetCore.Authentication.GssKerberos.Native.NativeMethods;

namespace Microsoft.AspNetCore.Authentication.GssKerberos
{
    public class GssInitiator
    {
        private IntPtr initiatorCredentials;
        private IntPtr gssTargetName;
        private IntPtr context;

        public bool IsEstablished { get; private set; }

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
                    ref GssNtPrincipalName,
                    out var gssUsername
                );
                if (majorStatus != GSS_S_COMPLETE)
                    throw new GssException("The GSS provider was unable to import the supplied principal name",
                        majorStatus, minorStatus, GssNtHostBasedService);

                // use the buffer to import the name into a gss_name
                majorStatus = gss_import_name(
                    out minorStatus,
                    ref gssTargetNameBuffer.Value,
                    ref GssNtPrincipalName,
                    out gssTargetName
                );
                if (majorStatus != GSS_S_COMPLETE)
                {
                    gss_release_name(out var _, ref gssUsername);
                    throw new GssException("The GSS provider was unable to import the supplied Target Name (SPN)",
                        majorStatus, minorStatus, GssNtHostBasedService);
                }

                // attempt to obtain a TGT from the KDC using the supplied username and password
                var actualMechanims = default(GssOidDesc);

                majorStatus = gss_acquire_cred_with_password(
                    out minorStatus,
                    gssUsername,
                    ref gssPasswordBuffer.Value,
                    0xffffffff,
                    ref GssSpnegoMechOidSet,
                    (int)CredentialUsage.Initiate,
                    ref initiatorCredentials,
                    ref actualMechanims,
                    out var actualExpiry);

                // release the gss_name allocated by gss, the gss_buffer we allocated is free'd by the using block
                gss_release_name(out var _, ref gssUsername);
                gss_release_name(out var _, ref gssTargetName);

                if (majorStatus != GSS_S_COMPLETE)
                    throw new GssException("The GSS Provider was unable aquire credentials for authentication",
                        majorStatus, minorStatus, GssSpnegoMechOidDesc);
            }
        }

        public byte[] Initiate(Byte[] token)
        {
            uint minorStatus = 0;
            uint majorStatus = 0;

            // If the token is null, supply a NULL pointer as the input
            var gssToken = token == null
                ? Disposable.From(default(GssBufferDescStruct))
                : GssBuffer.FromBytes(token);
            
 
            majorStatus = gss_init_sec_context(
                out minorStatus,
                initiatorCredentials,
                ref context,
                gssTargetName,
                ref GssSpnegoMechOidDesc,
                0,
                0,
                IntPtr.Zero,
                ref gssToken.Value,
                IntPtr.Zero,
                out var output,
                IntPtr.Zero,
                IntPtr.Zero
            );

            switch (majorStatus)
            {
                case GSS_S_COMPLETE:
                    IsEstablished = true;
                    return MarshalOutputToken(output);

                case GSS_S_CONTINUE_NEEDED:
                    return MarshalOutputToken(output);

                default:
                    throw new GssException("The GSS Provider was unable to generate the supplied authentication token",
                        majorStatus, minorStatus, GssSpnegoMechOidDesc);
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
    }
}
