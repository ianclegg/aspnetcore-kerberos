using System;
using System.Runtime.InteropServices;
using Microsoft.AspNetCore.Authentication.GssKerberos.Disposables;
using Microsoft.AspNetCore.Authentication.GssKerberos.Native;

namespace Microsoft.AspNetCore.Authentication.GssKerberos.Gss
{
    public class GssInitiator
    {
        private readonly IntPtr credentials;
        private readonly IntPtr gssTargetName;
        private IntPtr context;

        public bool IsEstablished { get; private set; }

        public GssInitiator(GssCredential credential, string spn)
        {
            credentials = credential.Credentials;

            using (var gssTargetNameBuffer = GssBuffer.FromString(spn))
            {
                // use the buffer to import the name into a gss_name
                var majorStatus = NativeMethods.gss_import_name(
                    out var minorStatus,
                    ref gssTargetNameBuffer.Value,
                    ref NativeMethods.GssNtPrincipalName,
                    out gssTargetName
                );

                if (majorStatus != NativeMethods.GSS_S_COMPLETE)
                {
                    throw new GssException("The GSS provider was unable to import the supplied Target Name (SPN)",
                        majorStatus, minorStatus, NativeMethods.GssNtHostBasedService);
                }
            }
        }

        public byte[] Initiate(Byte[] token)
        {
            // If the token is null, supply a NULL pointer as the input
            var gssToken = token == null
                ? Disposable.From(default(NativeMethods.GssBufferDescStruct))
                : GssBuffer.FromBytes(token);
            
 
            var majorStatus = NativeMethods.gss_init_sec_context(
                out var minorStatus,
                credentials,
                ref context,
                gssTargetName,
                ref NativeMethods.GssSpnegoMechOidDesc,
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
                case NativeMethods.GSS_S_COMPLETE:
                    IsEstablished = true;
                    return MarshalOutputToken(output);

                case NativeMethods.GSS_S_CONTINUE_NEEDED:
                    return MarshalOutputToken(output);

                default:
                    throw new GssException("The GSS Provider was unable to generate the supplied authentication token",
                        majorStatus, minorStatus, NativeMethods.GssSpnegoMechOidDesc);
            }
        }

        private static byte[] MarshalOutputToken(NativeMethods.GssBufferDescStruct gssToken)
        {
            if (gssToken.length > 0)
            {
                // Allocate a clr byte arry and copy the token data over
                var buffer = new byte[gssToken.length];
                Marshal.Copy(gssToken.value, buffer, 0, (int)gssToken.length);

                // Finally, release the underlying gss buffer
                var majorStatus = NativeMethods.gss_release_buffer(out var minorStatus, ref gssToken);
                if (majorStatus != NativeMethods.GSS_S_COMPLETE)
                    throw new GssException("An error occurred releasing the token buffer allocated by the GSS provider",
                        majorStatus, minorStatus, NativeMethods.GssSpnegoMechOidDesc);

                return buffer;
            }
            return new byte[0];
        }
    }
}
