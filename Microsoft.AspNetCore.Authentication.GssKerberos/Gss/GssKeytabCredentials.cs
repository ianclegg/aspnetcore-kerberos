using System;
using System.Runtime.InteropServices;
using Microsoft.AspNetCore.Authentication.GssKerberos.Disposables;

using static Microsoft.AspNetCore.Authentication.GssKerberos.Native.Krb5Interop;

namespace Microsoft.AspNetCore.Authentication.GssKerberos
{
    public class GssKeytabCredential : GssCredential
    {
        private IntPtr _credentials;
        private IntPtr _acceptorName;

        protected internal override IntPtr Credentials => _credentials;

        public GssKeytabCredential(string principal, string keytab, CredentialUsage usage, uint expiry = GSS_C_INDEFINITE)
        {
            // allocate a gss buffer and copy the principal name to it
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

                majorStatus = gss_acquire_cred(
                    out minorStatus,
                    acceptorName,
                    expiry,
                    ref GssSpnegoMechOidSet,
                    (int)usage,
                    ref _credentials,
                    IntPtr.Zero,            // dont mind what mechs we got
                    out var actualExpiry);

                if (majorStatus != GSS_S_COMPLETE)
                    throw new GssException("The GSS Provider was unable aquire credentials for authentication",
                        majorStatus, minorStatus, GssSpnegoMechOidDesc);
            }
        }

        public override void Dispose()
        {
            uint minorStatus = 0;
            uint majorStatus = 0;

            majorStatus = gss_release_name(out minorStatus, ref _acceptorName);
            if (majorStatus != GSS_S_COMPLETE)
            {
                throw new GssException("The GSS provider was unable to release the princpal name handle",
                    majorStatus, minorStatus, GssNtHostBasedService);
            }

            majorStatus = gss_release_cred(out minorStatus, ref _credentials);
            if (majorStatus != GSS_S_COMPLETE)
            {
                throw new GssException("The GSS provider was unable to release the credential handle",
                    majorStatus, minorStatus, GssNtHostBasedService);
            }
        }
    }
}
