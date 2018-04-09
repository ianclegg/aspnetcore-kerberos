using System;
using Microsoft.AspNetCore.Authentication.GssKerberos.Disposables;
using static Microsoft.AspNetCore.Authentication.GssKerberos.Native.Krb5Interop;

namespace Microsoft.AspNetCore.Authentication.GssKerberos.Gss
{
    public class GssKeytabCredential : GssCredential
    {
        private readonly IntPtr _credentials;

        public GssKeytabCredential(string principal, string keytab, CredentialUsage usage, uint expiry = GSS_C_INDEFINITE)
        {
            // TODO: Wrap this with pinvoke
            if (!string.IsNullOrEmpty(keytab))
            {
                // krb5_gss_register_acceptor_identity(string) 
            }

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

                // use the name to attempt to obtain the servers credentials, this is usually from a keytab file. The
                // server credentials are required to decrypt and verify incoming service tickets
                var actualMechanims = default(GssOidDesc);

                majorStatus = gss_acquire_cred(
                    out minorStatus,
                    acceptorName,
                    expiry,
                    ref GssSpnegoMechOidSet,
                    (int)usage,
                    ref _credentials,
                    ref actualMechanims,
                    out var actualExpiry);

                // release the gss_name allocated by gss, the gss_buffer we allocated is free'd by the using block
                gss_release_name(out minorStatus, ref acceptorName);

                if (majorStatus != GSS_S_COMPLETE)
                    throw new GssException("The GSS Provider was unable aquire credentials for authentication",
                        majorStatus, minorStatus, GssSpnegoMechOidDesc);
            }
        }

        protected internal override IntPtr Credentials => _credentials;

        public override void Dispose()
        {
            throw new NotImplementedException();
        }
    }
}
