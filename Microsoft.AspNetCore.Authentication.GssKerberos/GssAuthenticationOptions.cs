using Microsoft.AspNetCore.Authentication.GssKerberos.Gss;

namespace Microsoft.AspNetCore.Authentication.GssKerberos
{
    public class GssAuthenticationOptions : AuthenticationSchemeOptions
    {
        public GssCredential Credential { get; set; }
    }
}