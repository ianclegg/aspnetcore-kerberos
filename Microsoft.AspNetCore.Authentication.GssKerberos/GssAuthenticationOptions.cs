using Microsoft.AspNetCore.Authentication.GssKerberos.Gss;

namespace Microsoft.AspNetCore.Authentication.GssKerberos
{
    public class GssAuthenticationOptions : AuthenticationSchemeOptions
    {
        public IAcceptor Acceptor { get; set; }
    }
}