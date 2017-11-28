using System.Text;
using Microsoft.AspNetCore.Authentication.GssKerberos.Gss;

namespace Microsoft.AspNetCore.Authentication.GssKerberos
{
    public class GssContext
    {
        public static Encoding iso8859 = Encoding.GetEncoding("iso-8859-1");

        public static void main()
        {

            // Generate a token
            var initiator = new GssInitiator(
                credential: GssCredentials.FromPassword("<username>", "<password>"),
                spn: "<service>");
            
            var token = initiator.Initiate(null);

            // Accept the token
            var acceptor = new GssAcceptor(
                credential: GssCredentials.FromKeytab("<service>", CredentialUsage.Accept));
            acceptor.Accept(token);
        }
    }
}