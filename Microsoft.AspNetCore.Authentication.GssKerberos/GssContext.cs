using System;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Principal;
using System.Text;
using Microsoft.AspNetCore.Authentication.GssKerberos.Disposables;
using Microsoft.AspNetCore.Authentication.GssKerberos.Native;

namespace Microsoft.AspNetCore.Authentication.GssKerberos
{
    public class GssContext
    {
        public static Encoding iso8859 = Encoding.GetEncoding("iso-8859-1");

        public static void main()
        {

            // Generate a token
            var initiator = new GssInitiator(
                username: "<username>",
                password: "<password>",
                spn: "HTTP/orion.testweb.bp.com");
            
            var token = initiator.Initiate(null);

            // Accept the token
            var acceptor = new GssAcceptor("HTTP/orion.testweb.bp.com@BP1.AD.BP.COM", 0);
            acceptor.Accept(token);
        }
    }
}