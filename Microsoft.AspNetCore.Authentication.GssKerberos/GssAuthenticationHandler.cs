using System;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.GssKerberos.Gss;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.Authentication.GssKerberos
{
    internal class GssAuthenticationHandler : AuthenticationHandler<GssAuthenticationOptions>
    {
        private const string SchemeName = "Negotiate";

        private readonly GssCredential gssCredential;

        public GssAuthenticationHandler(
            IOptionsMonitor<GssAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock) : base(options, logger, encoder, clock)
        {
            this.gssCredential = this.Options.Credential;
        }

        protected new GssAuthenticationEvents Events
        {
            get => (GssAuthenticationEvents)base.Events;
            set => base.Events = value;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            string authorizationHeader = Request.Headers["Authorization"];
            if (string.IsNullOrEmpty(authorizationHeader))
            {
                return AuthenticateResult.NoResult();
            }

            if (!authorizationHeader.StartsWith("Negotiate ", StringComparison.OrdinalIgnoreCase))
            {
                return AuthenticateResult.NoResult();
            }

            var base64Token = authorizationHeader.Substring(SchemeName.Length).Trim();

            if (string.IsNullOrEmpty(base64Token))
            {
                const string noCredentialsMessage = "No credentials";
                Logger.LogInformation(noCredentialsMessage);
                return AuthenticateResult.Fail(noCredentialsMessage);
            }

            try
            {
                var asn1ServiceTicket = Convert.FromBase64String(base64Token);
                var acceptor = new GssAcceptor(this.gssCredential);

                acceptor.Accept(asn1ServiceTicket);

                if (acceptor.IsEstablished)
                {
                    // ok, now we have authentctaed the user we know who they are... but now we need to check if
                    // they are actually authorised to access the resource.
                    throw new Exception($"Authentication Failed");
                }
                else
                {
                    throw new Exception($"Authentication Failed");
                }

            }
            catch (Exception ex)
            {
                throw new Exception($"Authentication Failed");
            }
        }
    }
}
