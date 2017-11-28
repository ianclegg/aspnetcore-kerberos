using System;

namespace Microsoft.AspNetCore.Authentication.GssKerberos
{
    public static class BasicAuthenticationAppBuilderExtensions
    {
        private const string scheme = GssAuthenticationDefaults.AuthenticationScheme;

        public static AuthenticationBuilder AddKerberos(
            this AuthenticationBuilder builder)
            => builder.AddKerberos(scheme);

        public static AuthenticationBuilder AddKerberos(
            this AuthenticationBuilder builder,
            string authenticationScheme)
            => builder.AddKerberos(authenticationScheme, configureOptions: null);

        public static AuthenticationBuilder AddKerberos(
            this AuthenticationBuilder builder,
            Action<GssAuthenticationOptions> configureOptions)
            => builder.AddKerberos(scheme, configureOptions);

        public static AuthenticationBuilder AddKerberos(
            this AuthenticationBuilder builder,
            string authenticationScheme,
            Action<GssAuthenticationOptions> configureOptions) 
           => builder.AddScheme<GssAuthenticationOptions, GssAuthenticationHandler>(authenticationScheme, configureOptions);

    }
}
