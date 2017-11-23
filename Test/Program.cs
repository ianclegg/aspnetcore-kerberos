using System;

namespace Test
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");
            Microsoft.AspNetCore.Authentication.GssKerberos.GssContext.main();
        }
    }
}