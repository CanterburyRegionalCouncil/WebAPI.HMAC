using System;
using System.Security.Cryptography;

namespace WebAPI.HMAC.Crypto
{
    public static class ApiKeyGenerator
    {
        public static string Generate()
        {
            using (var cryptoProvider = new RNGCryptoServiceProvider())
            {
                var secretByteArray = new byte[32];
                cryptoProvider.GetBytes(secretByteArray);
                return Convert.ToBase64String(secretByteArray);
            }
        }
    }
}
