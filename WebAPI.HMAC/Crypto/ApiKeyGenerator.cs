using System;
using System.Security.Cryptography;

namespace WebAPI.HMAC.Crypto
{
    public static class ApiKeyGenerator
    {
        /// <summary>
        /// Generates a new API key.
        /// </summary>
        /// <param name="strength">The length of the resulting key will be approximately 1.33 * strength.</param>
        /// <returns></returns>
        public static string Generate(int strength)
        {
            using (var cryptoProvider = new RNGCryptoServiceProvider())
            {
                var secretByteArray = new byte[strength];
                cryptoProvider.GetBytes(secretByteArray);
                return Convert.ToBase64String(secretByteArray);
            }
        }
    }
}
