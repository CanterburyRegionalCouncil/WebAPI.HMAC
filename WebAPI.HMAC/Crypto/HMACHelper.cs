using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace WebAPI.HMAC.Crypto
{
    public static class HMACHelper
    {
        public static string BuildNonce()
        {
            return Guid.NewGuid().ToString("N");
        }

        public async static Task<string> BuildBase64Signature(
                string apiKey,
                string appId,
                Uri rawUri,
                HttpMethod httpMethod,
                HttpContent content,
                string nonce,
                string requestTimeStamp
            )
        {
            var requestUri = HttpUtility.UrlEncode(rawUri.AbsoluteUri.ToLower());
            var requestHttpMethod = httpMethod.Method;

            // Get the content string out of the content.
            var requestContentBase64String = await ComputeBase64RequestContent(content);

            // Rebuild the signature raw data.
            var signatureRawData =
                $"{appId}{requestHttpMethod}{requestUri}{requestTimeStamp}{nonce}{requestContentBase64String}";

            // Get the api key bytes.
            var secretKeyBytes = Convert.FromBase64String(apiKey);

            // Get the signature.
            var signature = Encoding.UTF8.GetBytes(signatureRawData);

            // Create HMAC SHA class with key data.
            using (var hmac = new HMACSHA256(secretKeyBytes))
            {
                return Convert.ToBase64String(hmac.ComputeHash(signature));
            }
        }

        private async static Task<string> ComputeBase64RequestContent(HttpContent httpContent)
        {
            // Hash the request content.
            var hash = await ComputeHash(httpContent);

            // If the result is not null then convert it into a base 64 string.
            return hash != null ? Convert.ToBase64String(hash) : string.Empty;
        }

        private static async Task<byte[]> ComputeHash(HttpContent httpContent)
        {
            using (var md5 = MD5.Create())
            {
                byte[] hash = null;
                if (httpContent != null)
                {
                    var content = await httpContent.ReadAsByteArrayAsync();
                    if (content.Length != 0)
                    {
                        hash = md5.ComputeHash(content);
                    }
                }
                return hash;
            }
        }
    }
}
