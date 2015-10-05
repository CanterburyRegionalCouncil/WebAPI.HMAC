using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace WebAPI.HMAC.Client
{
    public class CustomDelegatingHandler : DelegatingHandler
    {
        //Obtained from the server earlier, APIKey MUST be stored securely and in App.Config
        private const string AppId = "4d53bce03ec34c0a911182d4c228ee6c";
        private const string ApiKey = "A93reRTUJHsCuQSHR+L3GxqOJyDmQpCgps102ciuabc=";

        protected async override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var requestContentBase64String = string.Empty;

            var requestUri = HttpUtility.UrlEncode(request.RequestUri.AbsoluteUri.ToLower());
            var requestHttpMethod = request.Method.Method;

            //Calculate UNIX time
            var epochStart = new DateTime(1970, 01, 01, 0, 0, 0, 0, DateTimeKind.Utc);
            var timeSpan = DateTime.UtcNow - epochStart;
            var requestTimeStamp = Convert.ToUInt64(timeSpan.TotalSeconds).ToString();

            //create random nonce for each request
            var nonce = Guid.NewGuid().ToString("N");

            //Checking if the request contains body, usually will be null with HTTP GET and DELETE
            // Hashing the request body to make sure it matches what the server recieves.
            // If anyone tampers with the content of the request, the result won't match because they
            // couldn't hash it the same because they don't know the API key.
            if (request.Content != null)
            {
                var content = await request.Content.ReadAsByteArrayAsync();
                var md5 = MD5.Create();

                //Hashing the request body, any change in request body will result in different hash, we'll ensure message integrity
                var requestContentHash = md5.ComputeHash(content);
                requestContentBase64String = Convert.ToBase64String(requestContentHash);
            }

            //Creating the raw signature string
            var signatureRawData =
                $"{AppId}{requestHttpMethod}{requestUri}{requestTimeStamp}{nonce}{requestContentBase64String}";

            // Gets the bytes from the api key.
            var secretKeyBytes = Convert.FromBase64String(ApiKey);

            // Get the byte array out of the signature.
            var signature = Encoding.UTF8.GetBytes(signatureRawData);

            // Create HMAC SHA class with key data.
            using (var hmac = new HMACSHA256(secretKeyBytes))
            {
                var base64Signature = Convert.ToBase64String(hmac.ComputeHash(signature));

                //Setting the values in the Authorization header using custom scheme (amx)
                request.Headers.Authorization = new AuthenticationHeaderValue("amx",
                    $"{AppId}:{base64Signature}:{nonce}:{requestTimeStamp}");
            }

            var response = await base.SendAsync(request, cancellationToken);

            return response;
        }
    }
}