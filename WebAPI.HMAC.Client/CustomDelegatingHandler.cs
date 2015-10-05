using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using WebAPI.HMAC.Crypto;

namespace WebAPI.HMAC.Client
{
    public class CustomDelegatingHandler : DelegatingHandler
    {
        // TODO Should be obtained from the server earlier, APIKey MUST be stored securely e.g. in environment variables.
        private const string AppId = "4d53bce03ec34c0a911182d4c228ee6c";
        private const string ApiKey = "A93reRTUJHsCuQSHR+L3GxqOJyDmQpCgps102ciuabc=";

        protected async override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            // Calculate UNIX time.
            var epochStart = new DateTime(1970, 01, 01, 0, 0, 0, 0, DateTimeKind.Utc);
            var timeSpan = DateTime.UtcNow - epochStart;
            var requestTimeStamp = Convert.ToUInt64(timeSpan.TotalSeconds).ToString();

            //create random nonce for each request
            var nonce = HMACHelper.BuildNonce();

            // Build the base 64 signature.
            var base64Signature = await HMACHelper.BuildBase64Signature(
                ApiKey,
                AppId,
                request.RequestUri,
                request.Method,
                request.Content,
                nonce,
                requestTimeStamp
                );

            //Setting the values in the Authorization header using custom scheme (amx)
            request.Headers.Authorization = new AuthenticationHeaderValue("amx",
                $"{AppId}:{base64Signature}:{nonce}:{requestTimeStamp}");

            var response = await base.SendAsync(request, cancellationToken);

            return response;
        }
    }
}