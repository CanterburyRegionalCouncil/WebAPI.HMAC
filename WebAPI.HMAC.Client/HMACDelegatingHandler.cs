using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using WebAPI.HMAC.Crypto;

namespace WebAPI.HMAC.Client
{
    public class HMACDelegatingHandler : DelegatingHandler
    {
        private readonly string _appId;
        private readonly string _apiKey;

        public HMACDelegatingHandler(string appId, string apiKey)
        {
            _appId = appId;
            _apiKey = apiKey;

            InnerHandler = new HttpClientHandler();
        }

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
                _apiKey,
                _appId,
                request.RequestUri,
                request.Method,
                request.Content,
                nonce,
                requestTimeStamp
                );

            //Setting the values in the Authorization header using custom scheme (amx)
            request.Headers.Authorization = new AuthenticationHeaderValue("amx",
                $"{_appId}:{base64Signature}:{nonce}:{requestTimeStamp}");

            var response = await base.SendAsync(request, cancellationToken);

            return response;
        }
    }
}