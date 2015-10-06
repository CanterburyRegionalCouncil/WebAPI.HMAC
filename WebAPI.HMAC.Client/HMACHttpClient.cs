using System.Net.Http;

namespace WebAPI.HMAC.Client
{
    public class HMACHttpClient : HttpClient
    {
        public HMACHttpClient(string appId, string apiKey) : base(new HMACDelegatingHandler(appId, apiKey)) {}
    }
}