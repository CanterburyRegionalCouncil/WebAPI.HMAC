using System.Net.Http;

namespace WebAPI.HMAC.Http
{
    public class HMACHttpClient : HttpClient
    {
        public HMACHttpClient(string appId, string apiKey) : base(new HMACDelegatingHandler(appId, apiKey)) {}
    }
}