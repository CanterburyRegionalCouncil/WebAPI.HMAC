using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.Filters;
using System.Web.Http.Results;
using WebAPI.HMAC.Crypto;
using WebAPI.HMAC.Store;

namespace WebAPI.HMAC.Filters
{
    public class HMACAuthenticationAttribute : Attribute, IAuthenticationFilter
    {
        private const uint RequestMaxAgeInSeconds = 300; //5 mins
        private const string AuthenticationScheme = "amx";

        public IApiKeyStore ApiKeyStore { get; set; }

        public Task AuthenticateAsync(HttpAuthenticationContext context, CancellationToken cancellationToken)
        {
            if (ApiKeyStore == null)
            {
                throw new NullReferenceException("ApiKeyStore is null. You must set up your IoC container to inject an implementation of IApiKeyStore via property injection.");
            }

            var request = context.Request;

            // Make sure there's an authorisation header and that it uses the correct authorisation scheme.
            if (request.Headers.Authorization != null &&
                AuthenticationScheme.Equals(request.Headers.Authorization.Scheme, StringComparison.OrdinalIgnoreCase))
            {
                // Gets the raw auth header.
                var rawAuthzHeader = request.Headers.Authorization.Parameter;

                // Turns the raw auth header into an array.
                var autherizationHeaderArray = GetAuthorizationHeaderValues(rawAuthzHeader);

                // If a non-null array is available then get on with the rest.
                if (autherizationHeaderArray != null)
                {
                    // Split out the individual auth header components.
                    var appId = autherizationHeaderArray[0];
                    var incomingBase64Signature = autherizationHeaderArray[1];
                    var nonce = autherizationHeaderArray[2];
                    var requestTimeStamp = autherizationHeaderArray[3];

                    // Checks if the request is valid.
                    var isValid = IsValidRequest(request, appId, incomingBase64Signature, nonce, requestTimeStamp);

                    // If the request is valid, set a generic principal.
                    if (isValid)
                    {
                        var currentPrincipal = new GenericPrincipal(new GenericIdentity(appId), null);
                        context.Principal = currentPrincipal;
                    }
                    else
                    {
                        context.ErrorResult = new UnauthorizedResult(new AuthenticationHeaderValue[0], context.Request);
                    }
                }
                else
                {
                    context.ErrorResult = new UnauthorizedResult(new AuthenticationHeaderValue[0], context.Request);
                }
            }
            else
            {
                context.ErrorResult = new UnauthorizedResult(new AuthenticationHeaderValue[0], context.Request);
            }

            return Task.FromResult(0);
        }

        public Task ChallengeAsync(HttpAuthenticationChallengeContext context, CancellationToken cancellationToken)
        {
            context.Result = new ResultWithChallenge(context.Result);
            return Task.FromResult(0);
        }

        private static string[] GetAuthorizationHeaderValues(string rawAuthzHeader)
        {
            // Split the authentication header.
            var credArray = rawAuthzHeader.Split(':');

            // Make sure the authentication header has the four required values.
            return credArray.Length == 4 ? credArray : null;
        }

        private bool IsValidRequest(
            HttpRequestMessage req,
            string appId,
            string incomingBase64Signature,
            string nonce,
            string requestTimeStamp)
        {
            var apiKey = ApiKeyStore.GetApiKey(appId);

            // Check if the app ID provided returned an API key.
            if (apiKey == null)
            {
                return false;
            }

            // Check if the request is a replay.
            if (IsReplayRequest(nonce, requestTimeStamp))
            {
                return false;
            }

            // Rebuild the base 64 signature.
            var rebuiltbase64Signature = HMACHelper.BuildBase64Signature(
                apiKey,
                appId,
                req.RequestUri,
                req.Method,
                req.Content,
                nonce,
                requestTimeStamp
                );

            // Check if the signatures match.
            return (incomingBase64Signature.Equals(rebuiltbase64Signature, StringComparison.Ordinal));
        }

        private static bool IsReplayRequest(string nonce, string requestTimeStamp)
        {
            if (System.Runtime.Caching.MemoryCache.Default.Contains(nonce))
            {
                return true;
            }

            var epochStart = new DateTime(1970, 01, 01, 0, 0, 0, 0, DateTimeKind.Utc);
            var currentTs = DateTime.UtcNow - epochStart;

            var serverTotalSeconds = Convert.ToUInt64(currentTs.TotalSeconds);
            var requestTotalSeconds = Convert.ToUInt64(requestTimeStamp);

            if ((serverTotalSeconds - requestTotalSeconds) > RequestMaxAgeInSeconds)
            {
                return true;
            }

            System.Runtime.Caching.MemoryCache.Default.Add(nonce, requestTimeStamp, DateTimeOffset.UtcNow.AddSeconds(RequestMaxAgeInSeconds));

            return false;
        }

        public bool AllowMultiple => false;
    }

    public class ResultWithChallenge : IHttpActionResult
    {
        private const string AuthenticationScheme = "amx";
        private readonly IHttpActionResult _next;

        public ResultWithChallenge(IHttpActionResult next)
        {
            _next = next;
        }

        public async Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
        {
            var response = await _next.ExecuteAsync(cancellationToken);

            // For unauthorised requests, adds the authentication scheme to the response.
            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                response.Headers.WwwAuthenticate.Add(new AuthenticationHeaderValue(AuthenticationScheme));
            }

            return response;
        }
    }
}