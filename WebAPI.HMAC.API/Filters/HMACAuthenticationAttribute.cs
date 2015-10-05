using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using System.Web.Http.Filters;
using System.Web.Http.Results;

namespace WebAPI.HMAC.API.Filters
{
    public class HMACAuthenticationAttribute : Attribute, IAuthenticationFilter
    {
        private static readonly Dictionary<string, string> AllowedApps = new Dictionary<string, string>();
        private const uint RequestMaxAgeInSeconds = 300; //5 mins
        private const string AuthenticationScheme = "amx";

        public HMACAuthenticationAttribute()
        {
            // Get this list from the database. Maybe cache it for X amount of time.
            if (AllowedApps.Count == 0)
            {
                AllowedApps.Add("4d53bce03ec34c0a911182d4c228ee6c", "A93reRTUJHsCuQSHR+L3GxqOJyDmQpCgps102ciuabc=");
            }
        }

        public Task AuthenticateAsync(HttpAuthenticationContext context, CancellationToken cancellationToken)
        {
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
                    // This would be the place to build in the roles.
                    // Use identity to get roles based on user attached to app ID.
                    if (isValid.Result)
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

        private string[] GetAuthorizationHeaderValues(string rawAuthzHeader)
        {
            // Split the authentication header.
            var credArray = rawAuthzHeader.Split(':');

            // Make sure the authentication header has the four required values.
            return credArray.Length == 4 ? credArray : null;
        }

        private async Task<bool> IsValidRequest(HttpRequestMessage req, string appId, string incomingBase64Signature, string nonce, string requestTimeStamp)
        {
            var requestContentBase64String = "";
            var requestUri = HttpUtility.UrlEncode(req.RequestUri.AbsoluteUri.ToLower());
            var requestHttpMethod = req.Method.Method;

            // Check if the app ID provided is allowed to access the API period.
            if (!AllowedApps.ContainsKey(appId))
            {
                return false;
            }

            // Get the apiKey for the proivided appId.
            var sharedKey = AllowedApps[appId];

            // Check if the request is a replay.
            if (IsReplayRequest(nonce, requestTimeStamp))
            {
                return false;
            }

            // Hash the request content.
            var hash = await ComputeHash(req.Content);

            // If the result is not null then convert it into a base 64 string.
            if (hash != null)
            {
                requestContentBase64String = Convert.ToBase64String(hash);
            }

            // Rebuild the signature raw data.
            var signatureRawData =
                $"{appId}{requestHttpMethod}{requestUri}{requestTimeStamp}{nonce}{requestContentBase64String}";

            // Get the api key bytes.
            var secretKeyBytes = Convert.FromBase64String(sharedKey);

            // Get the signature.
            var signature = Encoding.UTF8.GetBytes(signatureRawData);

            // Create HMAC SHA class with key data.
            using (var hmac = new HMACSHA256(secretKeyBytes))
            {
                var base64Signature = Convert.ToBase64String(hmac.ComputeHash(signature));

                // Check if the base 64 signatures match.
                return (incomingBase64Signature.Equals(base64Signature, StringComparison.Ordinal));
            }
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

        private static async Task<byte[]> ComputeHash(HttpContent httpContent)
        {
            using (var md5 = MD5.Create())
            {
                byte[] hash = null;
                var content = await httpContent.ReadAsByteArrayAsync();
                if (content.Length != 0)
                {
                    hash = md5.ComputeHash(content);
                }
                return hash;
            }
        }

        public bool AllowMultiple => false;
    }

    public class ResultWithChallenge : IHttpActionResult
    {
        // TODO Could put this in the config file somewhere.
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