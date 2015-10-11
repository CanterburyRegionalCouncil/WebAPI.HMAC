# WebAPI.HMAC

WebAPI.HMAC is (hopefully) a lightweight way of implementing HMAC security when building ASP.Net Web API services.

Based on this post: http://bitoftech.net/2014/12/15/secure-asp-net-web-api-using-api-key-authentication-hmac-authentication/

[![Build status](https://ci.appveyor.com/api/projects/status/rgtjkcj5ccfce7rl?svg=true)](https://ci.appveyor.com/project/SamStrong/webapi-hmac)

## How To Get It

Install from [NuGet]("https://www.nuget.org/packages/WebAPI.HMAC/"):
* PM> Install-Package WebAPI.HMAC

### Package Contents

The package contains a single DLL, WebAPI.HMAC, that includes the following:
- WebAPI.HMAC.Crypto.ApiKeyGenerator
- WebAPI.HMAC.Crypto.HMACHelper
- WebAPI.HMAC.Filters.HMACAuthenticationAttribute
- WebAPI.HMAC.Http.HMACDelegatingHandler
- WebAPI.HMAC.Http.HMACHttpClient
- WebAPI.HMAC.Store.IApiKeyStore

## How To Use It

### Server

1. Install the NuGet package (see above).
2. Implement an IApiKeyStore.
3. Setup an IoC container that can be used for property injection into action filters (AutoFac is good for this).
4. Map IApiKeyStore to your concrete implementation.
5. Decorate your API controller or action methods with [HMACAuthentication].

### Client

1. Install the NuGet package (see above).
2. Instead of creating a HttpClient, create a HMACHttpClient, using your app ID and API Key as constructors.
3. Make calls to the API as normal.
