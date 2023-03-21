# WebAPI.HMAC

### This project has been archived and is no longer maintained.

Implementing a secure ASP.Net Web API application using HMAC security.

Based on this post: http://bitoftech.net/2014/12/15/secure-asp-net-web-api-using-api-key-authentication-hmac-authentication/

[![Build status](https://ci.appveyor.com/api/projects/status/rgtjkcj5ccfce7rl?svg=true)](https://ci.appveyor.com/project/SamStrong/webapi-hmac)

## Configuration based API Key Store example

The files under [ConfigApiKeyStore](https://github.com/gavinharriss/WebAPI.HMAC/tree/master/ConfigApiKeyStore) provide an IApiKeyStore implementation that uses the configuration file for storing App ID and Secret Key pairs.
