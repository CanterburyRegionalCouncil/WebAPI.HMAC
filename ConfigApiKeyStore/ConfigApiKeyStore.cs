using System.Configuration;
using WebAPI.HMAC.Store;

namespace YourApplication
{
    public class ConfigApiKeyStore : IApiKeyStore
    {
        public string GetApiKey(string appId)
        {
            var config = (ApiKeyStoreConfigurationSection)ConfigurationManager.GetSection("apiKeyStore");
            foreach (var apiKey in config.Elements)
            {
                if (apiKey.AppId == appId) return apiKey.SecretKey;
            }
            return null;
        }
    }
}