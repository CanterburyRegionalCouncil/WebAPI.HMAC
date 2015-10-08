namespace WebAPI.HMAC.Store
{
    public interface IApiKeyStore
    {
        /// <summary>
        /// Returns the API key that matches an application ID.
        /// </summary>
        /// <param name="appId">The application ID.</param>
        /// <returns>The API key.</returns>
        string GetApiKey(string appId);
    }
}