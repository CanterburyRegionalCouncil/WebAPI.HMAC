using System.Collections.Generic;
using System.Configuration;

namespace YourApplication
{
    public class ApiKeyStoreConfigurationSection : ConfigurationSection
    {
        [ConfigurationProperty("", IsDefaultCollection = true)]
        [ConfigurationCollection(typeof(ApiKeyCollection), AddItemName = "apiKey")]
        public ApiKeyCollection Elements
        {
            get { return (ApiKeyCollection)this[""]; }
        }
    }

    public class ApiKeyCollection : ConfigurationElementCollection, IEnumerable<ApiKeyElement>
    {
        private readonly List<ApiKeyElement> elements;

        public ApiKeyCollection()
        {
            this.elements = new List<ApiKeyElement>();
        }

        protected override ConfigurationElement CreateNewElement()
        {
            var element = new ApiKeyElement();
            this.elements.Add(element);
            return element;
        }

        protected override object GetElementKey(ConfigurationElement element)
        {
            return ((ApiKeyElement)element).AppId;
        }

        public new IEnumerator<ApiKeyElement> GetEnumerator()
        {
            return this.elements.GetEnumerator();
        }
    }

    public class ApiKeyElement : ConfigurationElement
    {
        [ConfigurationProperty("appId", IsKey = true, IsRequired = true)]
        public string AppId
        {
            get { return (string)this["appId"]; }
        }

        [ConfigurationProperty("secretKey", IsRequired = true)]
        public string SecretKey
        {
            get { return (string)this["secretKey"]; }
        }
    }
}