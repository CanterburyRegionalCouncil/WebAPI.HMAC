using System;
using System.Net.Http;
using System.Threading.Tasks;
using WebAPI.HMAC.Http;

namespace WebAPI.HMAC.Client
{
    class Program
    {
        static void Main(string[] args)
        {

            RunAsync().Wait();
        }

        static async Task RunAsync()
        {
            Console.WriteLine("Calling the back-end API");

            const string appId = "4d53bce03ec34c0a911182d4c228ee6c";
            const string apiKey = "A93reRTUJHsCuQSHR+L3GxqOJyDmQpCgps102ciuabc=";

            var client = new HMACHttpClient(appId, apiKey);

            var order = new Order { OrderId = 10248, CustomerName = "Taiseer Joudeh", ShipperCity = "Amman", IsShipped = true };

            var response = await client.PostAsJsonAsync("http://localhost:2757/api/orders", order);

            if (response.IsSuccessStatusCode)
            {
                var responseString = await response.Content.ReadAsStringAsync();
                Console.WriteLine(responseString);
                Console.WriteLine("HTTP Status: {0}, Reason {1}. Press ENTER to exit", response.StatusCode, response.ReasonPhrase);
            }
            else
            {
                Console.WriteLine("Failed to call the API. HTTP Status: {0}, Reason {1}", response.StatusCode, response.ReasonPhrase);
            }

            Console.ReadLine();
        }
    }
}
