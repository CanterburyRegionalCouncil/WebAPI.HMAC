using System;
using System.Net.Http;
using System.Threading.Tasks;

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

            var apiBaseAddress = "http://localhost:43326/";

            var customDelegatingHandler = new CustomDelegatingHandler();

            var client = HttpClientFactory.Create(customDelegatingHandler);

            var order = new Order { OrderId = 10248, CustomerName = "Taiseer Joudeh", ShipperCity = "Amman", IsShipped = true };

            var response = await client.PostAsJsonAsync(apiBaseAddress + "api/orders", order);

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
