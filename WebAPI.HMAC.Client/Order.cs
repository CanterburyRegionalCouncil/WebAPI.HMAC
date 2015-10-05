using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WebAPI.HMAC.Client
{
    public class Order
    {
        public int OrderId { get; set; }
        public string CustomerName { get; set; }
        public string ShipperCity { get; set; }
        public bool IsShipped { get; set; }
    }
}
