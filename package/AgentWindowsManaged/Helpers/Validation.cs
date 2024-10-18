using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DevolutionsAgent.Helpers
{
    internal class Validation
    {
        internal static bool IsValidPort(string port, out uint p)
        {
            p = 0;

            if (uint.TryParse(port, out p))
            {
                return p is > 0 and <= 65535;
            }

            return false;
        }
    }
}
