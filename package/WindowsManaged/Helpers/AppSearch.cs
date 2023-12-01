using System;
using System.Linq;
using DevolutionsGateway.Resources;

namespace DevolutionsGateway.Helpers
{
    internal static class AppSearch
    {
        internal static Version InstalledVersion =>
            WixSharp.CommonTasks.AppSearch.GetRelatedProducts("{" + Includes.UPGRADE_CODE + "}")
                .Where(productCode => WixSharp.CommonTasks.AppSearch.GetProductName(productCode)?.Equals(Includes.PRODUCT_NAME) ?? false)
                .Select(WixSharp.CommonTasks.AppSearch.GetProductVersion)
                .FirstOrDefault();
    }
}
