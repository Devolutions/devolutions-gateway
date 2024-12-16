using DevolutionsAgent.Resources;
using Microsoft.Deployment.WindowsInstaller;
using System;
using System.Collections.Generic;
using System.Linq;

namespace DevolutionsAgent.Helpers
{
    internal static class AppSearch
    {
        internal static Version InstalledVersion =>
            WixSharp.CommonTasks.AppSearch.GetRelatedProducts("{" + Includes.UPGRADE_CODE + "}")
                .Where(productCode => WixSharp.CommonTasks.AppSearch.GetProductName(productCode)?.Equals(Includes.PRODUCT_NAME) ?? false)
                .Select(WixSharp.CommonTasks.AppSearch.GetProductVersion)
                .FirstOrDefault();

        internal static IEnumerable<FeatureInstallation> InstalledFeatures =>
            ProductInstallation.GetRelatedProducts("{" + Includes.UPGRADE_CODE + "}")
                .Where(product => product.ProductName?.Equals(Includes.PRODUCT_NAME) ?? false)
                .Where(product => product.IsInstalled)
                .SelectMany(product => product.Features.Where(feature => feature.State == InstallState.Local));
    }
}
