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
            InstalledProducts.SelectMany(product => product.Features.Where(feature => feature.State == InstallState.Local));

        /// <summary>
        /// The features each installed related product defines, whatever their state.
        /// </summary>
        internal static IEnumerable<IEnumerable<string>> InstalledProductFeatureNames =>
            InstalledProducts.Select(product => product.Features.Select(feature => feature.FeatureName).ToList());

        private static IEnumerable<ProductInstallation> InstalledProducts =>
            ProductInstallation.GetRelatedProducts("{" + Includes.UPGRADE_CODE + "}")
                .Where(product => product.ProductName?.Equals(Includes.PRODUCT_NAME) ?? false)
                .Where(product => product.IsInstalled);
    }
}
