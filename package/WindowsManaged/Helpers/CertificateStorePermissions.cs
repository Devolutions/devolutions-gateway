using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using DevolutionsGateway.Resources;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace DevolutionsGateway.Helpers;

internal static class CertificateStorePermissions
{
    internal static void ValidateSelection(StoreLocation location)
    {
        if (location != StoreLocation.LocalMachine)
        {
            throw new InvalidOperationException("Select a LocalMachine certificate store. Setup cannot configure or verify the service account's CurrentUser or CurrentService store.");
        }
    }

    internal static string ValidateExisting(JObject config, SecurityIdentifier accountSid, string existingAccount, bool configuring)
    {
        string location = GetLocation(config);
        if (location == null || location == "LocalMachine")
        {
            return string.Empty;
        }

        if (configuring || string.IsNullOrWhiteSpace(existingAccount))
        {
            throw new InvalidOperationException("An existing CurrentUser or CurrentService certificate configuration can only be retained without reconfiguration for the same existing service account. Migrate to LocalMachine or certificate files before running setup.");
        }

        if (!GatewayServiceAccount.TryResolve(existingAccount, Includes.SERVICE_NAME, out GatewayServiceAccount previous, out string error))
        {
            throw new InvalidOperationException(error);
        }

        if (!previous.Sid.Equals(accountSid))
        {
            throw new InvalidOperationException("Changing the service account with a CurrentUser or CurrentService certificate store is not supported. Migrate to LocalMachine or certificate files before running setup.");
        }

        return Hash(config);
    }

    internal static bool PreserveExisting(JObject config, string validatedHash)
    {
        string location = GetLocation(config);
        if (!string.IsNullOrEmpty(validatedHash))
        {
            if (!string.Equals(validatedHash, Hash(config), StringComparison.Ordinal))
            {
                throw new InvalidOperationException("the retained certificate-store configuration changed after validation");
            }

            return true;
        }

        if (location != null && location != "LocalMachine")
        {
            throw new InvalidOperationException("the CurrentUser or CurrentService certificate configuration was not validated for retention");
        }

        return false;
    }

    private static string GetLocation(JObject config)
    {
        if (!string.Equals((string)config["TlsCertificateSource"], "System", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        JToken token = config["TlsCertificateStoreLocation"];
        if (token != null && token.Type != JTokenType.Null && token.Type != JTokenType.String)
        {
            throw new InvalidOperationException("TlsCertificateStoreLocation must be CurrentUser, CurrentService, or LocalMachine");
        }

        string location = (string)token ?? "CurrentUser";
        if (location != "CurrentUser" && location != "CurrentService" && location != "LocalMachine")
        {
            throw new InvalidOperationException("TlsCertificateStoreLocation must be CurrentUser, CurrentService, or LocalMachine");
        }

        return location;
    }

    private static string Hash(JObject config)
    {
        // Detect configuration changes without passing its potentially sensitive contents to deferred actions.
        using SHA256 hash = SHA256.Create();
        return Convert.ToBase64String(hash.ComputeHash(Encoding.UTF8.GetBytes(config.ToString(Formatting.None))));
    }
}
