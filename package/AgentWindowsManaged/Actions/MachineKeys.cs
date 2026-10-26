using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace DevolutionsAgent.Actions;

/// <summary>
/// Machine keys of the Microsoft Software Key Storage Provider, where the Windows software provider device-key backend
/// keeps its keys.
/// </summary>
internal static class MachineKeys
{
    internal static List<string> List()
    {
        int status = WinAPI.NCryptOpenStorageProvider(
            out IntPtr provider,
            CngProvider.MicrosoftSoftwareKeyStorageProvider.Provider,
            0);

        if (status != 0)
        {
            throw new Win32Exception(status, "NCryptOpenStorageProvider failed");
        }

        IntPtr state = IntPtr.Zero;

        try
        {
            List<string> names = new();

            while (true)
            {
                status = WinAPI.NCryptEnumKeys(provider, null, out IntPtr keyName, ref state, WinAPI.NCRYPT_MACHINE_KEY_FLAG);

                if (status == WinAPI.NTE_NO_MORE_ITEMS)
                {
                    return names;
                }

                if (status != 0)
                {
                    throw new Win32Exception(status, "NCryptEnumKeys failed");
                }

                try
                {
                    // pszName is the first field of NCryptKeyName.
                    names.Add(Marshal.PtrToStringUni(Marshal.ReadIntPtr(keyName)));
                }
                finally
                {
                    WinAPI.NCryptFreeBuffer(keyName);
                }
            }
        }
        finally
        {
            if (state != IntPtr.Zero)
            {
                WinAPI.NCryptFreeBuffer(state);
            }

            WinAPI.NCryptFreeObject(provider);
        }
    }

    internal static void Delete(string name)
    {
        using CngKey key = CngKey.Open(
            name,
            CngProvider.MicrosoftSoftwareKeyStorageProvider,
            CngKeyOpenOptions.MachineKey | CngKeyOpenOptions.Silent);
        key.Delete();
    }
}
