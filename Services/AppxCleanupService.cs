using System;
using Microsoft.Win32;

namespace EASYSID;

internal static class AppxCleanupService
{
    /// <summary>
    /// Removes ALL old SID subkeys from AppxAllUserStore.
    /// Only keeps the new SID subkey (if it exists) and non-SID keys.
    /// Stale SID keys from previous changes cause icon flickering
    /// because Windows tries to resolve package registrations for non-existent SIDs.
    /// </summary>
    internal static void CleanupAppxAllUserStore(string newSid = null)
    {
        string basePath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore";
        Console.WriteLine($"[*] CleanupAppxAllUserStore: scanning '{basePath}'...");
        try
        {
            using var appx = RegistryHelper.OpenRegKey(RegistryHive.LocalMachine, basePath, true);
            if (appx == null) { Console.WriteLine("  AppxAllUserStore key not found, skipping."); return; }

            int deletedTotal = 0;
            foreach (string subkeyName in appx.GetSubKeyNames())
            {
                if (!subkeyName.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)) continue;

                // Keep the new SID subkey, delete all others (stale from previous SID changes)
                if (newSid != null && subkeyName.Contains(newSid, StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine($"  Appx: keeping current SID subkey '{subkeyName}'");
                    continue;
                }

                Console.WriteLine($"  Appx: deleting stale SID subkey '{subkeyName}'");
                try
                {
                    appx.DeleteSubKeyTree(subkeyName, false);
                    deletedTotal++;
                }
                catch (Exception exDel)
                {
                    Console.WriteLine($"    Delete '{subkeyName}' failed: {exDel.Message}");
                }
            }
            Console.WriteLine($"  AppxAllUserStore cleanup: {deletedTotal} key(s) deleted.");
        }
        catch (Exception ex) { Console.WriteLine($"  AppxAllUserStore cleanup failed: {ex.Message}"); }
    }
}
