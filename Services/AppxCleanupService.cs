using System;
using Microsoft.Win32;

namespace EASYSID;

internal static class AppxCleanupService
{
    internal static void CleanupAppxAllUserStore(string hiveRoot = null)
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
                Console.WriteLine($"  Appx: SID subkey '{subkeyName}'");
                try
                {
                    using var sidKey = appx.OpenSubKey(subkeyName, true);
                    if (sidKey == null) continue;
                    foreach (string childName in sidKey.GetSubKeyNames())
                    {
                        if (childName.StartsWith("Microsoft.Windows.Search_", StringComparison.OrdinalIgnoreCase))
                        {
                            try
                            {
                                sidKey.DeleteSubKeyTree(childName, false);
                                Console.WriteLine($"    Deleted '{childName}'.");
                                deletedTotal++;
                            }
                            catch (Exception exDel) { Console.WriteLine($"    Delete '{childName}' failed: {exDel.Message}"); }
                        }
                    }
                }
                catch (Exception exSid) { Console.WriteLine($"  Appx: opening '{subkeyName}' failed: {exSid.Message}"); }
            }
            Console.WriteLine($"  AppxAllUserStore cleanup: {deletedTotal} key(s) deleted.");
        }
        catch (Exception ex) { Console.WriteLine($"  AppxAllUserStore cleanup failed: {ex.Message}"); }
    }
}
