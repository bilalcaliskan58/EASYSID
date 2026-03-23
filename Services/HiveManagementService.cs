using System;
using Microsoft.Win32;

namespace EASYSID;

/// <summary>
/// Manages user registry hive loading/unloading operations.
/// </summary>
internal static class HiveManagementService
{
    /// <summary>
    /// Reads HKLM\SYSTEM\CurrentControlSet\Control\HiveList, collects all
    /// user hive paths (excluding EASYSID-mounted temp hives), and unloads them.
    ///
    /// From RE of sub_14005D080:
    ///   - Enumerates all value names in the HiveList key
    ///   - Filters OUT hives whose names match EASYSID temp patterns:
    ///       ends with "EASYSID", starts with "AppEASYSID", equals "EASYSIDossoft-",
    ///       starts with "userhiveEASYSID", starts with "userclasseshiveEASYSID"
    ///   - Calls RegUnLoadKey(HKEY_USERS, hiveName) for each remaining user hive
    /// </summary>
    internal static void UnloadUserHives()
    {
        const string hiveListPath = @"SYSTEM\CurrentControlSet\Control\HiveList";
        try
        {
            using var hiveList = RegistryHelper.OpenRegKey(RegistryHive.LocalMachine, hiveListPath);
            if (hiveList == null)
            {
                Console.Error.WriteLine("  FAH: cannot open hivelist");
                return;
            }

            string[] allValues = hiveList.GetValueNames();
            Console.WriteLine($"  HiveList: {allValues.Length} value(s) found.");
            int unloaded = 0, skipped = 0, failed = 0;

            foreach (string valueName in allValues)
            {
                string lower = valueName.ToLowerInvariant();
                // Filter out EASYSID-mounted temp hives
                if (lower.EndsWith("easysid") ||
                    lower.StartsWith("appeasysid") ||
                    lower.Equals("easysidossoft-") ||
                    lower.StartsWith("userhiveeasysid") ||
                    lower.StartsWith("userclasseshiveeasysid") ||
                    lower.StartsWith("easysid_sd_") ||
                    lower.StartsWith("easysid_temp_"))
                {
                    Console.WriteLine($"  HiveList: skipping EASYSID hive '{valueName}'.");
                    skipped++;
                    continue;
                }

                // Unload user hive from HKEY_USERS (= HKCU parent)
                try
                {
                    int rc = NativeMethods.RegUnLoadKeyW(NativeMethods.HKEY_USERS, valueName);
                    if (rc == 0)
                    {
                        Console.WriteLine($"  HiveList: unloaded '{valueName}'.");
                        unloaded++;
                    }
                    else
                    {
                        Console.WriteLine($"  HiveList: RegUnLoadKey '{valueName}' returned 0x{rc:X8}.");
                        failed++;
                    }
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"  HiveList: RegUnLoadKey '{valueName}' exception: {ex.Message}");
                    failed++;
                }
            }
            Console.WriteLine($"  HiveList summary: {unloaded} unloaded, {skipped} skipped, {failed} failed.");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"  FAH cannot open hivelist: {ex.Message}");
        }
    }
}
