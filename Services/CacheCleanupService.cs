using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using Microsoft.Win32;

namespace EASYSID;

internal static class CacheCleanupService
{
    internal static void ClearIconAndShellCaches(string winDir)
    {
        Console.WriteLine("[*] Clearing icon/thumbnail caches and shell bags...");
        string systemDrive = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:";
        string usersRoot = Path.Combine(systemDrive, "Users");

        if (!Directory.Exists(usersRoot))
        {
            Console.WriteLine($"  Users root not found: {usersRoot}");
            return;
        }

        var ignoredProfiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Default", "Default User", "Public", "All Users", "defaultuser0"
        };

        int deletedFiles = 0, deletedKeys = 0;

        foreach (string profileDir in Directory.GetDirectories(usersRoot))
        {
            string profileName = Path.GetFileName(profileDir);
            if (ignoredProfiles.Contains(profileName))
                continue;

            // 1. Delete icon cache files
            string explorerCacheDir = Path.Combine(profileDir, @"AppData\Local\Microsoft\Windows\Explorer");
            if (Directory.Exists(explorerCacheDir))
            {
                try
                {
                    foreach (string cacheFile in Directory.GetFiles(explorerCacheDir, "iconcache_*.db"))
                    {
                        try { File.Delete(cacheFile); deletedFiles++; }
                        catch { }
                    }
                    foreach (string cacheFile in Directory.GetFiles(explorerCacheDir, "thumbcache_*.db"))
                    {
                        try { File.Delete(cacheFile); deletedFiles++; }
                        catch { }
                    }
                    // Also delete IconCacheToDelete file if present
                    string icd = Path.Combine(explorerCacheDir, "IconCacheToDelete");
                    if (File.Exists(icd)) { try { File.Delete(icd); deletedFiles++; } catch { } }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"    {profileName}: cache file cleanup: {ex.Message}");
                }
            }

            // 2. Delete shell bag data from user hive (NTUSER.DAT)
            string ntuserPath = Path.Combine(profileDir, "NTUSER.DAT");
            if (File.Exists(ntuserPath))
            {
                string tempName = "EASYSID_ICONCACHE_" + profileName.ToUpperInvariant();
                int rc = NativeImports.RegLoadKeyW(NativeMethods.HKEY_USERS, tempName, ntuserPath);
                if (rc != 0)
                {
                    GC.Collect(); GC.WaitForPendingFinalizers(); Thread.Sleep(300);
                    rc = NativeImports.RegLoadKeyW(NativeMethods.HKEY_USERS, tempName, ntuserPath);
                }
                if (rc == 0)
                {
                    try
                    {
                        using var hiveKey = RegistryHelper.OpenRegKey(RegistryHive.Users, tempName, true);
                        if (hiveKey != null)
                        {
                            // Shell bags: BagMRU and Bags store folder view state with icon positions
                            string[] shellBagPaths = new[]
                            {
                                @"Software\Microsoft\Windows\Shell\BagMRU",
                                @"Software\Microsoft\Windows\Shell\Bags",
                                @"Software\Microsoft\Windows\ShellNoRoam\BagMRU",
                                @"Software\Microsoft\Windows\ShellNoRoam\Bags",
                                @"Software\Microsoft\Windows\CurrentVersion\Explorer\Streams",
                                @"Software\Microsoft\Windows\CurrentVersion\Explorer\StreamMRU",
                            };
                            foreach (string sbPath in shellBagPaths)
                            {
                                try
                                {
                                    hiveKey.DeleteSubKeyTree(sbPath, false);
                                    deletedKeys++;
                                }
                                catch { }
                            }

                            // Clear IconStreams and PastIconsStream binary data
                            // These hold taskbar icon state - stale data causes icon shuffling
                            try
                            {
                                using var taskbarKey = hiveKey.OpenSubKey(
                                    @"Software\Microsoft\Windows\CurrentVersion\Explorer\TrayNotify", true);
                                if (taskbarKey != null)
                                {
                                    taskbarKey.DeleteValue("IconStreams", false);
                                    taskbarKey.DeleteValue("PastIconsStream", false);
                                    deletedKeys++;
                                }
                            }
                            catch { }
                        }
                    }
                    finally
                    {
                        // Flush and unload
                        IntPtr hiveHandle = RegistryHelper.OpenNtKey($@"\Registry\User\{tempName}", 0x20000);
                        if (hiveHandle != IntPtr.Zero)
                        {
                            NativeImports.NtFlushKey(hiveHandle);
                            NativeImports.NtClose(hiveHandle);
                        }
                        NativeMethods.RegUnLoadKeyW(NativeMethods.HKEY_USERS, tempName);
                    }
                }
                else
                {
                    Console.WriteLine($"    {profileName}: NTUSER.DAT load failed (0x{rc:X8}) - shell bag cleanup skipped.");
                }
            }

            // 3. Delete shell bag data from UsrClass.dat (HKCU\Software\Classes)
            string usrClassPath = Path.Combine(profileDir, @"AppData\Local\Microsoft\Windows\UsrClass.dat");
            if (File.Exists(usrClassPath))
            {
                string tempName2 = "EASYSID_ICONCACHE_CLS_" + profileName.ToUpperInvariant();
                int rc2 = NativeImports.RegLoadKeyW(NativeMethods.HKEY_USERS, tempName2, usrClassPath);
                if (rc2 != 0)
                {
                    GC.Collect(); GC.WaitForPendingFinalizers(); Thread.Sleep(300);
                    rc2 = NativeImports.RegLoadKeyW(NativeMethods.HKEY_USERS, tempName2, usrClassPath);
                }
                if (rc2 == 0)
                {
                    try
                    {
                        using var clsKey = RegistryHelper.OpenRegKey(RegistryHive.Users, tempName2, true);
                        if (clsKey != null)
                        {
                            string[] clsBagPaths = new[]
                            {
                                @"Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
                                @"Local Settings\Software\Microsoft\Windows\Shell\Bags",
                            };
                            foreach (string cbPath in clsBagPaths)
                            {
                                try
                                {
                                    clsKey.DeleteSubKeyTree(cbPath, false);
                                    deletedKeys++;
                                }
                                catch { }
                            }
                        }
                    }
                    finally
                    {
                        IntPtr hiveHandle2 = RegistryHelper.OpenNtKey($@"\Registry\User\{tempName2}", 0x20000);
                        if (hiveHandle2 != IntPtr.Zero)
                        {
                            NativeImports.NtFlushKey(hiveHandle2);
                            NativeImports.NtClose(hiveHandle2);
                        }
                        NativeMethods.RegUnLoadKeyW(NativeMethods.HKEY_USERS, tempName2);
                    }
                }
            }

            Console.WriteLine($"    {profileName}: icon cache cleanup done.");
        }

        // 4. Clear system-wide icon cache
        string systemIconCache = Path.Combine(winDir, @"System32\config\systemprofile\AppData\Local\Microsoft\Windows\Explorer");
        if (Directory.Exists(systemIconCache))
        {
            try
            {
                foreach (string f in Directory.GetFiles(systemIconCache, "iconcache_*.db"))
                {
                    try { File.Delete(f); deletedFiles++; } catch { }
                }
            }
            catch { }
        }

        Console.WriteLine($"  Icon/shell cache cleanup: {deletedFiles} file(s), {deletedKeys} registry key(s) cleared.");
    }
}
