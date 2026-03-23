using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

namespace EASYSID;

/// <summary>
/// Patches security descriptors of all registry keys in SAM, SECURITY, SOFTWARE, SYSTEM hives
/// and user hives, replacing old SID with new SID in Owner, Group, DACL, and SACL.
/// </summary>
internal static class SecurityDescriptorService
{
    /// <summary>
    /// Patches security descriptors of all registry keys in SAM, SECURITY, SOFTWARE, SYSTEM hives
    /// and user hive (if loaded). Opens each hive root via NtOpenKeyEx and recursively patches all subkeys.
    /// </summary>
    internal static void PatchAllHiveKeySecurityDescriptors(uint[] oldSa, uint[] newSa, string profilePath)
    {
        Console.WriteLine("[*] Patching registry key security descriptors (all hives)...");

        byte[] old16 = SidOperations.BuildSidPattern16(oldSa);
        byte[] new16 = SidOperations.BuildSidPattern16(newSa);

        // Debug: print the pattern bytes we're searching for
        Console.WriteLine($"  Old pattern: {BitConverter.ToString(old16)}");
        Console.WriteLine($"  New pattern: {BitConverter.ToString(new16)}");

        // Enable SeSecurityPrivilege (index 8) so we can read/write SACL
        NativeImports.RtlAdjustPrivilege(8, true, false, out _);

        // System hive roots
        string[] systemHives = new[]
        {
            @"\Registry\Machine\SAM",
            @"\Registry\Machine\SECURITY",
            @"\Registry\Machine\SOFTWARE",
            @"\Registry\Machine\SYSTEM",
        };

        foreach (string hivePath in systemHives)
        {
            PatchSingleHiveKeySD(hivePath, old16, new16);
        }

        // User hive files: load, patch SD, unload
        if (profilePath != null && Directory.Exists(profilePath))
        {
            var userHiveCandidates = new (string path, string tempName)[]
            {
                (Path.Combine(profilePath, "NTUSER.DAT"), "EASYSID_SD_NTUSER"),
                (Path.Combine(profilePath, @"AppData\Local\Microsoft\Windows\UsrClass.dat"), "EASYSID_SD_USRCLASS"),
            };

            foreach (var (hiveFile, tempName) in userHiveCandidates)
            {
                if (!File.Exists(hiveFile)) continue;
                string displayName = Path.GetFileName(hiveFile);

                Console.WriteLine($"  User hive: {displayName}");

                // Load hive
                int rc = NativeImports.RegLoadKeyW(NativeMethods.HKEY_LOCAL_MACHINE, tempName, hiveFile);
                if (rc != 0)
                {
                    // Retry after GC
                    GC.Collect();
                    GC.WaitForPendingFinalizers();
                    Thread.Sleep(500);
                    rc = NativeImports.RegLoadKeyW(NativeMethods.HKEY_LOCAL_MACHINE, tempName, hiveFile);
                }
                if (rc != 0)
                {
                    Console.WriteLine($"    RegLoadKey failed: 0x{rc:X8}  -  skipped.");
                    continue;
                }

                try
                {
                    PatchSingleHiveKeySD($@"\Registry\Machine\{tempName}", old16, new16);
                }
                finally
                {
                    // Flush and unload
                    IntPtr hiveHandle = RegistryHelper.OpenNtKey($@"\Registry\Machine\{tempName}", 0x20000);
                    if (hiveHandle != IntPtr.Zero)
                    {
                        NativeImports.NtFlushKey(hiveHandle);
                        NativeImports.NtClose(hiveHandle);
                    }
                    int urc = NativeMethods.RegUnLoadKeyW(NativeMethods.HKEY_LOCAL_MACHINE, tempName);
                    if (urc != 0)
                        Console.WriteLine($"    RegUnLoadKey: 0x{urc:X8}");
                }
            }
        }
        else
        {
            Console.WriteLine("  No profile path  -  user hive SD patching skipped.");
        }

        Console.WriteLine("  Registry key SD patching complete.");
    }

    private static void PatchSingleHiveKeySD(string ntPath, byte[] old16, byte[] new16)
    {
        string displayName = ntPath.Replace(@"\Registry\Machine\", "");
        Console.WriteLine($"  Hive: {displayName}");
        int changed = 0, total = 0, errors = 0;

        // ACCESS_MASK: READ_CONTROL | WRITE_OWNER | WRITE_DAC | ACCESS_SYSTEM_SECURITY | KEY_ENUMERATE_SUB_KEYS
        const uint ACCESS = 0x10E0008;

        IntPtr hiveHandle = RegistryHelper.OpenNtKey(ntPath, ACCESS);
        if (hiveHandle == IntPtr.Zero)
        {
            // Try without ACCESS_SYSTEM_SECURITY
            const uint ACCESS_NO_SACL = 0x000E0008;
            hiveHandle = RegistryHelper.OpenNtKey(ntPath, ACCESS_NO_SACL);
        }

        if (hiveHandle == IntPtr.Zero)
        {
            Console.WriteLine($"    Failed to open  -  skipped.");
            return;
        }

        try
        {
            PatchKeySecurityRecursive(hiveHandle, old16, new16, ref changed, ref total, ref errors);
            NativeImports.NtFlushKey(hiveHandle);
        }
        finally
        {
            NativeImports.NtClose(hiveHandle);
        }

        Console.WriteLine($"    Keys: {total} scanned, {changed} SD(s) patched, {errors} error(s).");
    }

    private static void PatchKeySecurityRecursive(IntPtr keyHandle, byte[] old16, byte[] new16,
                                                   ref int changed, ref int total, ref int errors)
    {
        const uint SD_ALL = 0xF; // OWNER|GROUP|DACL|SACL
        const uint SD_NO_SACL = 0x7; // OWNER|GROUP|DACL only
        const uint SD_BUFFER_SIZE = 0x4000; // 16 KB
        const int KeyBasicInformation = 0;

        total++;

        // 1. Query this key's security descriptor
        IntPtr sdBuf = Marshal.AllocHGlobal((int)SD_BUFFER_SIZE);
        try
        {
            uint queryMask = SD_ALL;
            int st = NativeImports.NtQuerySecurityObject(keyHandle, queryMask, sdBuf, SD_BUFFER_SIZE, out uint needed);

            // If SACL access denied (STATUS_ACCESS_DENIED=0xC0000022 or STATUS_PRIVILEGE_NOT_HELD=0xC0000061),
            // retry without SACL
            if (st == unchecked((int)0xC0000022) || st == unchecked((int)0xC0000061))
            {
                queryMask = SD_NO_SACL;
                st = NativeImports.NtQuerySecurityObject(keyHandle, queryMask, sdBuf, SD_BUFFER_SIZE, out needed);
            }

            if (st != 0)
            {
                // Try with larger buffer
                if (needed > SD_BUFFER_SIZE && needed < 0x100000)
                {
                    Marshal.FreeHGlobal(sdBuf);
                    sdBuf = Marshal.AllocHGlobal((int)needed);
                    st = NativeImports.NtQuerySecurityObject(keyHandle, queryMask, sdBuf, needed, out _);
                }
                if (st != 0)
                {
                    errors++;
                    return;
                }
            }

            // 2. Replace SIDs in-place within the self-relative SD buffer
            uint mask = SidOperations.ReplaceSidInSecurityDescriptor(sdBuf, old16, new16);
            if (mask != 0)
            {
                int setSt = NativeImports.NtSetSecurityObject(keyHandle, mask, sdBuf);
                if (setSt == 0)
                    changed++;
                else
                    errors++;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(sdBuf);
        }

        // 3. Enumerate and recurse into subkeys
        IntPtr enumBuf = Marshal.AllocHGlobal(0x1000);
        try
        {
            uint index = 0;
            while (true)
            {
                int st = NativeImports.NtEnumerateKey(keyHandle, index, KeyBasicInformation, enumBuf, 0x1000, out _);
                if (st != 0) break; // STATUS_NO_MORE_ENTRIES or error

                // KeyBasicInformation: {LARGE_INTEGER LastWriteTime, ULONG TitleIndex, ULONG NameLength, WCHAR Name[]}
                // NameLength is at offset 12 (after 8+4), Name starts at offset 16
                int nameLen = Marshal.ReadInt32(enumBuf, 12); // bytes
                string subkeyName = Marshal.PtrToStringUni(enumBuf + 16, nameLen / 2);

                // Open subkey with full security access
                // ACCESS_MASK: READ_CONTROL(0x20000) | WRITE_OWNER(0x80000) | WRITE_DAC(0x40000) |
                //              ACCESS_SYSTEM_SECURITY(0x1000000) | KEY_ENUMERATE_SUB_KEYS(0x8)
                const uint ACCESS = 0x10E0008;

                // Build UNICODE_STRING for subkey name
                IntPtr nameBuf = Marshal.StringToHGlobalUni(subkeyName);
                int byteLen = subkeyName.Length * 2;
                // UNICODE_STRING: {USHORT Length, USHORT MaxLength, WCHAR* Buffer}
                IntPtr ustr = Marshal.AllocHGlobal(16); // 2+2+4padding+8(ptr) for x64
                Marshal.WriteInt16(ustr, 0, (short)byteLen);
                Marshal.WriteInt16(ustr, 2, (short)(byteLen + 2));
                Marshal.WriteIntPtr(ustr, 8, nameBuf); // offset 8 on x64 (due to alignment)

                var oa = new OBJECT_ATTRIBUTES
                {
                    Length = Marshal.SizeOf<OBJECT_ATTRIBUTES>(),
                    RootDirectory = keyHandle,
                    ObjectName = ustr,
                    Attributes = 0x00000240, // OBJ_CASE_INSENSITIVE | OBJ_OPENIF
                };

                int openSt = NativeImports.NtOpenKeyEx(out IntPtr subHandle, ACCESS, ref oa, 0);
                if (openSt == 0)
                {
                    PatchKeySecurityRecursive(subHandle, old16, new16, ref changed, ref total, ref errors);
                    NativeImports.NtClose(subHandle);
                }
                // else: skip inaccessible subkeys silently

                Marshal.FreeHGlobal(nameBuf);
                Marshal.FreeHGlobal(ustr);

                index++;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(enumBuf);
        }
    }
}
