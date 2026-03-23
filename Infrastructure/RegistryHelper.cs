using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace EASYSID;

internal static class RegistryHelper
{
    internal static RegistryKey OpenRegKey(RegistryHive hive, string subKey, bool writable = false)
    {
        using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
        return baseKey.OpenSubKey(subKey, writable);
    }

    internal static RegistryKey CreateRegKey(RegistryHive hive, string subKey, bool writable = true)
    {
        using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
        return baseKey.CreateSubKey(subKey, writable);
    }

    internal static void CopyRegistryKey(RegistryKey src, RegistryKey dst)
    {
        foreach (string valueName in src.GetValueNames())
        {
            object val = src.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            RegistryValueKind kind = src.GetValueKind(valueName);
            if (val != null)
                dst.SetValue(valueName, val, kind);
        }
        foreach (string subkeyName in src.GetSubKeyNames())
        {
            using var srcSub = src.OpenSubKey(subkeyName);
            using var dstSub = dst.CreateSubKey(subkeyName);
            if (srcSub != null && dstSub != null)
                CopyRegistryKey(srcSub, dstSub);
        }
    }

    /// <summary>
    /// Opens a protected registry key (SAM or SECURITY hive) using NtOpenKey
    /// which respects SeTakeOwnershipPrivilege at the kernel level.
    ///
    /// CI (CONTAINER_INHERIT) on the root key does NOT retroactively propagate
    /// to existing subkeys  -  each intermediate key must be explicitly unlocked.
    /// Strategy: walk every path component from root to target, take ownership
    /// and set DACL on each node, then open target via RegOpenKeyExW.
    /// </summary>
    internal static bool WithProtectedKeyAccess(string subKey, bool needWrite, Action<RegistryKey> action)
    {
        // Enable all relevant privileges
        // SeSecurityPrivilege=8, SeTakeOwnershipPrivilege=9, SeBackupPrivilege=17, SeRestorePrivilege=18
        NativeImports.RtlAdjustPrivilege(8,  true, false, out _); // SeSecurityPrivilege
        NativeImports.RtlAdjustPrivilege(9,  true, false, out _); // SeTakeOwnershipPrivilege
        NativeImports.RtlAdjustPrivilege(17, true, false, out _); // SeBackupPrivilege
        NativeImports.RtlAdjustPrivilege(18, true, false, out _); // SeRestorePrivilege

        const int  KEY_READ    = 0x20019;
        const int  KEY_ALL     = 0xF003F;
        const int  WRITE_DAC   = 0x00040000;
        const int  WRITE_OWNER = 0x00080000;
        const int  READ_CTRL   = 0x00020000;
        const uint DACL_INFO   = 4;
        const uint OWNER_INFO  = 1;
        const uint OBJ_CI      = 0x40; // OBJ_CASE_INSENSITIVE

        // First try direct open  -  works as SYSTEM without any manipulation
        int access = needWrite ? KEY_ALL : KEY_READ;
        int rc = NativeImports.RegOpenKeyExW(NativeImports.HKEY_LOCAL_MACHINE, subKey, 0, access, out IntPtr hDirect);
        if (rc == 0)
        {
            try
            {
                using var key = RegistryKey.FromHandle(
                    new Microsoft.Win32.SafeHandles.SafeRegistryHandle(hDirect, ownsHandle: true));
                action(key);
                return true;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"  WithProtectedKeyAccess direct '{subKey}': {ex.Message}");
                return false;
            }
        }

        // Build NT absolute paths for each component of the path, e.g.:
        //   subKey = "SAM\SAM\Domains\Account"
        //    ->  \Registry\Machine\SAM
        //    ->  \Registry\Machine\SAM\SAM
        //    ->  \Registry\Machine\SAM\SAM\Domains
        //    ->  \Registry\Machine\SAM\SAM\Domains\Account  (target)
        string[] parts = subKey.Split('\\');
        var ntPaths = new string[parts.Length];
        string prefix = @"\Registry\Machine";
        for (int i = 0; i < parts.Length; i++)
        {
            prefix += @"\" + parts[i];
            ntPaths[i] = prefix;
        }

        // Track opened handles and original DACLs for cleanup
        var handles  = new List<IntPtr>();
        var origSds  = new List<(IntPtr handle, IntPtr sd)>();

        try
        {
            // For each node: take ownership, then open with WRITE_DAC and set DACL
            foreach (string ntPath in ntPaths)
            {
                // --- Take ownership ---
                var (oa1, usMem1, strBuf1) = MakeOA(ntPath, OBJ_CI);
                int st = NativeImports.NtOpenKey(out IntPtr hOwn, (uint)WRITE_OWNER, ref oa1);
                Marshal.FreeHGlobal(usMem1);
                Marshal.FreeHGlobal(strBuf1);

                if (st != 0)
                {
                    Console.Error.WriteLine($"  NtOpenKey '{ntPath}' WRITE_OWNER failed: 0x{st:X8}");
                    return false;
                }

                if (NativeImports.ConvertStringSecurityDescriptorToSecurityDescriptor("O:BA", 1, out IntPtr ownerSd, out _))
                {
                    NativeImports.NtSetSecurityObject(hOwn, OWNER_INFO, ownerSd);
                    NativeImports.LocalFree(ownerSd);
                }
                NativeImports.RegCloseKey(hOwn);

                // --- Set DACL ---
                var (oa2, usMem2, strBuf2) = MakeOA(ntPath, OBJ_CI);
                st = NativeImports.NtOpenKey(out IntPtr hDac, (uint)(WRITE_DAC | READ_CTRL), ref oa2);
                Marshal.FreeHGlobal(usMem2);
                Marshal.FreeHGlobal(strBuf2);

                if (st != 0)
                {
                    Console.Error.WriteLine($"  NtOpenKey '{ntPath}' WRITE_DAC failed: 0x{st:X8}");
                    return false;
                }

                // Snapshot original DACL for this node
                uint sdLen = 0;
                NativeImports.NtQuerySecurityObject(hDac, DACL_INFO, IntPtr.Zero, 0, out sdLen);
                IntPtr origSd = IntPtr.Zero;
                if (sdLen > 0)
                {
                    origSd = Marshal.AllocHGlobal((int)sdLen + 256);
                    NativeImports.NtQuerySecurityObject(hDac, DACL_INFO, origSd, sdLen + 256, out _);
                }
                origSds.Add((hDac, origSd));
                handles.Add(hDac);

                // Grant Admins + SYSTEM full access
                if (NativeImports.ConvertStringSecurityDescriptorToSecurityDescriptor(
                        "D:PAI(A;;KA;;;BA)(A;;KA;;;SY)", 1, out IntPtr newSd, out _))
                {
                    NativeImports.NtSetSecurityObject(hDac, DACL_INFO, newSd);
                    NativeImports.LocalFree(newSd);
                }
            }

            // All nodes unlocked  -  open target via NtOpenKey (avoids win32 SAM filter)
            string targetNtPath = ntPaths[ntPaths.Length - 1];
            var (oaT, usMemT, strBufT) = MakeOA(targetNtPath, OBJ_CI);
            int stT = NativeImports.NtOpenKey(out IntPtr hTarget, (uint)access, ref oaT);
            Marshal.FreeHGlobal(usMemT);
            Marshal.FreeHGlobal(strBufT);

            if (stT != 0)
            {
                Console.Error.WriteLine($"  NtOpenKey target '{targetNtPath}' failed: 0x{stT:X8}");
                return false;
            }

            try
            {
                using var key = RegistryKey.FromHandle(
                    new Microsoft.Win32.SafeHandles.SafeRegistryHandle(hTarget, ownsHandle: true));
                action(key);
                return true;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"  WithProtectedKeyAccess '{subKey}': {ex.Message}");
                return false;
            }
        }
        finally
        {
            // Restore DACLs in reverse order and close handles
            for (int i = origSds.Count - 1; i >= 0; i--)
            {
                var (h, sd) = origSds[i];
                if (sd != IntPtr.Zero)
                {
                    NativeImports.NtSetSecurityObject(h, DACL_INFO, sd);
                    Marshal.FreeHGlobal(sd);
                }
            }
            foreach (var h in handles)
                NativeImports.RegCloseKey(h);

            // Restore owner back to SYSTEM on each node (best-effort)
            foreach (string ntPath in ntPaths)
            {
                var (oa3, usMem3, strBuf3) = MakeOA(ntPath, OBJ_CI);
                if (NativeImports.NtOpenKey(out IntPtr hOwnR, (uint)WRITE_OWNER, ref oa3) == 0)
                {
                    if (NativeImports.ConvertStringSecurityDescriptorToSecurityDescriptor("O:SY", 1, out IntPtr sySd, out _))
                    {
                        NativeImports.NtSetSecurityObject(hOwnR, OWNER_INFO, sySd);
                        NativeImports.LocalFree(sySd);
                    }
                    NativeImports.RegCloseKey(hOwnR);
                }
                Marshal.FreeHGlobal(usMem3);
                Marshal.FreeHGlobal(strBuf3);
            }
        }
    }

    internal static IntPtr OpenNtKey(string ntPath, uint access)
    {
        IntPtr nameBuf = Marshal.StringToHGlobalUni(ntPath);
        int byteLen = ntPath.Length * 2;
        IntPtr ustr = Marshal.AllocHGlobal(16);
        Marshal.WriteInt16(ustr, 0, (short)byteLen);
        Marshal.WriteInt16(ustr, 2, (short)(byteLen + 2));
        Marshal.WriteIntPtr(ustr, 8, nameBuf);

        var oa = new OBJECT_ATTRIBUTES
        {
            Length = Marshal.SizeOf<OBJECT_ATTRIBUTES>(),
            RootDirectory = IntPtr.Zero,
            ObjectName = ustr,
            Attributes = 0x00000240, // OBJ_CASE_INSENSITIVE | OBJ_OPENIF
        };

        int st = NativeImports.NtOpenKeyEx(out IntPtr handle, access, ref oa, 0);
        Marshal.FreeHGlobal(nameBuf);
        Marshal.FreeHGlobal(ustr);

        if (st != 0)
        {
            Console.WriteLine($"    NtOpenKeyEx({ntPath.Replace(@"\Registry\Machine\", "")}): 0x{st:X8}");
            return IntPtr.Zero;
        }
        return handle;
    }

    internal static void SetKeyWriteTime(RegistryKey key, long fileTime)
    {
        try
        {
            // Get the native handle from the RegistryKey
            IntPtr hKey = key.Handle.DangerousGetHandle();

            // KeyWriteTimeInformation = 0, expects a LARGE_INTEGER (8 bytes)
            IntPtr buf = Marshal.AllocHGlobal(8);
            try
            {
                Marshal.WriteInt64(buf, fileTime);
                int status = NativeImports.NtSetInformationKey(hKey, 0, buf, 8);
                if (status != 0)
                    Console.WriteLine($"      NtSetInformationKey: 0x{status:X8}");
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"      SetKeyWriteTime: {ex.Message}");
        }
    }

    /// <summary>
    /// Recursively scans all registry values under rootKey and replaces
    /// occurrences of oldSid with newSid in String, ExpandString, and MultiString values.
    /// </summary>
    internal static int ReplaceUserHiveSidStrings(RegistryKey rootKey, string oldSid, string newSid)
    {
        int count = 0;
        try
        {
            // Replace in all values of this key
            foreach (string valueName in rootKey.GetValueNames())
            {
                RegistryValueKind kind = rootKey.GetValueKind(valueName);
                if (kind == RegistryValueKind.String || kind == RegistryValueKind.ExpandString)
                {
                    string val = rootKey.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
                    if (val != null && val.Contains(oldSid, StringComparison.OrdinalIgnoreCase))
                    {
                        // Check the char after match is not a digit (avoids partial SID matches)
                        string newVal = ReplaceSidInString(val, oldSid, newSid);
                        if (newVal != val)
                        {
                            rootKey.SetValue(valueName, newVal, kind);
                            count++;
                        }
                    }
                }
                else if (kind == RegistryValueKind.MultiString)
                {
                    string[] arr = rootKey.GetValue(valueName) as string[];
                    if (arr != null)
                    {
                        bool changed = false;
                        for (int i = 0; i < arr.Length; i++)
                        {
                            if (arr[i] != null && arr[i].Contains(oldSid, StringComparison.OrdinalIgnoreCase))
                            {
                                string newStr = ReplaceSidInString(arr[i], oldSid, newSid);
                                if (newStr != arr[i]) { arr[i] = newStr; changed = true; }
                            }
                        }
                        if (changed) { rootKey.SetValue(valueName, arr, kind); count++; }
                    }
                }
            }

            // Recurse into subkeys
            foreach (string subkeyName in rootKey.GetSubKeyNames())
            {
                try
                {
                    using var sub = rootKey.OpenSubKey(subkeyName, true);
                    if (sub != null)
                        count += ReplaceUserHiveSidStrings(sub, oldSid, newSid);
                }
                catch { /* access denied for some keys - skip */ }
            }
        }
        catch { }
        return count;
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// <summary>
    /// Replaces oldSid with newSid in str. Checks that the character after the
    /// match is not a digit (prevents partial sub-authority matches).
    /// </summary>
    private static string ReplaceSidInString(string str, string oldSid, string newSid)
    {
        int idx = 0;
        while (true)
        {
            int pos = str.IndexOf(oldSid, idx, StringComparison.OrdinalIgnoreCase);
            if (pos < 0) break;
            int afterPos = pos + oldSid.Length;
            // If next char is a digit, skip this match (partial sub-authority match guard)
            if (afterPos < str.Length && char.IsDigit(str[afterPos]))
            {
                idx = pos + 1;
                continue;
            }
            str = str.Substring(0, pos) + newSid + str.Substring(afterPos);
            idx = pos + newSid.Length;
        }
        return str;
    }

    /// <summary>
    /// Creates an OBJECT_ATTRIBUTES structure for NtOpenKey calls.
    /// Allocates unmanaged memory for the UNICODE_STRING and string buffer.
    /// Caller must free usMem and strBuf via Marshal.FreeHGlobal.
    /// </summary>
    private static (OBJECT_ATTRIBUTES oa, IntPtr usMem, IntPtr strBuf) MakeOA(string ntPath, uint attrs)
    {
        int byteLen = ntPath.Length * 2;
        IntPtr strBuf = Marshal.AllocHGlobal(byteLen);
        for (int i = 0; i < ntPath.Length; i++)
            Marshal.WriteInt16(strBuf, i * 2, (short)ntPath[i]);
        var us = new UNICODE_STRING { Length = (ushort)byteLen, MaximumLength = (ushort)byteLen, Buffer = strBuf };
        IntPtr usMem = Marshal.AllocHGlobal(Marshal.SizeOf<UNICODE_STRING>());
        Marshal.StructureToPtr(us, usMem, false);
        var oa = new OBJECT_ATTRIBUTES
        {
            Length = Marshal.SizeOf<OBJECT_ATTRIBUTES>(),
            ObjectName = usMem,
            Attributes = attrs,
        };
        return (oa, usMem, strBuf);
    }
}
