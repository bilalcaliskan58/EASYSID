using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

namespace EASYSID;

internal static class SidChangeService
{
    internal static bool ChangeSidInRegistry(string oldSid, string newSid, string winDir)
    {
        bool ok = true;
        Console.WriteLine($"[*] Updating SID in registry: {oldSid} -> {newSid}");

        // Parse old and new SID sub-authorities
        uint[] oldSa = SidOperations.ParseSidSubAuthorities(oldSid);
        uint[] newSa = SidOperations.ParseSidSubAuthorities(newSid);
        if (oldSa == null || newSa == null)
        {
            Console.Error.WriteLine("Invalid SID format.");
            return false;
        }

        // 0. Backup WinLogon settings before any changes
        Console.WriteLine("[*] Backing up WinLogon settings...");
        WinLogonService.BackupWinLogonSettings();

        // 1. Unload all non-temp user hives (FAH function from RE)
        Console.WriteLine("[*] Unloading user hives (FAH)...");
        HiveManagementService.UnloadUserHives();

        // 2. Patch SAM hive - Domains\Account V value (sub-authorities at 0x48/0x4C/0x50)
        bool samOk = PatchSamHive(oldSa, newSa, winDir);
        Console.WriteLine($"  >> PatchSamHive: {(samOk ? "OK" : "FAILED")}");
        ok = samOk && ok;

        // 2b. Patch SAM group memberships and user accounts (Builtin\Aliases, Account\Users, Account\Aliases)
        bool samGroupsOk = PatchSamGroupMemberships(oldSa, newSa);
        Console.WriteLine($"  >> PatchSamGroupMemberships: {(samGroupsOk ? "OK" : "FAILED")}");
        ok = samGroupsOk && ok;

        // 3. Patch SECURITY hive - AccountDomainInfo
        bool secOk = PatchSecurityHive(newSa, winDir);
        Console.WriteLine($"  >> PatchSecurityHive: {(secOk ? "OK" : "FAILED")}");
        ok = secOk && ok;

        // 4. Remap ProfileList entries (rename old SID subkeys to new SID)
        bool profOk = ProfileMigrationService.RemapProfileList(oldSid, newSid);
        Console.WriteLine($"  >> RemapProfileList: {(profOk ? "OK" : "FAILED")}");
        ok = profOk && ok;

        // 4b. Patch registry key security descriptors in all hives
        // (Critical: without this, NTUSER.DAT registry keys still have the old SID
        //  in their OWNER/DACL, causing profile load failure -> login screen loop)
        // Collect ALL profile paths that actually exist on disk
        var profilePaths = new List<string>();
        try
        {
            using var pl = RegistryHelper.OpenRegKey(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
            if (pl != null)
            {
                foreach (string sk in pl.GetSubKeyNames())
                {
                    if (!sk.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase))
                        continue;
                    using var sub = pl.OpenSubKey(sk);
                    string pip = sub?.GetValue("ProfileImagePath") as string;
                    if (pip == null) continue;
                    string resolved = Environment.ExpandEnvironmentVariables(pip);
                    if (Directory.Exists(resolved))
                        profilePaths.Add(resolved);
                    else
                        Console.WriteLine($"  Profile '{resolved}' directory missing - SD patching skipped for this profile.");
                }
            }
        }
        catch { }

        if (profilePaths.Count == 0)
            Console.WriteLine("  WARNING: No valid profile paths found for user hive SD patching!");

        // Patch system hive SDs once, then each user profile's hive SDs
        foreach (string profilePath in profilePaths)
        {
            Console.WriteLine($"  Patching SDs for profile: {Path.GetFileName(profilePath)}");
            SecurityDescriptorService.PatchAllHiveKeySecurityDescriptors(oldSa, newSa, profilePath);
        }
        if (profilePaths.Count == 0)
            SecurityDescriptorService.PatchAllHiveKeySecurityDescriptors(oldSa, newSa, null);

        // 3b. Remap SECURITY\Policy\Accounts  -  User Rights Assignments (LSA API)
        // Without this, new-SID accounts get no logon rights  ->  0xC000015B / EventID 4625
        bool lsaAcctsOk = LsaAccountService.RemapSecurityPolicyAccounts(oldSid, newSid);
        Console.WriteLine($"  >> RemapSecurityPolicyAccounts: {(lsaAcctsOk ? "OK" : "FAILED")}");
        ok = lsaAcctsOk && ok;

        // 5. Scan HKLM\SOFTWARE for old SID strings and replace
        Console.WriteLine("[*] Scanning HKLM\\SOFTWARE for old SID references...");
        try
        {
            using var software = RegistryHelper.OpenRegKey(RegistryHive.LocalMachine, "SOFTWARE", true);
            if (software != null)
            {
                int replaced = RegistryHelper.ReplaceUserHiveSidStrings(software, oldSid, newSid);
                Console.WriteLine($"  >> HKLM\\SOFTWARE scan: replaced {replaced} SID reference(s).");
            }
            else
            {
                Console.WriteLine("  >> HKLM\\SOFTWARE: key not found.");
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"  >> HKLM\\SOFTWARE scan failed: {ex.Message}");
        }

        // 5b. Scan HKLM\SYSTEM for old SID strings and replace
        // Services\<name>\ObjectName may contain user SID logon accounts
        Console.WriteLine("[*] Scanning HKLM\\SYSTEM for old SID references...");
        try
        {
            using var system = RegistryHelper.OpenRegKey(RegistryHive.LocalMachine, "SYSTEM", true);
            if (system != null)
            {
                int replaced = RegistryHelper.ReplaceUserHiveSidStrings(system, oldSid, newSid);
                Console.WriteLine($"  >> HKLM\\SYSTEM scan: replaced {replaced} SID reference(s).");
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"  >> HKLM\\SYSTEM scan failed: {ex.Message}");
        }

        // 5c. Remap service logon SIDs (ObjectName in Services registry)
        ServiceLogonService.RemapServiceLogonSids(oldSid, newSid);

        // 5d. Remap SID references in Scheduled Task XML files
        ServiceLogonService.RemapScheduledTaskSids(oldSid, newSid, winDir);

        // 5e. Clear stale LSA secrets tied to old machine SID
        LsaAccountService.ClearStaleLsaSecrets(oldSid);

        // 6. Clean up AppxAllUserStore keys with old SID
        Console.WriteLine("[*] Cleaning up AppxAllUserStore...");
        AppxCleanupService.CleanupAppxAllUserStore();

        // 7. Restore WinLogon settings (autologon, DisableCAD, etc.  -  not the login notice)
        Console.WriteLine("[*] Restoring WinLogon settings...");
        WinLogonService.RestoreWinLogonSettings();

        Console.WriteLine($"[*] Registry SID update complete. Overall ok={ok}");
        return ok;
    }

    private static bool PatchSamHive(uint[] oldSa, uint[] newSa, string winDir)
    {
        Console.WriteLine("[*] Patching SAM hive...");
        bool patched = false;

        bool ok = RegistryHelper.WithProtectedKeyAccess(@"SAM\SAM\Domains\Account", needWrite: true, key =>
        {
            byte[] v = key.GetValue("V") as byte[];
            if (v == null || v.Length < 0x54)
            {
                Console.Error.WriteLine($"  SAM V value not found or too small (len={v?.Length ?? 0}).");
                return;
            }

            // Dump full V value for offset analysis
            var sb = new System.Text.StringBuilder($"  V[full {v.Length} bytes]: ");
            for (int i = 0; i < v.Length; i++) sb.Append($"{v[i]:X2} ");
            Console.WriteLine(sb.ToString());

            // Search for oldSa[0] bytes in V value to find real offset
            byte[] sa0bytes = BitConverter.GetBytes(oldSa[0]);
            int foundOffset = -1;
            for (int i = 0; i <= v.Length - 12; i++)
            {
                if (v[i]   == sa0bytes[0] && v[i+1] == sa0bytes[1] &&
                    v[i+2] == sa0bytes[2] && v[i+3] == sa0bytes[3])
                {
                    // Verify sa1 and sa2 also match
                    uint sa1check = BitConverter.ToUInt32(v, i + 4);
                    uint sa2check = BitConverter.ToUInt32(v, i + 8);
                    if (sa1check == oldSa[1] && sa2check == oldSa[2])
                    {
                        foundOffset = i;
                        break;
                    }
                }
            }

            Console.WriteLine($"  Old SA expected: {oldSa[0]}-{oldSa[1]}-{oldSa[2]}");
            Console.WriteLine($"  New SA to write: {newSa[0]}-{newSa[1]}-{newSa[2]}");

            if (foundOffset < 0)
            {
                Console.Error.WriteLine("  Could not find old SA in V value - SAM patch skipped.");
                return;
            }

            Console.WriteLine($"  Found SA at offset 0x{foundOffset:X2}, patching...");

            // Patch at discovered offset
            Buffer.BlockCopy(BitConverter.GetBytes(newSa[0]), 0, v, foundOffset,     4);
            Buffer.BlockCopy(BitConverter.GetBytes(newSa[1]), 0, v, foundOffset + 4, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(newSa[2]), 0, v, foundOffset + 8, 4);

            key.SetValue("V", v, RegistryValueKind.Binary);
            Console.WriteLine("  SAM hive patched.");
            patched = true;
        });

        if (!ok || !patched) Console.Error.WriteLine("  SAM hive patch failed.");
        return ok && patched;
    }

    private static bool PatchSamGroupMemberships(uint[] oldSa, uint[] newSa)
    {
        Console.WriteLine("[*] Patching SAM group memberships and user accounts...");
        int totalPatched = 0;

        // 1. Patch Builtin\Aliases  -  group member SIDs (Administrators=0x220, Users=0x221, etc.)
        Console.WriteLine("  [Builtin\\Aliases] Patching group membership C values...");
        int builtinCount = PatchSamBinaryValues(@"SAM\SAM\Domains\Builtin\Aliases", oldSa, newSa, "C");
        Console.WriteLine($"  [Builtin\\Aliases] {builtinCount} value(s) patched.");
        totalPatched += builtinCount;

        // 2. Patch Account\Users  -  individual user V values (contain SID references)
        Console.WriteLine("  [Account\\Users] Patching user account V values...");
        int usersCount = PatchSamBinaryValues(@"SAM\SAM\Domains\Account\Users", oldSa, newSa, "V");
        Console.WriteLine($"  [Account\\Users] {usersCount} value(s) patched.");
        totalPatched += usersCount;

        // 3. Patch Account\Aliases  -  domain-local group membership C values
        Console.WriteLine("  [Account\\Aliases] Patching domain alias C values...");
        int aliasCount = PatchSamBinaryValues(@"SAM\SAM\Domains\Account\Aliases", oldSa, newSa, "C");
        Console.WriteLine($"  [Account\\Aliases] {aliasCount} value(s) patched.");
        totalPatched += aliasCount;

        Console.WriteLine($"  SAM membership patch total: {totalPatched} value(s) updated.");
        return true;
    }

    private static int PatchSamBinaryValues(string basePath, uint[] oldSa, uint[] newSa, string valueName)
    {
        int patchedCount = 0;

        bool ok = RegistryHelper.WithProtectedKeyAccess(basePath, needWrite: true, baseKey =>
        {
            string[] subkeys;
            try { subkeys = baseKey.GetSubKeyNames(); }
            catch (Exception ex)
            {
                Console.WriteLine($"    Cannot enumerate '{basePath}': {ex.Message}");
                return;
            }

            // Build the 12-byte old pattern and new pattern (3 x uint32 LE)
            byte[] oldPattern = new byte[12];
            byte[] newPattern = new byte[12];
            Buffer.BlockCopy(BitConverter.GetBytes(oldSa[0]), 0, oldPattern, 0, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(oldSa[1]), 0, oldPattern, 4, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(oldSa[2]), 0, oldPattern, 8, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(newSa[0]), 0, newPattern, 0, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(newSa[1]), 0, newPattern, 4, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(newSa[2]), 0, newPattern, 8, 4);

            foreach (string sk in subkeys)
            {
                // Skip "Names" subkey (it's a name -> RID mapping, not binary SID data)
                if (string.Equals(sk, "Names", StringComparison.OrdinalIgnoreCase))
                    continue;

                try
                {
                    using var sub = baseKey.OpenSubKey(sk, writable: true);
                    if (sub == null) continue;

                    byte[] data = sub.GetValue(valueName) as byte[];
                    if (data == null || data.Length < 12) continue;

                    // Search and replace all occurrences of oldPattern with newPattern
                    int replacements = 0;
                    for (int i = 0; i <= data.Length - 12; i++)
                    {
                        bool match = true;
                        for (int j = 0; j < 12; j++)
                        {
                            if (data[i + j] != oldPattern[j]) { match = false; break; }
                        }
                        if (match)
                        {
                            Buffer.BlockCopy(newPattern, 0, data, i, 12);
                            replacements++;
                            i += 11; // skip past this match
                        }
                    }

                    if (replacements > 0)
                    {
                        sub.SetValue(valueName, data, RegistryValueKind.Binary);
                        Console.WriteLine($"    {basePath}\\{sk}\\{valueName}: {replacements} SID occurrence(s) replaced.");
                        patchedCount++;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"    {basePath}\\{sk}: {ex.Message}");
                }
            }
        });

        if (!ok)
            Console.WriteLine($"    Could not access '{basePath}'  -  skipped.");

        return patchedCount;
    }

    private static bool PatchSecurityHive(uint[] newSa, string winDir)
    {
        Console.WriteLine("[*] Patching SECURITY hive via LsaSetInformationPolicy...");
        IntPtr nameBuf   = IntPtr.Zero;
        IntPtr newSidPtr = IntPtr.Zero;
        IntPtr infoPtr   = IntPtr.Zero;
        try
        {
            const uint POLICY_VIEW_LOCAL_INFORMATION  = 0x00000001;
            const uint POLICY_TRUST_ADMIN             = 0x00000008;
            const uint POLICY_CREATE_SECRET           = 0x00000020;
            const int  PolicyAccountDomainInformation = 5;

            var oa = new LSA_OBJECT_ATTRIBUTES { Length = (uint)Marshal.SizeOf<LSA_OBJECT_ATTRIBUTES>() };
            uint status = NativeImports.LsaOpenPolicy(IntPtr.Zero, ref oa,
                POLICY_VIEW_LOCAL_INFORMATION | POLICY_TRUST_ADMIN | POLICY_CREATE_SECRET,
                out IntPtr hPolicy);
            if (status != 0)
            {
                Console.Error.WriteLine($"  LsaOpenPolicy failed: 0x{status:X8}");
                return false;
            }

            try
            {
                // Read current domain info to preserve the domain name
                status = NativeImports.LsaQueryInformationPolicy(hPolicy, PolicyAccountDomainInformation, out IntPtr buf);
                if (status != 0)
                {
                    Console.Error.WriteLine($"  LsaQueryInformationPolicy failed: 0x{status:X8}");
                    return false;
                }

                var info = Marshal.PtrToStructure<LSA_ACCOUNT_DOMAIN_INFO>(buf);

                // CRITICAL: Copy DomainName.Buffer contents to our own memory BEFORE
                // calling LsaFreeMemory, because LsaFreeMemory invalidates info.DomainName.Buffer.
                ushort nameLen    = info.DomainName.Length;
                ushort nameMaxLen = info.DomainName.MaximumLength;
                byte[] nameBytes  = new byte[nameLen];
                string domainNameStr = "(empty)";

                if (nameLen > 0 && info.DomainName.Buffer != IntPtr.Zero)
                {
                    Marshal.Copy(info.DomainName.Buffer, nameBytes, 0, nameLen);
                    domainNameStr = Encoding.Unicode.GetString(nameBytes, 0, nameLen);
                }
                Console.WriteLine($"  Current domain name: '{domainNameStr}' (len={nameLen})");

                // Log current SID before freeing
                if (info.Sid != IntPtr.Zero)
                {
                    NativeImports.ConvertSidToStringSid(info.Sid, out string oldSidStr);
                    Console.WriteLine($"  Current LSA SID: {oldSidStr}");
                }

                NativeImports.LsaFreeMemory(buf); // NOW safe  -  we copied what we need

                // Allocate our own copy of the domain name buffer
                int nameBufSize = nameMaxLen > 0 ? nameMaxLen : 2;
                nameBuf = Marshal.AllocHGlobal(nameBufSize);
                if (nameBytes.Length > 0)
                    Marshal.Copy(nameBytes, 0, nameBuf, nameBytes.Length);

                // Build new SID using ConvertStringSidToSid (validated by Windows)
                string newSidStr = $"S-1-5-21-{newSa[0]}-{newSa[1]}-{newSa[2]}";
                Console.WriteLine($"  New SID to set: {newSidStr}");
                if (!NativeImports.ConvertStringSidToSid(newSidStr, out newSidPtr))
                {
                    int err = Marshal.GetLastWin32Error();
                    Console.Error.WriteLine($"  ConvertStringSidToSid failed: Win32 error {err}");
                    return false;
                }

                // Build new LSA_ACCOUNT_DOMAIN_INFO with our copied name + new SID
                var newInfo = new LSA_ACCOUNT_DOMAIN_INFO
                {
                    DomainName = new LSA_UNICODE_STRING
                    {
                        Length         = nameLen,
                        MaximumLength  = nameMaxLen,
                        Buffer         = nameBuf
                    },
                    Sid = newSidPtr
                };

                infoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<LSA_ACCOUNT_DOMAIN_INFO>());
                Marshal.StructureToPtr(newInfo, infoPtr, false);

                status = NativeImports.LsaSetInformationPolicy(hPolicy, PolicyAccountDomainInformation, infoPtr);
                if (status != 0)
                {
                    Console.Error.WriteLine($"  LsaSetInformationPolicy failed: 0x{status:X8}");
                    return false;
                }

                Console.WriteLine($"  SECURITY hive patched via LSA. New SID: {newSidStr}");
                return true;
            }
            finally { NativeImports.LsaClose(hPolicy); }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"  PatchSecurityHive exception: {ex.Message}");
            return false;
        }
        finally
        {
            if (nameBuf   != IntPtr.Zero) Marshal.FreeHGlobal(nameBuf);
            if (newSidPtr != IntPtr.Zero) NativeImports.LocalFree(newSidPtr);
            if (infoPtr   != IntPtr.Zero) Marshal.FreeHGlobal(infoPtr);
        }
    }
}
