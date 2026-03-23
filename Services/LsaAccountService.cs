using System;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace EASYSID;

/// <summary>
/// Handles remapping LSA Policy accounts (User Rights Assignments) and
/// clearing stale LSA secrets after SID change.
/// </summary>
internal static class LsaAccountService
{
    /// <summary>
    /// Enumerates all LSA Policy accounts and migrates user rights from
    /// accounts with the old SID to corresponding accounts with the new SID.
    /// </summary>
    internal static bool RemapSecurityPolicyAccounts(string oldSid, string newSid)
    {
        Console.WriteLine("[*] Remapping LSA Policy\\Accounts (User Rights Assignments)...");
        int migrated = 0, skipped = 0, failed = 0;

        const uint POLICY_VIEW_LOCAL_INFORMATION = 0x00000001;
        const uint POLICY_LOOKUP_NAMES           = 0x00000800;
        const uint POLICY_CREATE_ACCOUNT         = 0x00000010;
        const uint STATUS_NO_MORE_ENTRIES        = 0x8000001A;
        const uint STATUS_OBJECT_NAME_NOT_FOUND  = 0xC0000034;

        var oa = new LSA_OBJECT_ATTRIBUTES { Length = (uint)Marshal.SizeOf<LSA_OBJECT_ATTRIBUTES>() };
        uint status = NativeImports.LsaOpenPolicy(IntPtr.Zero, ref oa,
            POLICY_VIEW_LOCAL_INFORMATION | POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT,
            out IntPtr hPolicy);
        if (status != 0)
        {
            Console.WriteLine($"  LsaOpenPolicy failed: 0x{status:X8}");
            return false;
        }

        try
        {
            IntPtr enumCtx = IntPtr.Zero;
            status = NativeImports.LsaEnumerateAccounts(hPolicy, ref enumCtx, out IntPtr buffer, 0x10000, out uint count);
            if (status != 0 && status != STATUS_NO_MORE_ENTRIES)
            {
                Console.WriteLine($"  LsaEnumerateAccounts failed: 0x{status:X8}");
                return false;
            }

            Console.WriteLine($"  LSA accounts enumerated: {count}");

            for (uint i = 0; i < count; i++)
            {
                IntPtr sidPtr = Marshal.ReadIntPtr(buffer, (int)(i * IntPtr.Size));
                if (sidPtr == IntPtr.Zero) continue;

                NativeImports.ConvertSidToStringSid(sidPtr, out string accountSid);
                if (accountSid == null) continue;

                Console.WriteLine($"    Account: {accountSid}");

                if (!accountSid.StartsWith(oldSid, StringComparison.OrdinalIgnoreCase))
                    continue;

                string suffix    = accountSid.Substring(oldSid.Length);
                string newSidStr = newSid + suffix;
                Console.WriteLine($"    Migrating rights: {accountSid} -> {newSidStr}");

                // Get rights of old account
                uint st2 = NativeImports.LsaEnumerateAccountRights(hPolicy, sidPtr, out IntPtr rightsPtr, out uint rightsCount);
                if (st2 == STATUS_OBJECT_NAME_NOT_FOUND || rightsCount == 0)
                {
                    Console.WriteLine($"    No rights on {accountSid}, skipping.");
                    skipped++;
                    continue;
                }
                if (st2 != 0)
                {
                    Console.WriteLine($"    LsaEnumerateAccountRights failed: 0x{st2:X8}");
                    failed++;
                    continue;
                }

                // Copy rights array
                var rights = new LSA_UNICODE_STRING[rightsCount];
                for (uint r = 0; r < rightsCount; r++)
                {
                    rights[r] = Marshal.PtrToStructure<LSA_UNICODE_STRING>(
                        rightsPtr + (int)(r * Marshal.SizeOf<LSA_UNICODE_STRING>()));
                    Console.WriteLine($"      Right: {Marshal.PtrToStringUni(rights[r].Buffer, rights[r].Length / 2)}");
                }
                NativeImports.LsaFreeMemory(rightsPtr);

                // Get binary form of new SID
                if (!NativeImports.ConvertStringSidToSid(newSidStr, out IntPtr newSidBin))
                {
                    Console.WriteLine($"    ConvertStringSidToSid failed for {newSidStr}");
                    failed++;
                    continue;
                }

                try
                {
                    uint st3 = NativeImports.LsaAddAccountRights(hPolicy, newSidBin, rights, rightsCount);
                    if (st3 != 0)
                    {
                        Console.WriteLine($"    LsaAddAccountRights failed: 0x{st3:X8}");
                        failed++;
                        continue;
                    }

                    // Remove all rights from old account
                    uint st4 = NativeImports.LsaRemoveAccountRights(hPolicy, sidPtr, true, null, 0);
                    if (st4 != 0)
                        Console.WriteLine($"    LsaRemoveAccountRights (non-fatal): 0x{st4:X8}");

                    Console.WriteLine($"    Migrated {rightsCount} right(s) to {newSidStr}.");
                    migrated++;
                }
                finally { NativeImports.LocalFree(newSidBin); }
            }

            if (buffer != IntPtr.Zero) NativeImports.LsaFreeMemory(buffer);
        }
        finally { NativeImports.LsaClose(hPolicy); }

        Console.WriteLine($"  LSA Policy\\Accounts: {migrated} migrated, {skipped} skipped, {failed} failed.");
        return failed == 0;
    }

    /// <summary>
    /// Clears LSA secrets that are tied to the old machine SID.
    /// LSA secrets live in HKLM\SECURITY\Policy\Secrets and store encrypted
    /// credentials for services, cached logons, and auto-logon passwords.
    ///
    /// After a SID change the encryption keys change (they are derived from the
    /// machine SID / boot key), so stale secrets cause authentication failures.
    /// We delete secrets whose name contains the old SID or known stale prefixes.
    /// Safe to delete  -  Windows regenerates them on demand.
    /// </summary>
    internal static void ClearStaleLsaSecrets(string oldSid)
    {
        Console.WriteLine("[*] Clearing stale LSA secrets...");
        int cleared = 0, errors = 0;

        try
        {
            // LSA Secrets are under HKLM\SECURITY\Policy\Secrets
            // Each subkey is a secret name; the actual encrypted blob is in sub-values.
            // We need SE_SECURITY_NAME + SE_TAKE_OWNERSHIP_NAME to access this key.
            NativeImports.RtlAdjustPrivilege(8,  true, false, out _); // SeSecurityPrivilege
            NativeImports.RtlAdjustPrivilege(9,  true, false, out _); // SeTakeOwnershipPrivilege
            NativeImports.RtlAdjustPrivilege(17, true, false, out _); // SeBackupPrivilege
            NativeImports.RtlAdjustPrivilege(18, true, false, out _); // SeRestorePrivilege

            using var secrets = RegistryHelper.OpenRegKey(RegistryHive.LocalMachine, @"SECURITY\Policy\Secrets", true);
            if (secrets == null)
            {
                Console.WriteLine("  SECURITY\\Policy\\Secrets not accessible (normal if no domain).");
                return;
            }

            foreach (string secretName in secrets.GetSubKeyNames())
            {
                // Delete secrets tied to old SID or known machine-bound prefixes:
                //   _SC_<ServiceName>      -  service account passwords (regenerated by SCM)
                //   $MACHINE.ACC           -  machine account password (workgroup: not used)
                //   NL$KM                  -  netlogon session key (domain: regenerated)
                //   DPAPI_SYSTEM           -  DO NOT delete: protects DPAPI master keys,
                //                           deleting causes permanent loss of EFS/Credential data
                bool isStale =
                    secretName.Contains(oldSid, StringComparison.OrdinalIgnoreCase) ||
                    secretName.StartsWith("_SC_",        StringComparison.OrdinalIgnoreCase) ||
                    secretName.Equals("$MACHINE.ACC",    StringComparison.OrdinalIgnoreCase);

                // Explicitly preserve critical secrets that must NOT be deleted
                if (secretName.Equals("DPAPI_SYSTEM", StringComparison.OrdinalIgnoreCase) ||
                    secretName.Equals("DefaultPassword", StringComparison.OrdinalIgnoreCase))
                    continue;

                if (!isStale) continue;

                try
                {
                    secrets.DeleteSubKeyTree(secretName, false);
                    Console.WriteLine($"    Deleted LSA secret: {secretName}");
                    cleared++;
                }
                catch (Exception exDel)
                {
                    Console.WriteLine($"    Could not delete secret '{secretName}': {exDel.Message}");
                    errors++;
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  LSA secrets clear failed: {ex.Message}");
        }

        Console.WriteLine($"  LSA Secrets: {cleared} cleared, {errors} error(s).");
    }
}
