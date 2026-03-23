using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace EASYSID;

internal static class SidReadService
{
    /// <summary>
    /// Reads the current machine SID using multiple fallback methods:
    ///   1. LSA policy (authoritative)
    ///   2. SAM hive V value
    ///   3. Local user account SID derivation
    /// </summary>
    public static string GetCurrentMachineSid()
    {
        // Primary: LsaQueryInformationPolicy(PolicyAccountDomainInformation)
        // This is exactly what Get-Sid -Machine uses - the authoritative source.
        string sidFromLsa = TryReadSidFromLsa();
        if (sidFromLsa != null)
        {
            Console.WriteLine($"  [SID source] LSA policy: {sidFromLsa}");
            return sidFromLsa;
        }
        Console.WriteLine("  [SID source] LSA failed, trying SAM hive...");

        // Fallback 1: SAM hive V value
        string sidFromSam = TryReadSamWithAclGrant();
        if (sidFromSam != null)
        {
            Console.WriteLine($"  [SID source] SAM hive: {sidFromSam}");
            return sidFromSam;
        }
        Console.WriteLine("  [SID source] SAM hive failed, trying local users...");

        // Fallback 2: enumerate local user accounts and strip the RID
        string sidFromUsers = TryGetSidFromLocalUsers();
        if (sidFromUsers != null)
        {
            Console.WriteLine($"  [SID source] Local user accounts: {sidFromUsers}");
            return sidFromUsers;
        }

        Console.WriteLine("  [SID source] All methods failed!");
        return null;
    }

    private static string TryReadSidFromLsa()
    {
        try
        {
            const uint POLICY_VIEW_LOCAL_INFORMATION = 0x00000001;
            const int  PolicyAccountDomainInformation = 5;

            var oa = new LSA_OBJECT_ATTRIBUTES { Length = (uint)Marshal.SizeOf<LSA_OBJECT_ATTRIBUTES>() };
            uint status = NativeImports.LsaOpenPolicy(IntPtr.Zero, ref oa, POLICY_VIEW_LOCAL_INFORMATION, out IntPtr hPolicy);
            if (status != 0)
            {
                Console.WriteLine($"  LsaOpenPolicy failed: 0x{status:X8}");
                return null;
            }

            try
            {
                status = NativeImports.LsaQueryInformationPolicy(hPolicy, PolicyAccountDomainInformation, out IntPtr buf);
                if (status != 0)
                {
                    Console.WriteLine($"  LsaQueryInformationPolicy failed: 0x{status:X8}");
                    return null;
                }

                try
                {
                    var info = Marshal.PtrToStructure<LSA_ACCOUNT_DOMAIN_INFO>(buf);
                    if (info.Sid == IntPtr.Zero) return null;
                    NativeImports.ConvertSidToStringSid(info.Sid, out string sidStr);
                    return sidStr;
                }
                finally { NativeImports.LsaFreeMemory(buf); }
            }
            finally { NativeImports.LsaClose(hPolicy); }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  TryReadSidFromLsa exception: {ex.Message}");
            return null;
        }
    }

    private static string TryReadSamWithAclGrant()
    {
        string result = null;
        Console.WriteLine("  SAM: opening HKLM\\SAM\\SAM\\Domains\\Account...");
        RegistryHelper.WithProtectedKeyAccess(@"SAM\SAM\Domains\Account", needWrite: false, key =>
        {
            byte[] v = key.GetValue("V") as byte[];
            Console.WriteLine($"  SAM: V value length = {v?.Length ?? 0} bytes");
            if (v != null && v.Length >= 0x54)
            {
                uint sa1 = BitConverter.ToUInt32(v, 0x48);
                uint sa2 = BitConverter.ToUInt32(v, 0x4C);
                uint sa3 = BitConverter.ToUInt32(v, 0x50);
                result = $"S-1-5-21-{sa1}-{sa2}-{sa3}";
                Console.WriteLine($"  SAM: parsed SID at offsets 0x48/0x4C/0x50: {result}");
            }
            else
            {
                Console.WriteLine("  SAM: V value missing or too small (<0x54 bytes).");
            }
        });
        return result;
    }

    /// <summary>
    /// Enumerates HKLM\SAM\SAM\Domains\Account\Users\Names and gets one SID,
    /// or falls back to WMI Win32_UserAccount to get a local account SID and strips the RID.
    /// </summary>
    private static string TryGetSidFromLocalUsers()
    {
        // Try WMI: SELECT SID FROM Win32_UserAccount WHERE LocalAccount=True
        Console.WriteLine("  LocalUsers: querying WMI Win32_UserAccount...");
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                "SELECT SID FROM Win32_UserAccount WHERE LocalAccount=True");
            int found = 0;
            foreach (System.Management.ManagementObject obj in searcher.Get())
            {
                string sid = obj["SID"]?.ToString();
                found++;
                Console.WriteLine($"  LocalUsers: WMI account SID={sid}");
                if (!string.IsNullOrEmpty(sid) && sid.StartsWith("S-1-5-21-"))
                {
                    int lastDash = sid.LastIndexOf('-');
                    if (lastDash > 0)
                    {
                        string machineSid = sid.Substring(0, lastDash);
                        Console.WriteLine($"  LocalUsers: machine SID derived = {machineSid}");
                        return machineSid;
                    }
                }
            }
            Console.WriteLine($"  LocalUsers: WMI returned {found} account(s), none matched S-1-5-21-.");
        }
        catch (Exception ex) { Console.WriteLine($"  LocalUsers: WMI query failed: {ex.Message}"); }

        // Last try: current user token SID
        Console.WriteLine("  LocalUsers: trying current token identity...");
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            string sid = identity.User?.Value;
            Console.WriteLine($"  LocalUsers: current token SID = {sid}");
            if (!string.IsNullOrEmpty(sid) && sid.StartsWith("S-1-5-21-"))
            {
                int lastDash = sid.LastIndexOf('-');
                if (lastDash > 0)
                {
                    string machineSid = sid.Substring(0, lastDash);
                    Console.WriteLine($"  LocalUsers: machine SID derived = {machineSid}");
                    return machineSid;
                }
            }
        }
        catch (Exception ex) { Console.WriteLine($"  LocalUsers: token identity failed: {ex.Message}"); }

        Console.WriteLine("  LocalUsers: all fallbacks exhausted.");
        return null;
    }
}
