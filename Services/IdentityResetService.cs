using System;
using Microsoft.Win32;

namespace EASYSID;

internal static class IdentityResetService
{
    /// <summary>
    /// Generates a new random GUID and writes it to:
    ///   HKLM\SOFTWARE\Microsoft\Cryptography -> MachineGuid
    /// </summary>
    internal static bool ResetMachineGuid(string winDir)
    {
        Console.WriteLine("[*] Resetting MachineGuid...");
        try
        {
            using var key = RegistryHelper.OpenRegKey(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Cryptography", true);
            if (key == null) { Console.WriteLine("  MachineGuid key not found, skipping."); return true; }

            string oldGuid = key.GetValue("MachineGuid") as string ?? "(not set)";
            string newGuid = Guid.NewGuid().ToString();
            key.SetValue("MachineGuid", newGuid, RegistryValueKind.String);
            // Verify write
            string verify = key.GetValue("MachineGuid") as string;
            Console.WriteLine($"  MachineGuid: {oldGuid} -> {newGuid} (verify={verify})");
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"  MachineGuid reset failed: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Generates a new random Machine ID and writes it to:
    ///   HKLM\SOFTWARE\Microsoft\SQMClient -> MachineId
    ///   Format: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
    /// </summary>
    internal static bool ResetMachineId(string winDir)
    {
        Console.WriteLine("[*] Resetting Machine ID...");
        try
        {
            using var key = RegistryHelper.OpenRegKey(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\SQMClient", true);
            if (key == null) { Console.WriteLine("  SQMClient key not found, skipping."); return true; }

            string oldId = key.GetValue("MachineId") as string ?? "(not set)";
            string newId = "{" + Guid.NewGuid().ToString().ToUpper() + "}";
            key.SetValue("MachineId", newId, RegistryValueKind.String);
            Console.WriteLine($"  MachineId: {oldId} -> {newId}");
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"  Machine ID reset failed: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Resets the WSUS client ID by deleting SusClientId and SusClientIdValidation from:
    ///   HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate
    /// A new ID is generated on next Windows Update check.
    /// </summary>
    internal static bool ResetWsusId(string winDir)
    {
        Console.WriteLine("[*] Resetting WSUS ID...");
        try
        {
            using var key = RegistryHelper.OpenRegKey(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate", true);
            if (key == null) { Console.WriteLine("  WindowsUpdate key not found, skipping."); return true; }

            string oldId   = key.GetValue("SusClientId") as string ?? "(not set)";
            string oldVald = key.GetValue("SusClientIdValidation") as string ?? "(not set)";
            key.DeleteValue("SusClientId", false);
            key.DeleteValue("SusClientIdValidation", false);
            Console.WriteLine($"  SusClientId deleted (was: {oldId}).");
            Console.WriteLine($"  SusClientIdValidation deleted (was: {oldVald}).");
            Console.WriteLine("  WSUS ID removed (will be regenerated on next update check).");
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"  WSUS ID reset failed: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Resets the MSDTC Client ID by deleting CIDField from:
    ///   HKLM\SOFTWARE\Microsoft\MSDTC
    /// </summary>
    internal static bool ResetMsdtcCid(string winDir)
    {
        Console.WriteLine("[*] Resetting MSDTC CID...");
        try
        {
            using var key = RegistryHelper.OpenRegKey(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\MSDTC", true);
            if (key == null) { Console.WriteLine("  MSDTC key not found, skipping."); return true; }

            object oldCid = key.GetValue("CIDField");
            string oldCidStr = oldCid != null ? BitConverter.ToString((byte[])oldCid) : "(not set)";
            key.DeleteValue("CIDField", false);
            Console.WriteLine($"  MSDTC CIDField deleted (was: {oldCidStr}).");
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"  MSDTC CID reset failed: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Resets the Device Identifier used by modern apps:
    ///   HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion -> DeviceId
    /// </summary>
    internal static bool ResetDeviceId(string winDir)
    {
        Console.WriteLine("[*] Resetting Device ID...");
        bool ok = true;
        try
        {
            using var key = RegistryHelper.OpenRegKey(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", true);
            if (key != null)
            {
                string oldId = key.GetValue("DeviceId") as string ?? "(not set)";
                key.DeleteValue("DeviceId", false);
                Console.WriteLine($"  DeviceId deleted (was: {oldId}). Will regenerate on next boot.");
            }
            else Console.WriteLine("  Windows NT\\CurrentVersion key not found, skipping.");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"  Device ID reset failed: {ex.Message}");
            ok = false;
        }
        return ok;
    }

    /// <summary>
    /// Resets the DHCPv6 DUID at:
    ///   HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters -> Dhcpv6DUID
    ///   HKLM\SYSTEM\CurrentControlSet\Services\Dhcp\Parameters -> DhcpClientIdentifier
    /// </summary>
    internal static bool ResetDhcpDuid(string winDir)
    {
        Console.WriteLine("[*] Resetting DHCPv6 DUID...");
        bool ok = true;
        try
        {
            using var key = RegistryHelper.OpenRegKey(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters", true);
            if (key != null)
            {
                object oldDuid = key.GetValue("Dhcpv6DUID");
                string oldDuidStr = oldDuid is byte[] b ? BitConverter.ToString(b) : (oldDuid?.ToString() ?? "(not set)");
                key.DeleteValue("Dhcpv6DUID", false);
                Console.WriteLine($"  Tcpip6 Dhcpv6DUID deleted (was: {oldDuidStr}).");
            }
            else Console.WriteLine("  Tcpip6\\Parameters key not found, skipping.");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"  DHCPv6 DUID (Tcpip6) reset failed: {ex.Message}");
            ok = false;
        }
        try
        {
            using var key = RegistryHelper.OpenRegKey(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\Dhcp\Parameters", true);
            if (key != null)
            {
                object oldCid = key.GetValue("DhcpClientIdentifier");
                string oldCidStr = oldCid is byte[] b ? BitConverter.ToString(b) : (oldCid?.ToString() ?? "(not set)");
                key.DeleteValue("DhcpClientIdentifier", false);
                Console.WriteLine($"  Dhcp DhcpClientIdentifier deleted (was: {oldCidStr}).");
            }
            else Console.WriteLine("  Dhcp\\Parameters key not found, skipping.");
        }
        catch (Exception ex) { Console.WriteLine($"  Dhcp DhcpClientIdentifier reset skipped: {ex.Message}"); }

        Console.WriteLine("  DUID cleared (will regenerate on next network start).");
        return ok;
    }
}
