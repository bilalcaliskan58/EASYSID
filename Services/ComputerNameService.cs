using System;
using System.Security.Cryptography;
using Microsoft.Win32;

namespace EASYSID;

internal static class ComputerNameService
{
    internal static bool ChangeComputerName(string newName, string newDescription, string winDir)
    {
        if (string.IsNullOrEmpty(newName)) return true;
        if (!IsValidComputerName(newName, out char badChar))
        {
            Console.Error.WriteLine($"Specified computername contains invalid character {badChar}");
            return false;
        }

        Console.WriteLine($"[*] Changing computer name to: {newName}");
        bool ok = true;

        try
        {
            const string basePath = @"SYSTEM\CurrentControlSet\Control\ComputerName";
            string oldName = Environment.MachineName;
            Console.WriteLine($"  Current name: {oldName} -> new name: {newName}");

            using var key1 = RegistryHelper.OpenRegKey(RegistryHive.LocalMachine, basePath + @"\ComputerName", true);
            if (key1 != null) { key1.SetValue("ComputerName", newName, RegistryValueKind.String); Console.WriteLine("    ComputerName\\ComputerName: set."); }
            else Console.WriteLine("    ComputerName\\ComputerName key: not found.");

            using var key2 = RegistryHelper.OpenRegKey(RegistryHive.LocalMachine, basePath + @"\ActiveComputerName", true);
            if (key2 != null) { key2.SetValue("ComputerName", newName, RegistryValueKind.String); Console.WriteLine("    ActiveComputerName\\ComputerName: set."); }
            else Console.WriteLine("    ActiveComputerName\\ComputerName key: not found.");

            using var tcpip = RegistryHelper.OpenRegKey(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", true);
            if (tcpip != null)
            {
                tcpip.SetValue("Hostname",    newName, RegistryValueKind.String);
                tcpip.SetValue("NV Hostname", newName, RegistryValueKind.String);
                Console.WriteLine("    Tcpip\\Parameters Hostname + NV Hostname: set.");
            }
            else Console.WriteLine("    Tcpip\\Parameters key: not found.");

            using var lanman = RegistryHelper.OpenRegKey(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", true);
            if (lanman != null)
            {
                lanman.SetValue("Srvcomment", newDescription ?? string.Empty, RegistryValueKind.String);
                Console.WriteLine($"    LanmanServer Srvcomment: set to '{newDescription ?? ""}'.");
            }
            else Console.WriteLine("    LanmanServer\\Parameters key: not found.");

            Console.WriteLine("  Computer name updated in registry.");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"  Computer name change failed: {ex.Message}");
            ok = false;
        }

        return ok;
    }

    private static bool IsValidComputerName(string name, out char badChar)
    {
        badChar = '\0';
        if (name.Length > 15) { badChar = name[15]; return false; }
        foreach (char c in name)
        {
            if (!char.IsLetterOrDigit(c) && c != '-')
            {
                badChar = c;
                return false;
            }
        }
        return true;
    }

    /// <summary>
    /// Resolves the new computer name based on the option string:
    ///   null or empty -> keep current (return null)
    ///   "?"           -> random name: PC-XXXXXX (6 random alphanumeric chars)
    ///   other         -> use as-is
    /// </summary>
    internal static string ResolveNewComputerName(string option, string currentName)
    {
        if (string.IsNullOrEmpty(option)) return null;
        if (option == "?")
        {
            using var rng = RandomNumberGenerator.Create();
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            byte[] buf = new byte[6];
            rng.GetBytes(buf);
            var name = new char[6];
            for (int i = 0; i < 6; i++)
                name[i] = chars[buf[i] % chars.Length];
            return "PC-" + new string(name);
        }
        return option;
    }
}
