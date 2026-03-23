using System;
using System.IO;
using System.Text;
using Microsoft.Win32;

namespace EASYSID;

/// <summary>
/// Handles remapping SID references in Windows Services registry and
/// Scheduled Task XML definitions after SID change.
/// </summary>
internal static class ServiceLogonService
{
    /// <summary>
    /// Scans HKLM\SYSTEM\CurrentControlSet\Services and replaces old SID
    /// references in ObjectName (service logon account) and other string values.
    ///
    /// Services configured to run as a local user (e.g. .\username or the SID
    /// directly) need to be updated after a SID change or they fail to start.
    /// </summary>
    internal static void RemapServiceLogonSids(string oldSid, string newSid)
    {
        Console.WriteLine("[*] Remapping SID references in Services registry...");
        try
        {
            using var services = RegistryHelper.OpenRegKey(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services", true);
            if (services == null)
            {
                Console.WriteLine("  Services key not found.");
                return;
            }

            int replaced = RegistryHelper.ReplaceUserHiveSidStrings(services, oldSid, newSid);
            Console.WriteLine($"  Services: {replaced} SID reference(s) replaced.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  Services SID remap failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Scans all scheduled task XML files under %SystemRoot%\System32\Tasks
    /// and replaces old SID string references with the new SID.
    ///
    /// Task definitions store the author/RunAs SID in plain text inside the XML.
    /// Without this, tasks that run as a specific user SID fail after SID change.
    /// </summary>
    internal static void RemapScheduledTaskSids(string oldSid, string newSid, string winDir)
    {
        Console.WriteLine("[*] Remapping SID references in Scheduled Tasks XML...");
        string tasksDir = Path.Combine(winDir, @"System32\Tasks");
        if (!Directory.Exists(tasksDir))
        {
            Console.WriteLine($"  Tasks directory not found: {tasksDir}");
            return;
        }

        int patched = 0, scanned = 0, errors = 0;

        // Use safe recursive enumeration instead of Directory.EnumerateFiles with
        // SearchOption.AllDirectories. The latter throws and aborts the entire scan
        // if ANY subdirectory is inaccessible (OneDrive, third-party task folders).
        EnumerateTaskFiles(tasksDir, oldSid, newSid, ref patched, ref scanned, ref errors);

        Console.WriteLine($"  Scheduled Tasks: {scanned} scanned, {patched} patched, {errors} error(s).");
    }

    /// <summary>
    /// Safely enumerates task files recursively, skipping inaccessible directories
    /// (OneDrive, third-party task folders that may not exist or have restricted ACLs).
    /// Unlike Directory.EnumerateFiles with AllDirectories, this doesn't abort
    /// the entire scan when a single subdirectory is inaccessible.
    /// </summary>
    private static void EnumerateTaskFiles(string directory, string oldSid, string newSid,
                                            ref int patched, ref int scanned, ref int errors)
    {
        // Process files in this directory
        try
        {
            foreach (string file in Directory.GetFiles(directory))
            {
                scanned++;
                try
                {
                    byte[] rawBytes = File.ReadAllBytes(file);
                    if (rawBytes.Length < 10) continue;

                    Encoding fileEncoding;
                    if (rawBytes.Length >= 2 && rawBytes[0] == 0xFF && rawBytes[1] == 0xFE)
                        fileEncoding = Encoding.Unicode;
                    else if (rawBytes.Length >= 3 && rawBytes[0] == 0xEF && rawBytes[1] == 0xBB && rawBytes[2] == 0xBF)
                        fileEncoding = Encoding.UTF8;
                    else
                        fileEncoding = Encoding.UTF8;

                    string content = fileEncoding.GetString(rawBytes);
                    if (!content.Contains(oldSid, StringComparison.OrdinalIgnoreCase))
                        continue;

                    string newContent = content.Replace(oldSid, newSid, StringComparison.OrdinalIgnoreCase);
                    File.WriteAllText(file, newContent, fileEncoding);
                    Console.WriteLine($"    Patched task: {Path.GetFileName(file)}");
                    patched++;
                }
                catch (Exception exFile)
                {
                    Console.WriteLine($"    Skip '{Path.GetFileName(file)}': {exFile.Message}");
                    errors++;
                }
            }
        }
        catch (UnauthorizedAccessException)
        {
            Console.WriteLine($"    Skip directory (access denied): {Path.GetFileName(directory)}");
        }
        catch (DirectoryNotFoundException) { }
        catch (Exception ex)
        {
            Console.WriteLine($"    Skip directory '{Path.GetFileName(directory)}': {ex.Message}");
        }

        // Recurse into subdirectories independently
        try
        {
            foreach (string subDir in Directory.GetDirectories(directory))
                EnumerateTaskFiles(subDir, oldSid, newSid, ref patched, ref scanned, ref errors);
        }
        catch (UnauthorizedAccessException) { }
        catch (DirectoryNotFoundException) { }
        catch { }
    }
}
