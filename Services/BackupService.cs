using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace EASYSID;

/// <summary>
/// Comprehensive backup and restore service for EASYSID.
///
/// Creates a full system snapshot before SID change including:
///   - Registry hives (SAM, SECURITY, SOFTWARE, SYSTEM)
///   - Registry exports (ProfileList, Winlogon, Policies)
///   - User profile hives (NTUSER.DAT, UsrClass.dat)
///   - DPAPI master keys (Protect directories)
///   - Chromium browser profiles (Chrome, Edge, Brave, Opera, Vivaldi)
///   - Default app associations (UserChoice ProgId values)
///   - Machine identity values (MachineGuid, MachineId, WSUS, MSDTC, DeviceId, DHCP)
///   - Metadata and SHA256 manifest for integrity verification
///
/// Restore supports:
///   - Full rollback (registry imports + profile hives + DPAPI + browser data)
///   - Selective restore (individual components)
///   - Integrity verification before restore
///   - Snapshot listing and cleanup
/// </summary>
internal static class BackupService
{
    internal const string DefaultBackupRoot = @"C:\ProgramData\EASYSID\Backups";
    private const int MaxSnapshots = 5; // keep last N snapshots, auto-clean older ones
    private const int SnapshotVersion = 2;

    // Registry keys to export via reg.exe (importable with reg import)
    private static readonly (string Key, string FileName)[] SnapshotExportKeys =
    {
        (@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList", "ProfileList.reg"),
        (@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Winlogon.reg"),
        (@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "PoliciesSystem.reg"),
        (@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Authentication\LogonUI", "LogonUI.reg"),
        (@"HKLM\SOFTWARE\Microsoft\Cryptography", "Cryptography.reg"),
        (@"HKLM\SOFTWARE\Microsoft\SQMClient", "SQMClient.reg"),
        (@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate", "WindowsUpdate.reg"),
        (@"HKLM\SOFTWARE\Microsoft\MSDTC", "MSDTC.reg"),
        (@"HKLM\SYSTEM\CurrentControlSet\Control\ComputerName", "ComputerName.reg"),
        (@"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "TcpipParameters.reg"),
    };

    // Registry hives to save via reg.exe (restorable only offline or via reg restore)
    private static readonly (string Key, string FileName)[] SnapshotHiveKeys =
    {
        (@"HKLM\SAM", "SAM.hiv"),
        (@"HKLM\SECURITY", "SECURITY.hiv"),
        (@"HKLM\SOFTWARE", "SOFTWARE.hiv"),
        (@"HKLM\SYSTEM", "SYSTEM.hiv"),
    };

    // Chromium browser data directories relative to user profile
    private static readonly (string RelPath, string Name)[] ChromiumBrowserPaths =
    {
        (@"AppData\Local\Google\Chrome\User Data", "Chrome"),
        (@"AppData\Local\Microsoft\Edge\User Data", "Edge"),
        (@"AppData\Local\BraveSoftware\Brave-Browser\User Data", "Brave"),
        (@"AppData\Roaming\Opera Software\Opera Stable", "Opera"),
        (@"AppData\Local\Vivaldi\User Data", "Vivaldi"),
    };

    private static readonly HashSet<string> IgnoredProfiles = new(StringComparer.OrdinalIgnoreCase)
    {
        "Default", "Default User", "Public", "All Users", "defaultuser0"
    };

    // -----------------------------------------------------------------------
    // Snapshot creation
    // -----------------------------------------------------------------------

    internal static bool CreateSnapshot(string backupRoot, string oldSid, string newSid,
                                        string newName, out string snapshotDir)
    {
        snapshotDir = string.Empty;
        try
        {
            string root = string.IsNullOrWhiteSpace(backupRoot) ? DefaultBackupRoot : backupRoot;
            string stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            snapshotDir = Path.Combine(root, stamp);
            Directory.CreateDirectory(snapshotDir);

            Console.WriteLine($"[*] Creating snapshot: {snapshotDir}");

            // 1. Metadata
            WriteMetadata(snapshotDir, oldSid, newSid, newName);

            // 2. Registry exports (importable online via reg import)
            Console.WriteLine("  [backup] Registry exports...");
            string regDir = Path.Combine(snapshotDir, "Registry");
            Directory.CreateDirectory(regDir);
            foreach (var item in SnapshotExportKeys)
            {
                string target = Path.Combine(regDir, item.FileName);
                ProcessRunner.RunHiddenProcess("reg.exe", $"export \"{item.Key}\" \"{target}\" /y");
                // Non-fatal if a key doesn't exist
            }

            // 3. Registry hive saves (restorable offline)
            Console.WriteLine("  [backup] Registry hives...");
            string hiveDir = Path.Combine(snapshotDir, "Hives");
            Directory.CreateDirectory(hiveDir);
            foreach (var item in SnapshotHiveKeys)
            {
                string target = Path.Combine(hiveDir, item.FileName);
                if (!ProcessRunner.RunHiddenProcess("reg.exe", $"save \"{item.Key}\" \"{target}\" /y"))
                    Console.WriteLine($"    WARNING: Failed to save {item.Key}");
            }

            // 4. User profile data
            string profileDir = Path.Combine(snapshotDir, "Profiles");
            Directory.CreateDirectory(profileDir);
            BackupAllUserProfiles(profileDir);

            // 5. Machine identity values
            Console.WriteLine("  [backup] Machine identity values...");
            BackupMachineIdentity(snapshotDir);

            // 6. Default app associations
            Console.WriteLine("  [backup] Default app associations...");
            BackupDefaultApps(snapshotDir);

            // 7. SHA256 manifest for integrity verification
            Console.WriteLine("  [backup] Generating integrity manifest...");
            GenerateManifest(snapshotDir);

            // 8. Auto-cleanup old snapshots
            CleanupOldSnapshots(root);

            Console.WriteLine($"  [backup] Snapshot complete: {snapshotDir}");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  Snapshot creation failed: {ex.Message}");
            return false;
        }
    }

    // -----------------------------------------------------------------------
    // Offline restore (WinPE)
    // -----------------------------------------------------------------------

    /// <summary>
    /// Restores a snapshot to an offline Windows installation from WinPE.
    ///
    /// In WinPE the target Windows is mounted on a different drive (D:, E: etc.).
    /// The running OS is X:\Windows (WinPE RAM disk). This method:
    ///   1. Resolves the target Windows and Users directories
    ///   2. Restores registry hives via reg load/restore/unload to offline hives
    ///   3. Copies DPAPI master keys directly to profile folders
    ///   4. Copies browser profile data directly
    ///   5. Restores profile hive files (NTUSER.DAT, UsrClass.dat)
    ///
    /// Usage from WinPE command prompt:
    ///   X:\> EASYSID.exe /ROLLBACK=D:\ProgramData\EASYSID\Backups\20260323_143000 /OFFLINE=D:
    /// </summary>
    internal static bool OfflineRestore(string snapshotDir, string targetDrive)
    {
        try
        {
            // Normalize target drive
            targetDrive = targetDrive.TrimEnd('\\', '/');
            if (!targetDrive.EndsWith(":")) targetDrive += ":";

            string targetWindows = Path.Combine(targetDrive, "Windows");
            string targetUsers = Path.Combine(targetDrive, "Users");

            // If user passed D:\Windows, extract the drive
            if (targetDrive.Contains(@"\Windows"))
            {
                targetWindows = targetDrive;
                targetDrive = targetDrive.Substring(0, 2); // "D:"
                targetUsers = Path.Combine(targetDrive, "Users");
            }

            Console.WriteLine($"[*] WinPE Offline Restore");
            Console.WriteLine($"    Snapshot:       {snapshotDir}");
            Console.WriteLine($"    Target drive:   {targetDrive}");
            Console.WriteLine($"    Target Windows: {targetWindows}");
            Console.WriteLine($"    Target Users:   {targetUsers}");

            if (!Directory.Exists(snapshotDir))
            {
                Console.Error.WriteLine($"Snapshot directory not found: {snapshotDir}");
                return false;
            }

            if (!Directory.Exists(targetWindows))
            {
                Console.Error.WriteLine($"Target Windows not found: {targetWindows}");
                Console.Error.WriteLine("Make sure the correct drive letter is specified.");
                return false;
            }

            // Verify integrity
            VerifyManifest(snapshotDir);

            // Read metadata
            var metadata = ReadMetadata(snapshotDir);
            if (metadata != null)
            {
                Console.WriteLine($"    Snapshot date:  {metadata.GetValueOrDefault("created_local", "?")}");
                Console.WriteLine($"    Machine name:   {metadata.GetValueOrDefault("machine_name", "?")}");
                Console.WriteLine($"    Old SID:        {metadata.GetValueOrDefault("old_sid", "?")}");
            }

            bool ok = true;

            // 1. Offline registry hive restore
            // In WinPE, hives are files on disk - we can replace them directly
            Console.WriteLine("\n  [offline] Registry hives...");
            string hiveDir = Path.Combine(snapshotDir, "Hives");
            if (Directory.Exists(hiveDir))
            {
                string configDir = Path.Combine(targetWindows, @"System32\config");
                var hiveMap = new (string BackupFile, string TargetFile)[]
                {
                    ("SAM.hiv",      Path.Combine(configDir, "SAM")),
                    ("SECURITY.hiv", Path.Combine(configDir, "SECURITY")),
                    ("SOFTWARE.hiv", Path.Combine(configDir, "SOFTWARE")),
                    ("SYSTEM.hiv",   Path.Combine(configDir, "SYSTEM")),
                };

                foreach (var (backupFile, targetFile) in hiveMap)
                {
                    string src = Path.Combine(hiveDir, backupFile);
                    if (!File.Exists(src))
                    {
                        Console.WriteLine($"    {backupFile}: not in snapshot, skipping.");
                        continue;
                    }

                    try
                    {
                        // Backup current hive before overwriting
                        string backupCurrent = targetFile + ".easysid-pre-restore";
                        if (File.Exists(targetFile) && !File.Exists(backupCurrent))
                        {
                            File.Copy(targetFile, backupCurrent, false);
                            Console.WriteLine($"    {backupFile}: current hive backed up to .easysid-pre-restore");
                        }

                        File.Copy(src, targetFile, true);
                        Console.WriteLine($"    {backupFile}: restored.");
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine($"    {backupFile}: FAILED - {ex.Message}");
                        ok = false;
                    }
                }
            }
            else
            {
                Console.WriteLine("    No hive backup directory found.");
            }

            // 2. Registry exports (load offline SOFTWARE hive, import .reg files)
            Console.WriteLine("\n  [offline] Registry exports...");
            string regDir = Path.Combine(snapshotDir, "Registry");
            if (Directory.Exists(regDir))
            {
                // Load offline SOFTWARE hive temporarily
                string offlineSoftware = Path.Combine(targetWindows, @"System32\config\SOFTWARE");
                string tempHiveName = "EASYSID_OFFLINE_SW";
                bool hiveLoaded = false;

                if (File.Exists(offlineSoftware))
                {
                    int rc = NativeImports.RegLoadKeyW(NativeImports.HKEY_LOCAL_MACHINE, tempHiveName, offlineSoftware);
                    if (rc == 0)
                    {
                        hiveLoaded = true;
                        Console.WriteLine($"    Offline SOFTWARE hive loaded as HKLM\\{tempHiveName}");
                    }
                    else
                    {
                        Console.WriteLine($"    Could not load offline SOFTWARE hive (0x{rc:X8})");
                    }
                }

                // Import .reg files that target HKLM\SOFTWARE
                foreach (string regFile in Directory.GetFiles(regDir, "*.reg"))
                {
                    string fileName = Path.GetFileName(regFile);
                    if (hiveLoaded)
                    {
                        // Rewrite .reg file to point to temp hive location
                        try
                        {
                            string content = File.ReadAllText(regFile, Encoding.Unicode);
                            string modified = content.Replace(
                                @"HKEY_LOCAL_MACHINE\SOFTWARE",
                                $@"HKEY_LOCAL_MACHINE\{tempHiveName}");
                            string tempReg = Path.Combine(Path.GetTempPath(), fileName);
                            File.WriteAllText(tempReg, modified, Encoding.Unicode);
                            ProcessRunner.RunHiddenProcess("reg.exe", $"import \"{tempReg}\"");
                            try { File.Delete(tempReg); } catch { }
                            Console.WriteLine($"    {fileName}: imported (offline).");
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"    {fileName}: import failed - {ex.Message}");
                        }
                    }
                    else
                    {
                        Console.WriteLine($"    {fileName}: skipped (hive not loaded).");
                    }
                }

                // Unload offline hive
                if (hiveLoaded)
                {
                    NativeMethods.RegUnLoadKeyW(NativeImports.HKEY_LOCAL_MACHINE, tempHiveName);
                    Console.WriteLine($"    Offline SOFTWARE hive unloaded.");
                }
            }

            // 3. Profile hive files (NTUSER.DAT, UsrClass.dat)
            Console.WriteLine("\n  [offline] User profile hives...");
            string profileBackupDir = Path.Combine(snapshotDir, "Profiles");
            if (Directory.Exists(profileBackupDir) && Directory.Exists(targetUsers))
            {
                foreach (string srcProfileDir in Directory.GetDirectories(profileBackupDir))
                {
                    string profileName = Path.GetFileName(srcProfileDir);
                    string dstProfileDir = Path.Combine(targetUsers, profileName);
                    if (!Directory.Exists(dstProfileDir))
                    {
                        Console.WriteLine($"    {profileName}: target profile not found, skipping.");
                        continue;
                    }

                    // NTUSER.DAT
                    string srcNtuser = Path.Combine(srcProfileDir, "NTUSER.DAT");
                    string dstNtuser = Path.Combine(dstProfileDir, "NTUSER.DAT");
                    if (File.Exists(srcNtuser))
                    {
                        try
                        {
                            File.Copy(srcNtuser, dstNtuser, true);
                            Console.WriteLine($"    {profileName}: NTUSER.DAT restored.");
                        }
                        catch (Exception ex) { Console.WriteLine($"    {profileName}: NTUSER.DAT - {ex.Message}"); ok = false; }
                    }

                    // UsrClass.dat
                    string srcUsr = Path.Combine(srcProfileDir, "UsrClass.dat");
                    string dstUsr = Path.Combine(dstProfileDir, @"AppData\Local\Microsoft\Windows\UsrClass.dat");
                    if (File.Exists(srcUsr))
                    {
                        try
                        {
                            string dstUsrDir = Path.GetDirectoryName(dstUsr);
                            if (!string.IsNullOrEmpty(dstUsrDir)) Directory.CreateDirectory(dstUsrDir);
                            File.Copy(srcUsr, dstUsr, true);
                            Console.WriteLine($"    {profileName}: UsrClass.dat restored.");
                        }
                        catch (Exception ex) { Console.WriteLine($"    {profileName}: UsrClass.dat - {ex.Message}"); ok = false; }
                    }

                    // 4. DPAPI master keys
                    string dpapiSrc = Path.Combine(srcProfileDir, "DPAPI");
                    string dpapiDst = Path.Combine(dstProfileDir, @"AppData\Roaming\Microsoft\Protect");
                    if (Directory.Exists(dpapiSrc))
                    {
                        try
                        {
                            ProcessRunner.CopyDirectoryRecursive(dpapiSrc, dpapiDst);
                            Console.WriteLine($"    {profileName}: DPAPI keys restored.");
                        }
                        catch (Exception ex) { Console.WriteLine($"    {profileName}: DPAPI - {ex.Message}"); }
                    }

                    // 5. Browser profiles
                    string browsersDir = Path.Combine(srcProfileDir, "Browsers");
                    if (Directory.Exists(browsersDir))
                    {
                        foreach (var (relPath, name) in ChromiumBrowserPaths)
                        {
                            string browserBackup = Path.Combine(browsersDir, name);
                            if (!Directory.Exists(browserBackup)) continue;

                            string browserTarget = Path.Combine(dstProfileDir, relPath);
                            if (!Directory.Exists(browserTarget)) continue;

                            ProcessRunner.CopyIfExists(
                                Path.Combine(browserBackup, "Local State"),
                                Path.Combine(browserTarget, "Local State"));

                            foreach (string profSubDir in Directory.GetDirectories(browserBackup))
                            {
                                string subName = Path.GetFileName(profSubDir);
                                string targetSub = Path.Combine(browserTarget, subName);
                                if (!Directory.Exists(targetSub)) continue;

                                ProcessRunner.CopyIfExists(
                                    Path.Combine(profSubDir, "Preferences"),
                                    Path.Combine(targetSub, "Preferences"));
                                ProcessRunner.CopyIfExists(
                                    Path.Combine(profSubDir, "Bookmarks"),
                                    Path.Combine(targetSub, "Bookmarks"));
                            }
                            Console.WriteLine($"    {profileName}/{name}: browser data restored.");
                        }
                    }
                }
            }

            // 6. Machine identity
            Console.WriteLine("\n  [offline] Machine identity...");
            RestoreMachineIdentityOffline(snapshotDir, targetWindows);

            Console.WriteLine(ok
                ? "\n[*] Offline restore completed successfully."
                : "\n[*] Offline restore completed with errors. Check output above.");
            Console.WriteLine("    Reboot the target system to apply changes.");

            return ok;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Offline restore failed: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Restores machine identity values to an offline SOFTWARE hive.
    /// </summary>
    private static void RestoreMachineIdentityOffline(string snapshotDir, string targetWindows)
    {
        string identityPath = Path.Combine(snapshotDir, "identity.txt");
        if (!File.Exists(identityPath))
        {
            Console.WriteLine("    No identity backup found.");
            return;
        }

        var identity = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (string line in File.ReadAllLines(identityPath))
        {
            int eq = line.IndexOf('=');
            if (eq > 0) identity[line.Substring(0, eq)] = line.Substring(eq + 1);
        }

        // Load offline SOFTWARE hive
        string softwarePath = Path.Combine(targetWindows, @"System32\config\SOFTWARE");
        if (!File.Exists(softwarePath))
        {
            Console.WriteLine("    Offline SOFTWARE hive not found.");
            return;
        }

        string tempName = "EASYSID_OFFLINE_ID";
        int rc = NativeImports.RegLoadKeyW(NativeImports.HKEY_LOCAL_MACHINE, tempName, softwarePath);
        if (rc != 0)
        {
            Console.WriteLine($"    Could not load offline SOFTWARE (0x{rc:X8})");
            return;
        }

        try
        {
            if (identity.TryGetValue("MachineGuid", out string mg) && !string.IsNullOrEmpty(mg))
            {
                using var key = RegistryHelper.OpenRegKey(Microsoft.Win32.RegistryHive.LocalMachine,
                    $@"{tempName}\Microsoft\Cryptography", true);
                key?.SetValue("MachineGuid", mg, Microsoft.Win32.RegistryValueKind.String);
                Console.WriteLine($"    MachineGuid: {mg}");
            }

            if (identity.TryGetValue("MachineId", out string mi) && !string.IsNullOrEmpty(mi))
            {
                using var key = RegistryHelper.OpenRegKey(Microsoft.Win32.RegistryHive.LocalMachine,
                    $@"{tempName}\Microsoft\SQMClient", true);
                key?.SetValue("MachineId", mi, Microsoft.Win32.RegistryValueKind.String);
                Console.WriteLine($"    MachineId: {mi}");
            }

            if (identity.TryGetValue("SusClientId", out string sus) && !string.IsNullOrEmpty(sus))
            {
                using var key = RegistryHelper.OpenRegKey(Microsoft.Win32.RegistryHive.LocalMachine,
                    $@"{tempName}\Microsoft\Windows\CurrentVersion\WindowsUpdate", true);
                key?.SetValue("SusClientId", sus, Microsoft.Win32.RegistryValueKind.String);
                Console.WriteLine($"    SusClientId: {sus}");
            }
        }
        finally
        {
            NativeMethods.RegUnLoadKeyW(NativeImports.HKEY_LOCAL_MACHINE, tempName);
        }
    }

    // -----------------------------------------------------------------------
    // Snapshot restoration (online)
    // -----------------------------------------------------------------------

    /// <summary>
    /// Online restore: if running as SYSTEM (Phase 2 / scheduled task), performs
    /// full restore including user hives via reg load/unload. If running interactively,
    /// schedules a boot-time task to do the full restore at next startup.
    /// </summary>
    internal static bool RestoreSnapshot(string snapshotDir)
    {
        try
        {
            Console.WriteLine($"[*] Restoring snapshot: {snapshotDir}");
            if (!Directory.Exists(snapshotDir))
            {
                Console.Error.WriteLine($"Snapshot directory not found: {snapshotDir}");
                return false;
            }

            // Verify integrity
            if (!VerifyManifest(snapshotDir))
            {
                Console.Error.WriteLine("  WARNING: Integrity check failed or manifest missing.");
            }

            // Read metadata
            var metadata = ReadMetadata(snapshotDir);
            if (metadata != null)
            {
                Console.WriteLine($"  Snapshot date:  {metadata.GetValueOrDefault("created_local", "?")}");
                Console.WriteLine($"  Machine name:   {metadata.GetValueOrDefault("machine_name", "?")}");
                Console.WriteLine($"  Old SID:        {metadata.GetValueOrDefault("old_sid", "?")}");
            }

            // Check if we're running as SYSTEM (background task)
            bool isSystem = Environment.UserName.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) ||
                            System.Security.Principal.WindowsIdentity.GetCurrent()?.IsSystem == true;

            if (!isSystem)
            {
                // Interactive mode: schedule a boot-time rollback task
                Console.WriteLine("  Running interactively - scheduling boot-time rollback...");
                return ScheduleBootRollback(snapshotDir);
            }

            // SYSTEM mode: perform full restore now
            Console.WriteLine("  Running as SYSTEM - performing full restore...");
            return PerformFullOnlineRestore(snapshotDir, metadata);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Snapshot restore failed: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Schedules a boot-time task that runs EASYSID /ROLLBACK as SYSTEM,
    /// enabling full hive restore. Then shuts down the machine.
    /// </summary>
    private static bool ScheduleBootRollback(string snapshotDir)
    {
        string exePath = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName
                         ?? Path.Combine(AppContext.BaseDirectory, "EASYSID.exe");

        string taskArgs = $"/ROLLBACK=\"{snapshotDir}\" /F";
        const string taskName = "EASYSID_ROLLBACK";

        // Clean up any previous rollback tasks
        BackgroundTaskService.DeleteScheduledTask(taskName);

        // Create boot-time task (reuses the XML method from BackgroundTaskService)
        string xmlContent = $@"<?xml version=""1.0"" encoding=""UTF-16""?>
<Task version=""1.4"" xmlns=""http://schemas.microsoft.com/windows/2004/02/mit/task"">
  <RegistrationInfo>
    <Description>EASYSID Rollback - Restore from snapshot</Description>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
      <Delay>PT5S</Delay>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id=""Author"">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>true</WakeToRun>
    <ExecutionTimeLimit>PT2H</ExecutionTimeLimit>
  </Settings>
  <Actions Context=""Author"">
    <Exec>
      <Command>""{exePath}""</Command>
      <Arguments>{System.Security.SecurityElement.Escape(taskArgs)}</Arguments>
    </Exec>
  </Actions>
</Task>";

        string xmlPath = Path.Combine(Path.GetTempPath(), "EASYSID_rollback_task.xml");
        File.WriteAllText(xmlPath, xmlContent, Encoding.Unicode);

        try
        {
            bool created = ProcessRunner.RunHiddenProcess("schtasks.exe",
                $"/Create /TN \"{taskName}\" /XML \"{xmlPath}\" /F");

            if (!created)
            {
                Console.Error.WriteLine("  Failed to create rollback task.");
                return false;
            }

            Console.WriteLine("  Rollback task scheduled. System will shut down now.");
            Console.WriteLine("  Full restore will run at next boot as SYSTEM.");

            // Set WinLogon notice
            WinLogonService.SetWinLogonNotice(
                "EASYSID ROLLBACK IN PROGRESS",
                "Snapshot restore is running. Please wait until the system restarts.");

            // Shutdown
            System.Threading.Thread.Sleep(2000);
            ShutdownService.ForceSystemRestart(true, "EASYSID: Rollback scheduled. Rebooting for restore...");
            return true;
        }
        finally
        {
            try { File.Delete(xmlPath); } catch { }
        }
    }

    /// <summary>
    /// Performs full online restore when running as SYSTEM.
    /// User hives are accessible via reg load/unload since no user is logged in.
    /// </summary>
    private static bool PerformFullOnlineRestore(string snapshotDir, Dictionary<string, string> metadata)
    {
        bool ok = true;

        // Acquire all needed privileges
        NativeImports.RtlAdjustPrivilege(8,  true, false, out _); // SeSecurityPrivilege
        NativeImports.RtlAdjustPrivilege(9,  true, false, out _); // SeTakeOwnershipPrivilege
        NativeImports.RtlAdjustPrivilege(17, true, false, out _); // SeBackupPrivilege
        NativeImports.RtlAdjustPrivilege(18, true, false, out _); // SeRestorePrivilege

        // 1. Registry imports
        Console.WriteLine("  [restore] Registry exports...");
        string regDir = Path.Combine(snapshotDir, "Registry");
        if (Directory.Exists(regDir))
        {
            foreach (string regFile in Directory.GetFiles(regDir, "*.reg"))
            {
                bool r = ProcessRunner.RunHiddenProcess("reg.exe", $"import \"{regFile}\"");
                if (!r) Console.WriteLine($"    WARNING: Failed to import {Path.GetFileName(regFile)}");
                ok = r && ok;
            }
        }
        else
        {
            // Legacy v1 format
            foreach (var item in SnapshotExportKeys)
            {
                string source = Path.Combine(snapshotDir, item.FileName);
                if (File.Exists(source))
                    ok = ProcessRunner.RunHiddenProcess("reg.exe", $"import \"{source}\"") && ok;
            }
        }

        // 2. Machine identity (direct registry write, works as SYSTEM)
        Console.WriteLine("  [restore] Machine identity...");
        RestoreMachineIdentity(snapshotDir);

        // 3. User profiles: hives, DPAPI, browsers
        Console.WriteLine("  [restore] User profiles (full)...");
        string profileBackupDir = Path.Combine(snapshotDir, "Profiles");
        if (Directory.Exists(profileBackupDir))
        {
            string systemDrive = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:";
            string usersRoot = Path.Combine(systemDrive, "Users");

            foreach (string srcProfileDir in Directory.GetDirectories(profileBackupDir))
            {
                string profileName = Path.GetFileName(srcProfileDir);
                string dstProfileDir = Path.Combine(usersRoot, profileName);
                if (!Directory.Exists(dstProfileDir))
                {
                    Console.WriteLine($"    {profileName}: target not found, skipping.");
                    continue;
                }

                // NTUSER.DAT - not loaded since no user is logged in
                string srcNtuser = Path.Combine(srcProfileDir, "NTUSER.DAT");
                string dstNtuser = Path.Combine(dstProfileDir, "NTUSER.DAT");
                if (File.Exists(srcNtuser))
                {
                    try { File.Copy(srcNtuser, dstNtuser, true); Console.WriteLine($"    {profileName}: NTUSER.DAT restored."); }
                    catch (Exception ex)
                    {
                        // Hive might still be loaded - try reg load/unload approach
                        Console.WriteLine($"    {profileName}: NTUSER.DAT locked ({ex.Message}), trying reg load...");
                        RestoreLockedHive(srcNtuser, dstNtuser, profileName, "NTUSER");
                    }
                }

                // UsrClass.dat
                string srcUsr = Path.Combine(srcProfileDir, "UsrClass.dat");
                string dstUsr = Path.Combine(dstProfileDir, @"AppData\Local\Microsoft\Windows\UsrClass.dat");
                if (File.Exists(srcUsr))
                {
                    try
                    {
                        string dstUsrDir = Path.GetDirectoryName(dstUsr);
                        if (!string.IsNullOrEmpty(dstUsrDir)) Directory.CreateDirectory(dstUsrDir);
                        File.Copy(srcUsr, dstUsr, true);
                        Console.WriteLine($"    {profileName}: UsrClass.dat restored.");
                    }
                    catch { }
                }

                // DPAPI keys
                string dpapiSrc = Path.Combine(srcProfileDir, "DPAPI");
                string dpapiDst = Path.Combine(dstProfileDir, @"AppData\Roaming\Microsoft\Protect");
                if (Directory.Exists(dpapiSrc))
                {
                    try { ProcessRunner.CopyDirectoryRecursive(dpapiSrc, dpapiDst); Console.WriteLine($"    {profileName}: DPAPI restored."); }
                    catch (Exception ex) { Console.WriteLine($"    {profileName}: DPAPI - {ex.Message}"); }
                }

                // Browser profiles
                string browsersDir = Path.Combine(srcProfileDir, "Browsers");
                if (Directory.Exists(browsersDir))
                {
                    foreach (var (relPath, name) in ChromiumBrowserPaths)
                    {
                        string browserBackup = Path.Combine(browsersDir, name);
                        if (!Directory.Exists(browserBackup)) continue;
                        string browserTarget = Path.Combine(dstProfileDir, relPath);
                        if (!Directory.Exists(browserTarget)) continue;

                        ProcessRunner.CopyIfExists(
                            Path.Combine(browserBackup, "Local State"),
                            Path.Combine(browserTarget, "Local State"));

                        foreach (string profSubDir in Directory.GetDirectories(browserBackup))
                        {
                            string subName = Path.GetFileName(profSubDir);
                            string targetSub = Path.Combine(browserTarget, subName);
                            if (!Directory.Exists(targetSub)) continue;
                            ProcessRunner.CopyIfExists(Path.Combine(profSubDir, "Preferences"), Path.Combine(targetSub, "Preferences"));
                            ProcessRunner.CopyIfExists(Path.Combine(profSubDir, "Bookmarks"), Path.Combine(targetSub, "Bookmarks"));
                        }
                        Console.WriteLine($"    {profileName}/{name}: browser data restored.");
                    }
                }
            }
        }

        // 4. Default app associations
        Console.WriteLine("  [restore] Default app associations...");
        RestoreDefaultApps(snapshotDir);

        // Cleanup: delete rollback task if it exists
        BackgroundTaskService.DeleteScheduledTask("EASYSID_ROLLBACK");
        WinLogonService.ClearWinLogonNotice();

        Console.WriteLine(ok
            ? "[*] Full online restore completed."
            : "[*] Online restore completed with warnings.");

        // Reboot to apply
        Console.WriteLine("  Rebooting to apply changes...");
        ShutdownService.ForceSystemRestart(true, "EASYSID: Restore complete. Rebooting to apply...");

        return ok;
    }

    /// <summary>
    /// Attempts to restore a locked hive by loading the backup, exporting values,
    /// loading the target, and importing. Last resort for online restore.
    /// </summary>
    private static void RestoreLockedHive(string srcHive, string dstHive, string profileName, string label)
    {
        // Try to unload the target hive first, then copy
        string tempUnloadName = $"EASYSID_UNLOAD_{label}_{profileName}".ToUpperInvariant();
        try
        {
            // Force GC to release any managed handles
            GC.Collect();
            GC.WaitForPendingFinalizers();
            System.Threading.Thread.Sleep(500);

            // Try unloading the hive from HKU
            NativeMethods.RegUnLoadKeyW(NativeMethods.HKEY_USERS, profileName);
            System.Threading.Thread.Sleep(200);

            // Now try the copy again
            File.Copy(srcHive, dstHive, true);
            Console.WriteLine($"    {profileName}: {label} restored after unload.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    {profileName}: {label} still locked - {ex.Message}");
            Console.WriteLine($"    Use WinPE offline restore: /ROLLBACK=... /OFFLINE=D:");
        }
    }

    // -----------------------------------------------------------------------
    // Snapshot listing
    // -----------------------------------------------------------------------

    internal static void ListSnapshots(string backupRoot = null)
    {
        string root = string.IsNullOrWhiteSpace(backupRoot) ? DefaultBackupRoot : backupRoot;
        Console.WriteLine($"[*] Snapshots in: {root}");

        if (!Directory.Exists(root))
        {
            Console.WriteLine("  No snapshots found.");
            return;
        }

        var dirs = Directory.GetDirectories(root)
            .OrderByDescending(d => d)
            .ToArray();

        if (dirs.Length == 0)
        {
            Console.WriteLine("  No snapshots found.");
            return;
        }

        Console.WriteLine($"  {"#",-3} {"Date",-20} {"Machine",-16} {"Old SID",-45} {"Size",10}");
        Console.WriteLine(new string('-', 98));

        for (int i = 0; i < dirs.Length; i++)
        {
            string dir = dirs[i];
            var meta = ReadMetadata(dir);
            string date = meta?.GetValueOrDefault("created_local", "?") ?? "?";
            string machine = meta?.GetValueOrDefault("machine_name", "?") ?? "?";
            string sid = meta?.GetValueOrDefault("old_sid", "?") ?? "?";
            long size = GetDirectorySize(dir);
            string sizeStr = FormatSize(size);

            // Truncate date to readable format
            if (date.Length > 19) date = date.Substring(0, 19);

            Console.WriteLine($"  {i + 1,-3} {date,-20} {machine,-16} {sid,-45} {sizeStr,10}");
        }

        Console.WriteLine($"\n  Total: {dirs.Length} snapshot(s)");
        Console.WriteLine($"  Restore with: EASYSID /ROLLBACK=\"{dirs[0]}\"");
    }

    // -----------------------------------------------------------------------
    // Private helpers - Backup
    // -----------------------------------------------------------------------

    private static void WriteMetadata(string snapshotDir, string oldSid, string newSid, string newName)
    {
        string metadataPath = Path.Combine(snapshotDir, "metadata.txt");
        File.WriteAllLines(metadataPath, new[]
        {
            $"created_local={DateTime.Now:O}",
            $"created_utc={DateTime.UtcNow:O}",
            $"machine_name={Environment.MachineName}",
            $"old_sid={oldSid}",
            $"new_sid={newSid}",
            $"new_name={(string.IsNullOrWhiteSpace(newName) ? "(unchanged)" : newName)}",
            $"os_version={Environment.OSVersion.Version}",
            $"user={Environment.UserName}",
            $"version={SnapshotVersion}",
        }, Encoding.UTF8);
    }

    private static void BackupAllUserProfiles(string profileBackupDir)
    {
        string systemDrive = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:";
        string usersRoot = Path.Combine(systemDrive, "Users");
        if (!Directory.Exists(usersRoot))
        {
            Console.WriteLine($"  [backup] Users root not found: {usersRoot}");
            return;
        }

        foreach (string userDir in Directory.GetDirectories(usersRoot))
        {
            string profileName = Path.GetFileName(userDir);
            if (IgnoredProfiles.Contains(profileName)) continue;

            Console.WriteLine($"  [backup] Profile: {profileName}");
            string outDir = Path.Combine(profileBackupDir, profileName);
            Directory.CreateDirectory(outDir);

            // Registry hives
            ProcessRunner.CopyIfExists(
                Path.Combine(userDir, "NTUSER.DAT"),
                Path.Combine(outDir, "NTUSER.DAT"));
            ProcessRunner.CopyIfExists(
                Path.Combine(userDir, @"AppData\Local\Microsoft\Windows\UsrClass.dat"),
                Path.Combine(outDir, "UsrClass.dat"));

            // DPAPI master keys
            string dpapiSrc = Path.Combine(userDir, @"AppData\Roaming\Microsoft\Protect");
            string dpapiDst = Path.Combine(outDir, "DPAPI");
            if (Directory.Exists(dpapiSrc))
            {
                try
                {
                    ProcessRunner.CopyDirectoryRecursive(dpapiSrc, dpapiDst);
                    Console.WriteLine($"    DPAPI keys: backed up");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"    DPAPI keys: {ex.Message}");
                }
            }

            // Chromium browser profiles (Local State + profile Preferences)
            foreach (var (relPath, name) in ChromiumBrowserPaths)
            {
                string browserDir = Path.Combine(userDir, relPath);
                if (!Directory.Exists(browserDir)) continue;

                string browserBackup = Path.Combine(outDir, "Browsers", name);
                Directory.CreateDirectory(browserBackup);

                // Local State (contains encrypted key and machine IDs)
                ProcessRunner.CopyIfExists(
                    Path.Combine(browserDir, "Local State"),
                    Path.Combine(browserBackup, "Local State"));

                // Each profile's Preferences and Bookmarks
                foreach (string profileSubDir in Directory.GetDirectories(browserDir))
                {
                    string subName = Path.GetFileName(profileSubDir);
                    if (!subName.Equals("Default", StringComparison.OrdinalIgnoreCase) &&
                        !subName.StartsWith("Profile ", StringComparison.OrdinalIgnoreCase))
                        continue;

                    string profileBackup = Path.Combine(browserBackup, subName);
                    Directory.CreateDirectory(profileBackup);
                    ProcessRunner.CopyIfExists(
                        Path.Combine(profileSubDir, "Preferences"),
                        Path.Combine(profileBackup, "Preferences"));
                    ProcessRunner.CopyIfExists(
                        Path.Combine(profileSubDir, "Bookmarks"),
                        Path.Combine(profileBackup, "Bookmarks"));
                    ProcessRunner.CopyIfExists(
                        Path.Combine(profileSubDir, "Shortcuts"),
                        Path.Combine(profileBackup, "Shortcuts"));
                }

                Console.WriteLine($"    {name}: backed up");
            }
        }
    }

    private static void BackupMachineIdentity(string snapshotDir)
    {
        var identityLines = new List<string>();
        try
        {
            using var cryptKey = RegistryHelper.OpenRegKey(RegistryHive.LocalMachine,
                @"SOFTWARE\Microsoft\Cryptography");
            string machineGuid = cryptKey?.GetValue("MachineGuid") as string;
            identityLines.Add($"MachineGuid={machineGuid ?? ""}");
        }
        catch { }

        try
        {
            using var sqmKey = RegistryHelper.OpenRegKey(RegistryHive.LocalMachine,
                @"SOFTWARE\Microsoft\SQMClient");
            string machineId = sqmKey?.GetValue("MachineId") as string;
            identityLines.Add($"MachineId={machineId ?? ""}");
        }
        catch { }

        try
        {
            using var wuKey = RegistryHelper.OpenRegKey(RegistryHive.LocalMachine,
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate");
            string susId = wuKey?.GetValue("SusClientId") as string;
            identityLines.Add($"SusClientId={susId ?? ""}");
        }
        catch { }

        try
        {
            using var compKey = RegistryHelper.OpenRegKey(RegistryHive.LocalMachine,
                @"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName");
            string compName = compKey?.GetValue("ComputerName") as string;
            identityLines.Add($"ComputerName={compName ?? ""}");
        }
        catch { }

        File.WriteAllLines(Path.Combine(snapshotDir, "identity.txt"), identityLines, Encoding.UTF8);
    }

    private static void BackupDefaultApps(string snapshotDir)
    {
        var defaults = new List<string>();
        try
        {
            using var fileExts = RegistryHelper.OpenRegKey(RegistryHive.CurrentUser,
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts");
            if (fileExts != null)
            {
                foreach (string ext in fileExts.GetSubKeyNames())
                {
                    try
                    {
                        using var uc = fileExts.OpenSubKey(ext + @"\UserChoice");
                        string progId = uc?.GetValue("ProgId") as string;
                        if (!string.IsNullOrEmpty(progId))
                            defaults.Add($"ext|{ext}|{progId}");
                    }
                    catch { }
                }
            }
        }
        catch { }

        try
        {
            using var urlAssoc = RegistryHelper.OpenRegKey(RegistryHive.CurrentUser,
                @"Software\Microsoft\Windows\Shell\Associations\UrlAssociations");
            if (urlAssoc != null)
            {
                foreach (string proto in urlAssoc.GetSubKeyNames())
                {
                    try
                    {
                        using var uc = urlAssoc.OpenSubKey(proto + @"\UserChoice");
                        string progId = uc?.GetValue("ProgId") as string;
                        if (!string.IsNullOrEmpty(progId))
                            defaults.Add($"proto|{proto}|{progId}");
                    }
                    catch { }
                }
            }
        }
        catch { }

        if (defaults.Count > 0)
            File.WriteAllLines(Path.Combine(snapshotDir, "defaults.txt"), defaults, Encoding.UTF8);
    }

    // -----------------------------------------------------------------------
    // Private helpers - Restore
    // -----------------------------------------------------------------------

    private static void RestoreUserProfiles(string profileBackupDir)
    {
        if (!Directory.Exists(profileBackupDir))
        {
            Console.WriteLine("    No profile backup directory found.");
            return;
        }

        string systemDrive = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:";
        string usersRoot = Path.Combine(systemDrive, "Users");

        foreach (string srcProfileDir in Directory.GetDirectories(profileBackupDir))
        {
            string profileName = Path.GetFileName(srcProfileDir);
            string dstProfileDir = Path.Combine(usersRoot, profileName);
            if (!Directory.Exists(dstProfileDir))
            {
                Console.WriteLine($"    {profileName}: target profile missing, skipping.");
                continue;
            }

            // Registry hives
            ProcessRunner.CopyIfExists(
                Path.Combine(srcProfileDir, "NTUSER.DAT"),
                Path.Combine(dstProfileDir, "NTUSER.DAT"));
            ProcessRunner.CopyIfExists(
                Path.Combine(srcProfileDir, "UsrClass.dat"),
                Path.Combine(dstProfileDir, @"AppData\Local\Microsoft\Windows\UsrClass.dat"));

            Console.WriteLine($"    {profileName}: profile hives restored.");
        }
    }

    private static void RestoreDpapiKeys(string snapshotDir)
    {
        string profileBackupDir = Path.Combine(snapshotDir, "Profiles");
        if (!Directory.Exists(profileBackupDir)) return;

        string systemDrive = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:";
        string usersRoot = Path.Combine(systemDrive, "Users");

        foreach (string srcProfileDir in Directory.GetDirectories(profileBackupDir))
        {
            string profileName = Path.GetFileName(srcProfileDir);
            string dstProfileDir = Path.Combine(usersRoot, profileName);
            if (!Directory.Exists(dstProfileDir)) continue;

            string dpapiSrc = Path.Combine(srcProfileDir, "DPAPI");
            string dpapiDst = Path.Combine(dstProfileDir, @"AppData\Roaming\Microsoft\Protect");
            if (!Directory.Exists(dpapiSrc)) continue;

            try
            {
                ProcessRunner.CopyDirectoryRecursive(dpapiSrc, dpapiDst);
                Console.WriteLine($"    {profileName}: DPAPI keys restored.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"    {profileName}: DPAPI restore failed: {ex.Message}");
            }
        }
    }

    private static void RestoreBrowserProfiles(string snapshotDir)
    {
        string profileBackupDir = Path.Combine(snapshotDir, "Profiles");
        if (!Directory.Exists(profileBackupDir)) return;

        string systemDrive = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:";
        string usersRoot = Path.Combine(systemDrive, "Users");

        foreach (string srcProfileDir in Directory.GetDirectories(profileBackupDir))
        {
            string profileName = Path.GetFileName(srcProfileDir);
            string dstProfileDir = Path.Combine(usersRoot, profileName);
            if (!Directory.Exists(dstProfileDir)) continue;

            string browsersDir = Path.Combine(srcProfileDir, "Browsers");
            if (!Directory.Exists(browsersDir)) continue;

            foreach (var (relPath, name) in ChromiumBrowserPaths)
            {
                string browserBackup = Path.Combine(browsersDir, name);
                if (!Directory.Exists(browserBackup)) continue;

                string browserDir = Path.Combine(dstProfileDir, relPath);
                if (!Directory.Exists(browserDir)) continue;

                // Restore Local State
                ProcessRunner.CopyIfExists(
                    Path.Combine(browserBackup, "Local State"),
                    Path.Combine(browserDir, "Local State"));

                // Restore each profile's Preferences and Bookmarks
                foreach (string profSubDir in Directory.GetDirectories(browserBackup))
                {
                    string subName = Path.GetFileName(profSubDir);
                    string targetSubDir = Path.Combine(browserDir, subName);
                    if (!Directory.Exists(targetSubDir)) continue;

                    ProcessRunner.CopyIfExists(
                        Path.Combine(profSubDir, "Preferences"),
                        Path.Combine(targetSubDir, "Preferences"));
                    ProcessRunner.CopyIfExists(
                        Path.Combine(profSubDir, "Bookmarks"),
                        Path.Combine(targetSubDir, "Bookmarks"));
                    ProcessRunner.CopyIfExists(
                        Path.Combine(profSubDir, "Shortcuts"),
                        Path.Combine(targetSubDir, "Shortcuts"));
                }

                Console.WriteLine($"    {profileName}/{name}: browser data restored.");
            }
        }
    }

    private static void RestoreMachineIdentity(string snapshotDir)
    {
        string identityPath = Path.Combine(snapshotDir, "identity.txt");
        if (!File.Exists(identityPath))
        {
            Console.WriteLine("    No identity backup found.");
            return;
        }

        var identity = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (string line in File.ReadAllLines(identityPath))
        {
            int eq = line.IndexOf('=');
            if (eq > 0) identity[line.Substring(0, eq)] = line.Substring(eq + 1);
        }

        try
        {
            if (identity.TryGetValue("MachineGuid", out string mg) && !string.IsNullOrEmpty(mg))
            {
                using var key = RegistryHelper.OpenRegKey(RegistryHive.LocalMachine,
                    @"SOFTWARE\Microsoft\Cryptography", true);
                key?.SetValue("MachineGuid", mg, RegistryValueKind.String);
                Console.WriteLine($"    MachineGuid: restored ({mg})");
            }
        }
        catch (Exception ex) { Console.WriteLine($"    MachineGuid restore: {ex.Message}"); }

        try
        {
            if (identity.TryGetValue("MachineId", out string mi) && !string.IsNullOrEmpty(mi))
            {
                using var key = RegistryHelper.OpenRegKey(RegistryHive.LocalMachine,
                    @"SOFTWARE\Microsoft\SQMClient", true);
                key?.SetValue("MachineId", mi, RegistryValueKind.String);
                Console.WriteLine($"    MachineId: restored ({mi})");
            }
        }
        catch (Exception ex) { Console.WriteLine($"    MachineId restore: {ex.Message}"); }

        try
        {
            if (identity.TryGetValue("SusClientId", out string sus) && !string.IsNullOrEmpty(sus))
            {
                using var key = RegistryHelper.OpenRegKey(RegistryHive.LocalMachine,
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate", true);
                key?.SetValue("SusClientId", sus, RegistryValueKind.String);
                Console.WriteLine($"    SusClientId: restored ({sus})");
            }
        }
        catch (Exception ex) { Console.WriteLine($"    SusClientId restore: {ex.Message}"); }
    }

    private static void RestoreDefaultApps(string snapshotDir)
    {
        string defaultsPath = Path.Combine(snapshotDir, "defaults.txt");
        if (!File.Exists(defaultsPath))
        {
            Console.WriteLine("    No default apps backup found.");
            return;
        }

        // Just copy the defaults file to the UserDefaults location
        // so MigrateAllUserDefaults can pick it up on next SID change
        try
        {
            string targetDir = Path.GetDirectoryName(UserDefaultsService.DefaultsFilePath);
            if (!string.IsNullOrEmpty(targetDir)) Directory.CreateDirectory(targetDir);
            File.Copy(defaultsPath, UserDefaultsService.DefaultsFilePath, true);
            Console.WriteLine($"    Default apps: {File.ReadAllLines(defaultsPath).Length} entry(ies) restored.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    Default apps restore: {ex.Message}");
        }
    }

    // -----------------------------------------------------------------------
    // Integrity verification (SHA256 manifest)
    // -----------------------------------------------------------------------

    private static void GenerateManifest(string snapshotDir)
    {
        var manifest = new List<string>();
        using var sha256 = SHA256.Create();

        foreach (string file in Directory.EnumerateFiles(snapshotDir, "*", SearchOption.AllDirectories))
        {
            string relativePath = file.Substring(snapshotDir.Length + 1);
            if (relativePath.Equals("manifest.sha256", StringComparison.OrdinalIgnoreCase))
                continue;

            try
            {
                byte[] hash = sha256.ComputeHash(File.ReadAllBytes(file));
                string hashStr = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                manifest.Add($"{hashStr}  {relativePath}");
            }
            catch { }
        }

        File.WriteAllLines(Path.Combine(snapshotDir, "manifest.sha256"), manifest, Encoding.UTF8);
        Console.WriteLine($"    Manifest: {manifest.Count} file(s) hashed.");
    }

    private static bool VerifyManifest(string snapshotDir)
    {
        string manifestPath = Path.Combine(snapshotDir, "manifest.sha256");
        if (!File.Exists(manifestPath))
        {
            Console.WriteLine("    No manifest found - skipping integrity check.");
            return true; // no manifest = legacy snapshot, skip check
        }

        using var sha256 = SHA256.Create();
        int verified = 0, failed = 0, missing = 0;

        foreach (string line in File.ReadAllLines(manifestPath))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            int sep = line.IndexOf("  ");
            if (sep < 0) continue;

            string expectedHash = line.Substring(0, sep);
            string relativePath = line.Substring(sep + 2);
            string fullPath = Path.Combine(snapshotDir, relativePath);

            if (!File.Exists(fullPath))
            {
                Console.WriteLine($"    MISSING: {relativePath}");
                missing++;
                continue;
            }

            try
            {
                byte[] hash = sha256.ComputeHash(File.ReadAllBytes(fullPath));
                string actualHash = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                if (actualHash == expectedHash)
                    verified++;
                else
                {
                    Console.WriteLine($"    MODIFIED: {relativePath}");
                    failed++;
                }
            }
            catch
            {
                failed++;
            }
        }

        Console.WriteLine($"    Integrity: {verified} OK, {failed} modified, {missing} missing.");
        return failed == 0 && missing == 0;
    }

    // -----------------------------------------------------------------------
    // Snapshot management
    // -----------------------------------------------------------------------

    private static void CleanupOldSnapshots(string backupRoot)
    {
        if (!Directory.Exists(backupRoot)) return;

        var dirs = Directory.GetDirectories(backupRoot)
            .OrderByDescending(d => d)
            .ToArray();

        if (dirs.Length <= MaxSnapshots) return;

        Console.WriteLine($"  [cleanup] {dirs.Length} snapshots found, keeping last {MaxSnapshots}...");
        for (int i = MaxSnapshots; i < dirs.Length; i++)
        {
            try
            {
                Directory.Delete(dirs[i], true);
                Console.WriteLine($"    Deleted old snapshot: {Path.GetFileName(dirs[i])}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"    Could not delete {Path.GetFileName(dirs[i])}: {ex.Message}");
            }
        }
    }

    private static Dictionary<string, string> ReadMetadata(string snapshotDir)
    {
        string metadataPath = Path.Combine(snapshotDir, "metadata.txt");
        if (!File.Exists(metadataPath)) return null;

        var meta = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (string line in File.ReadAllLines(metadataPath))
        {
            int eq = line.IndexOf('=');
            if (eq > 0) meta[line.Substring(0, eq)] = line.Substring(eq + 1);
        }
        return meta;
    }

    // -----------------------------------------------------------------------
    // Utility
    // -----------------------------------------------------------------------

    private static long GetDirectorySize(string path)
    {
        try
        {
            return Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories)
                .Sum(f => { try { return new FileInfo(f).Length; } catch { return 0; } });
        }
        catch { return 0; }
    }

    private static string FormatSize(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
        if (bytes < 1024 * 1024 * 1024) return $"{bytes / (1024.0 * 1024):F1} MB";
        return $"{bytes / (1024.0 * 1024 * 1024):F1} GB";
    }
}
