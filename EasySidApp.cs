using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Principal;

namespace EASYSID;

/// <summary>
/// Main orchestrator for the EASYSID SID changing utility.
/// Coordinates all services to perform the SID change workflow.
/// </summary>
public static class EasySidApp
{
    // -----------------------------------------------------------------------
    // Core entry point
    // -----------------------------------------------------------------------

    public static ExitCode Run(Options opts)
    {
        if (opts == null) throw new ArgumentNullException(nameof(opts));

        // 0. Always clean up stale WinLogon notices on every startup.
        // If a previous run crashed or reboot failed, the login screen notice
        // ("SID Change in Progress") may still be showing. Clean it up immediately.
        try { WinLogonService.ClearStaleNotices(); } catch { }

        // 1. Require administrator (checked first for all operations)
        if (!IsAdministrator())
        {
            Console.Error.WriteLine("Administrator access is required to run this program.");
            return ExitCode.NotAdministrator;
        }

        // 0a. If /LIST requested, show available snapshots and exit
        if (opts.ListSnapshots)
        {
            BackupService.ListSnapshots(opts.BackupDirectory);
            return ExitCode.Success;
        }

        // 0b. If /CANCEL requested, clean up everything and exit
        if (opts.Cancel)
        {
            CancelPendingSidChange();
            return ExitCode.Success;
        }

        // 0c. If /CLEARNOTICE requested, clear notices and DISM policy, then exit
        if (opts.ClearNotice)
        {
            Console.WriteLine("[*] Clearing WinLogon notice messages...");
            WinLogonService.ClearWinLogonNotice();
            UserDefaultsService.CleanupDismPolicy();
            BackgroundTaskService.DeleteScheduledTask("EASYSID_CLEANUP");
        BackgroundTaskService.DeleteScheduledTask("EASYSID_FIXBROWSERKEYS");
            Console.WriteLine("  WinLogon notices cleared.");
            return ExitCode.Success;
        }

        // 2. Acquire SeSecurityPrivilege (privilege index 8) via RtlAdjustPrivilege
        int privResult = NativeImports.RtlAdjustPrivilege(8, true, false, out _);
        if (privResult != 0)
        {
            Console.Error.WriteLine(
                "Required privilege SeSecurityPrivilege missing " +
                "(SeSecurityPrivilege must be listed with WHOAMI /PRIV)");
            return ExitCode.MissingPrivilege;
        }

        // 3. Also acquire additional privileges needed for SAM/SECURITY hive access
        Console.WriteLine(" ");
        var origColor = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("[*] Acquiring privileges...");
        Console.ForegroundColor = ConsoleColor.Green;
        { int r = NativeImports.RtlAdjustPrivilege(8,  true, false, out _); Console.WriteLine($"  SeSecurityPrivilege      (8):  {(r == 0 ? "OK" : $"failed 0x{r:X8}")}"); }
        { int r = NativeImports.RtlAdjustPrivilege(9,  true, false, out _); Console.WriteLine($"  SeTakeOwnershipPrivilege (9):  {(r == 0 ? "OK" : $"failed 0x{r:X8}")}"); }
        { int r = NativeImports.RtlAdjustPrivilege(17, true, false, out _); Console.WriteLine($"  SeBackupPrivilege       (17):  {(r == 0 ? "OK" : $"failed 0x{r:X8}")}"); }
        { int r = NativeImports.RtlAdjustPrivilege(18, true, false, out _); Console.WriteLine($"  SeRestorePrivilege      (18):  {(r == 0 ? "OK" : $"failed 0x{r:X8}")}"); }
        Console.ForegroundColor = origColor;

        // Optional maintenance mode: restore a previous snapshot and exit.
        // /OFFLINE=D: /ROLLBACK=<path> -> offline restore from WinPE
        if (!string.IsNullOrWhiteSpace(opts.RollbackDirectory))
        {
            bool rollbackOk;
            if (!string.IsNullOrWhiteSpace(opts.OfflineRestoreTarget))
                rollbackOk = BackupService.OfflineRestore(opts.RollbackDirectory, opts.OfflineRestoreTarget);
            else
                rollbackOk = BackupService.RestoreSnapshot(opts.RollbackDirectory);
            return rollbackOk ? ExitCode.Success : ExitCode.RegistryError;
        }

        // 4. Check BitLocker - SID change can trigger recovery mode
        if (!opts.IsBackgroundService)
        {
            string bitlockerWarning = CheckBitLocker();
            if (bitlockerWarning != null)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine();
                Console.WriteLine("  *** BitLocker is active! SID change cannot proceed. ***");
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine(bitlockerWarning);
                Console.WriteLine();
                Console.WriteLine("  SID change modifies registry hives which BitLocker/TPM will");
                Console.WriteLine("  detect as tampering, locking you out with a recovery key prompt.");
                Console.WriteLine("  Please disable BitLocker before running EASYSID.");
                Console.ResetColor();
                return ExitCode.InvalidArguments;
            }
        }

        // 5. Check for another instance already running
        if (IsAnotherInstanceRunning())
        {
            Console.Error.WriteLine("Do not interrupt SID change in process!");
            return ExitCode.AlreadyRunning;
        }

        // 5. Resolve Windows directory
        string winDir = string.IsNullOrEmpty(opts.OfflineWindowsPath)
            ? Environment.GetFolderPath(Environment.SpecialFolder.Windows)
            : opts.OfflineWindowsPath;

        if (!Directory.Exists(winDir))
        {
            Console.Error.WriteLine($"Invalid Windows directory {winDir}");
            return ExitCode.InvalidWindowsDirectory;
        }

        // 6. Read current SID
        string currentSid = SidReadService.GetCurrentMachineSid();
        if (currentSid == null)
        {
            Console.Error.WriteLine("Failed to read current machine SID.");
            return ExitCode.FailedToChangeSid;
        }

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"Current SID: {currentSid}");

        // 6b. Detect domain membership and warn about consequences
        var domainInfo = DetectDomainMembership();
        if (domainInfo.IsDomainJoined && !opts.NameOnly)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine();
            Console.WriteLine("  *** WARNING: This machine is joined to a domain! ***");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"  Domain:    {domainInfo.DomainName}");
            Console.WriteLine($"  DC:        {domainInfo.DomainController ?? "(not reachable)"}");
            Console.WriteLine();
            Console.WriteLine("  SID change on a domain-joined machine will:");
            Console.WriteLine("    - Break domain trust relationship (Kerberos/NTLM auth failure)");
            Console.WriteLine("    - Prevent domain logon until machine is re-joined");
            Console.WriteLine("    - Invalidate all Group Policy assignments");
            Console.WriteLine("    - Reset WSUS reporting history");
            Console.WriteLine("    - Require re-join to domain: Remove from domain -> Reboot -> Re-join");
            Console.WriteLine();
            Console.WriteLine("  Recommended: Remove machine from domain BEFORE changing SID,");
            Console.WriteLine("  then re-join after reboot with the new identity.");
            Console.ForegroundColor = origColor;

            if (!opts.Force)
            {
                Console.Write("\n  Continue anyway? (Y/N): ");
                string domainAnswer = Console.ReadLine();
                if (!string.Equals(domainAnswer?.Trim(), "Y", StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine("  Aborted. Remove from domain first, then run EASYSID.");
                    return ExitCode.Success;
                }
            }
            else
            {
                Console.WriteLine("  /F flag set - continuing despite domain membership.");
            }
        }

        // 7. Determine new SID
        // If the user explicitly set a SID, use it now.
        // If random (default), defer generation to Phase 2 so each imaged machine gets a unique SID.
        string newSid;
        if (opts.NameOnly)
            newSid = currentSid;
        else if (opts.SidExplicitlySet && !string.IsNullOrEmpty(opts.NewSid))
            newSid = opts.NewSid;
        else if (opts.IsBackgroundService)
            newSid = SidOperations.GenerateRandomSid(); // Phase 2: generate now
        else
            newSid = null; // Phase 1: defer to Phase 2

        Console.ForegroundColor = ConsoleColor.Gray;
        Console.WriteLine($"New SID:     {newSid ?? "(Random - will be generated at next boot)"}");


        Console.ForegroundColor = origColor;
        // 8. Determine new computer name
        string currentName = Environment.MachineName;
        string newName = ComputerNameService.ResolveNewComputerName(opts.ComputerName, currentName);
        if (newName != null)
            Console.WriteLine($"New Name:    {newName}");

        // 9. Confirm (unless /F)
        if (!opts.Force)
        {
            Console.WriteLine();
            Console.Write("To assure correct change of SID, current user will be logged off. Continue? (Y/N): ");
            string answer = Console.ReadLine();
            if (!string.Equals(answer?.Trim(), "Y", StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine("Aborted.");
                return ExitCode.Success;
            }
        }

        // 10. If not running as a background service, install a service and log off.
        if (!opts.IsBackgroundService)
        {
            Console.WriteLine("[*] Foreground mode: scheduling background task...");
            if (opts.NameOnly) Console.WriteLine("  /NS flag: SID change will be skipped, name-only mode.");

            // Build args from current options (not raw command line).
            // This ensures interactively chosen values (SID, name, etc.)
            // are passed to Phase 2 instead of being regenerated randomly.
            string[] rawArgs = BuildArgsFromOptions(opts);
            Console.WriteLine($"  Original args: {string.Join(" ", rawArgs)}");

            string phase2LogPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                "Temp", "EASYSID_EASYSID.log");
            Console.WriteLine($"  Phase 2 log will be at: {phase2LogPath}");

            bool svcOk = BackgroundTaskService.InstallAndStartBackgroundService(rawArgs, opts.Force, opts.Reboot);
            if (!svcOk)
                Console.Error.WriteLine("[ERROR] Failed to schedule background task. Aborting.");
            return ExitCode.Success;
        }

        // 10b. Running as background task (SYSTEM context).
        string logPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "Temp", $"EASYSID_{opts.BackgroundServiceName ?? "bg"}.log");

        using var logWriter = new WinLogonService.WinLogonProgressWriter(logPath);
        var origOut = Console.Out;
        var origErr = Console.Error;
        Console.SetOut(logWriter);
        Console.SetError(logWriter);

        Console.WriteLine($"[EASYSID background] Started at {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        Console.WriteLine($"[EASYSID background] Log: {logPath}");
        Console.WriteLine($"[EASYSID background] Old SID: {currentSid}");
        Console.WriteLine($"[EASYSID background] New SID: {newSid}");

        // Prevent startup-loop if this run crashes before final cleanup.
        if (!string.IsNullOrEmpty(opts.BackgroundServiceName))
            BackgroundTaskService.DisableScheduledTask(opts.BackgroundServiceName);

        bool success = true;

        try
        {
            if (!opts.SkipBackup)
            {
                if (!BackupService.CreateSnapshot(opts.BackupDirectory, currentSid, newSid, newName, out string snapshotDir))
                {
                    Console.WriteLine("  >> Snapshot creation: FAILED");
                    success = false;
                    throw new InvalidOperationException("Pre-change snapshot failed; SID change aborted.");
                }
                Console.WriteLine($"  >> Snapshot creation: OK ({snapshotDir})");
            }
            else
            {
                Console.WriteLine("  >> Snapshot creation: SKIPPED (/NOBACKUP flag)");
            }

            // Disable interfering components before making registry changes
            SystemProtectionService.StopUcpdDriver();
            SystemProtectionService.DisableWindowsDefender();

            bool stepOk;

            if (!opts.NameOnly)
            {
                stepOk = SidChangeService.ChangeSidInRegistry(currentSid, newSid, winDir);
                Console.WriteLine($"  >> ChangeSidInRegistry: {(stepOk ? "OK" : "FAILED")}");
                success = stepOk && success;
            }
            else
            {
                Console.WriteLine("  >> ChangeSidInRegistry: SKIPPED (/NS flag)");
            }

            if (newName != null && !string.IsNullOrEmpty(newName))
            {
                stepOk = ComputerNameService.ChangeComputerName(newName, opts.ComputerDescription, winDir);
                Console.WriteLine($"  >> ChangeComputerName: {(stepOk ? "OK" : "FAILED")}");
                success = stepOk && success;
            }

            if (!opts.SkipMachineGuid)
            {
                stepOk = IdentityResetService.ResetMachineGuid(winDir);
                Console.WriteLine($"  >> ResetMachineGuid: {(stepOk ? "OK" : "FAILED")}");
                success = stepOk && success;
            }
            else Console.WriteLine("  >> ResetMachineGuid: SKIPPED (/NMG flag)");

            if (!opts.SkipMachineId)
            {
                stepOk = IdentityResetService.ResetMachineId(winDir);
                Console.WriteLine($"  >> ResetMachineId: {(stepOk ? "OK" : "FAILED")}");
                success = stepOk && success;
            }
            else Console.WriteLine("  >> ResetMachineId: SKIPPED (/NMID flag)");

            if (!opts.SkipWsus)
            {
                stepOk = IdentityResetService.ResetWsusId(winDir);
                Console.WriteLine($"  >> ResetWsusId: {(stepOk ? "OK" : "FAILED")}");
                success = stepOk && success;
            }
            else Console.WriteLine("  >> ResetWsusId: SKIPPED (/NW flag)");

            if (!opts.SkipMsdtcCid)
            {
                stepOk = IdentityResetService.ResetMsdtcCid(winDir);
                Console.WriteLine($"  >> ResetMsdtcCid: {(stepOk ? "OK" : "FAILED")}");
                success = stepOk && success;
            }
            else Console.WriteLine("  >> ResetMsdtcCid: SKIPPED (/NCID flag)");

            if (!opts.SkipDeviceId)
            {
                stepOk = IdentityResetService.ResetDeviceId(winDir);
                Console.WriteLine($"  >> ResetDeviceId: {(stepOk ? "OK" : "FAILED")}");
                success = stepOk && success;
            }
            else Console.WriteLine("  >> ResetDeviceId: SKIPPED (/NDI flag)");

            if (!opts.SkipDhcpDuid)
            {
                stepOk = IdentityResetService.ResetDhcpDuid(winDir);
                Console.WriteLine($"  >> ResetDhcpDuid: {(stepOk ? "OK" : "FAILED")}");
                success = stepOk && success;
            }
            else Console.WriteLine("  >> ResetDhcpDuid: SKIPPED (/NDUID flag)");

            // Clear icon/thumbnail caches and shell bags
            CacheCleanupService.ClearIconAndShellCaches(winDir);
            Console.WriteLine("  >> ClearIconAndShellCaches: OK");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERROR] {ex}");
            success = false;
        }
        finally
        {
            // Restore UCPD driver to automatic start
            SystemProtectionService.RestoreUcpdDriver();

            // Restore AutoLogon that was disabled before the task was scheduled
            WinLogonService.RestoreAutoLogon();

            // Delete the scheduled task so it doesn't run again on next boot
            if (!string.IsNullOrEmpty(opts.BackgroundServiceName))
                BackgroundTaskService.DeleteScheduledTask(opts.BackgroundServiceName);

            // Also clean up any orphan EASYSID* tasks from previous runs
            BackgroundTaskService.CleanupOrphanEASYSIDTasks();

            Console.WriteLine($"[EASYSID background] Finished at {DateTime.Now:yyyy-MM-dd HH:mm:ss}. Success={success}");

            // Restore Console before clearing the logon notice
            Console.SetOut(origOut);
            Console.SetError(origErr);

            // Clear the WinLogon notice
            WinLogonService.ClearWinLogonNotice();
        }

        if (!success)
            return ExitCode.FailedToChangeSid;

        Console.WriteLine("SID change completed successfully.");

        // Self-delete: schedule just before reboot/shutdown
        BackgroundTaskService.ScheduleSelfDelete();

        // 11. Schedule a cleanup task that runs at next boot to clear WinLogon
        // notices in case reboot fails and user has to force-shutdown.
        // This task just runs: EASYSID /CLEARNOTICE and deletes itself.
        ScheduleBootCleanup();

        // 12. Reboot or shutdown
        if (opts.Reboot || opts.Shutdown)
        {
            string reason = opts.Reboot
                ? "EASYSID: SID change complete. Rebooting..."
                : "EASYSID: SID change complete. Shutting down...";
            ShutdownService.ForceSystemRestart(opts.Reboot, reason);
        }

        return ExitCode.Success;
    }

    // -----------------------------------------------------------------------
    // Boot cleanup safety net
    // -----------------------------------------------------------------------

    /// <summary>
    /// Creates a one-shot boot task that clears WinLogon notices and deletes itself.
    /// Safety net: if reboot fails and user force-shuts down, the next boot
    /// will still clean up the "SID Change in Progress" login screen message.
    /// </summary>
    private static void ScheduleBootCleanup()
    {
        try
        {
            string exePath = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName;
            if (string.IsNullOrEmpty(exePath)) return;

            const string taskName = "EASYSID_CLEANUP";

            string xml = $@"<?xml version=""1.0"" encoding=""UTF-16""?>
<Task version=""1.4"" xmlns=""http://schemas.microsoft.com/windows/2004/02/mit/task"">
  <Triggers>
    <BootTrigger><Enabled>true</Enabled><Delay>PT10S</Delay></BootTrigger>
    <LogonTrigger><Enabled>true</Enabled><Delay>PT5S</Delay></LogonTrigger>
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
    <DeleteExpiredTaskAfter>PT1M</DeleteExpiredTaskAfter>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>
  </Settings>
  <Actions Context=""Author"">
    <Exec>
      <Command>""{exePath}""</Command>
      <Arguments>/CLEARNOTICE</Arguments>
    </Exec>
  </Actions>
</Task>";

            string xmlPath = Path.Combine(Path.GetTempPath(), "EASYSID_cleanup.xml");
            File.WriteAllText(xmlPath, xml, System.Text.Encoding.Unicode);
            ProcessRunner.RunHiddenProcess("schtasks.exe", $"/Create /TN \"{taskName}\" /XML \"{xmlPath}\" /F");
            try { File.Delete(xmlPath); } catch { }

            Console.WriteLine("  Boot cleanup task scheduled (safety net for WinLogon notice).");
        }
        catch { }
    }

    // -----------------------------------------------------------------------
    // Cancel pending SID change
    // -----------------------------------------------------------------------

    private static void CancelPendingSidChange()
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("[*] Cancelling pending SID change...");
        Console.ResetColor();

        // 1. Delete all EASYSID scheduled tasks
        Console.WriteLine("  Removing scheduled tasks...");
        BackgroundTaskService.CleanupOrphanEASYSIDTasks();
        BackgroundTaskService.DeleteScheduledTask("EASYSID");
        BackgroundTaskService.DeleteScheduledTask("EASYSID_ROLLBACK");
        BackgroundTaskService.DeleteScheduledTask("EASYSID_CLEANUP");
        BackgroundTaskService.DeleteScheduledTask("EASYSID_FIXBROWSERKEYS");

        // 2. Clear WinLogon notices (login screen messages)
        Console.WriteLine("  Clearing WinLogon notices...");
        WinLogonService.ClearWinLogonNotice();

        // 3. Restore AutoLogon if it was disabled
        Console.WriteLine("  Restoring AutoLogon...");
        WinLogonService.RestoreAutoLogon();

        // 4. Restore WinLogon settings (ForceAutoLogon, DisableCAD, etc.)
        Console.WriteLine("  Restoring WinLogon settings...");
        WinLogonService.RestoreWinLogonSettings();

        // 5. Restore UCPD driver if it was disabled
        Console.WriteLine("  Restoring UCPD driver...");
        SystemProtectionService.RestoreUcpdDriver();

        // 6. Clean up temp files
        Console.WriteLine("  Cleaning up temp files...");
        try
        {
            string tempDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp");
            foreach (string f in Directory.GetFiles(tempDir, "EASYSID_*.log"))
            {
                try { File.Delete(f); Console.WriteLine($"    Deleted: {Path.GetFileName(f)}"); }
                catch { }
            }
            foreach (string f in Directory.GetFiles(tempDir, "EASYSID_task_*.xml"))
            {
                try { File.Delete(f); Console.WriteLine($"    Deleted: {Path.GetFileName(f)}"); }
                catch { }
            }
        }
        catch { }

        // 7. Abort any pending system shutdown
        Console.WriteLine("  Aborting pending shutdown...");
        try { NativeImports.AbortSystemShutdown(null); }
        catch { }

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("\n[*] Cancel complete. System restored to pre-EASYSID state.");
        Console.ResetColor();
        Console.WriteLine("    All scheduled tasks removed.");
        Console.WriteLine("    WinLogon notices cleared.");
        Console.WriteLine("    AutoLogon settings restored.");
        Console.WriteLine("    No reboot required.");
    }

    // -----------------------------------------------------------------------
    // Interactive setup (no arguments)
    // -----------------------------------------------------------------------

    private static Options InteractiveSetup()
    {
        var opts = new Options();
        Console.WriteLine();

        // Show current machine info
        string currentSid = SidReadService.GetCurrentMachineSid();
        string currentName = Environment.MachineName;

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"  Machine:     {currentName}");
        Console.WriteLine($"  Current SID: {currentSid ?? "(could not read)"}");
        Console.ResetColor();
        Console.WriteLine();

        // 1. Ask to continue
        Console.Write("Start SID change? (Y/N): ");
        string answer = Console.ReadLine();
        if (!string.Equals(answer?.Trim(), "Y", StringComparison.OrdinalIgnoreCase))
        {
            PrintUsage();
            return null;
        }

        // 2. Computer name
        Console.WriteLine();
        Console.Write($"New computer name (Enter=keep '{currentName}', ?=random PC-XXXXXX): ");
        string nameInput = Console.ReadLine()?.Trim();
        if (!string.IsNullOrEmpty(nameInput))
            opts.ComputerName = nameInput;

        // 3. SID
        Console.Write("New SID (Enter=random, unique per machine): ");
        string sidInput = Console.ReadLine()?.Trim();
        if (!string.IsNullOrEmpty(sidInput))
        {
            opts.NewSid = sidInput;
            opts.SidExplicitlySet = true;
        }

        // If user specified a SID, use it. Otherwise show "Random" — actual
        // generation is deferred to Phase 2 so each imaged machine gets a unique SID.
        string newSidDisplay = opts.SidExplicitlySet
            ? opts.NewSid
            : "(Random - unique per machine)";

        // Resolve the new computer name
        string newName = ComputerNameService.ResolveNewComputerName(opts.ComputerName, currentName);

        // 3b. Browser warning
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("  NOTE: The following will be reset after SID change:");
        Console.WriteLine("    - Default apps (Chrome as default browser, PDF reader, etc.)");
        Console.WriteLine("    - Chrome/Edge profiles (saved passwords, cookies, auto-fill)");
        Console.WriteLine("  These are bound to Windows SID via DPAPI and UserChoice hashes.");
        Console.WriteLine("  After reboot: re-set default apps in Settings > Default Apps,");
        Console.WriteLine("  and enable Chrome/Edge Sync to restore browser data.");
        Console.ResetColor();

        // 4. Shutdown, Reboot, or Cancel
        Console.WriteLine();
        Console.WriteLine("After SID change, the system needs to restart.");
        Console.WriteLine("  [S] Shutdown  (for imaging - system powers off, Phase 2 runs at next boot)");
        Console.WriteLine("  [R] Reboot    (direct - system restarts, Phase 2 runs immediately)");
        Console.WriteLine("  [C] Cancel    (abort - remove all pending tasks and restore settings)");
        Console.Write("Choice (S/R/C): ");
        string restartChoice = Console.ReadLine()?.Trim().ToUpperInvariant();

        if (restartChoice == "C")
        {
            CancelPendingSidChange();
            return null;
        }
        else if (restartChoice == "R")
            opts.Reboot = true;
        else
            opts.Shutdown = true;

        // 5. Summary - show current vs new side by side
        Console.WriteLine();
        Console.WriteLine("  " + new string('=', 60));
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"  Current SID:  {currentSid}");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"  New SID:      {newSidDisplay}");
        Console.ResetColor();
        Console.WriteLine("  " + new string('-', 60));
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"  Current Name: {currentName}");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"  New Name:     {newName ?? currentName}");
        Console.ResetColor();
        Console.WriteLine("  " + new string('-', 60));
        Console.WriteLine($"  After change: {(opts.Reboot ? "Reboot" : "Shutdown")}");
        Console.WriteLine("  " + new string('=', 60));
        Console.WriteLine();
        Console.Write("Proceed? (Y/N): ");
        string confirmAnswer = Console.ReadLine();
        if (!string.Equals(confirmAnswer?.Trim(), "Y", StringComparison.OrdinalIgnoreCase))
        {
            Console.WriteLine("Cancelled.");
            return null;
        }

        opts.Force = true; // don't ask again in Run()
        return opts;
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// <summary>
    /// Builds a command-line argument array from the current Options object.
    /// Only passes /SID= when the user explicitly specified one.
    /// When SID is random (default), Phase 2 generates its own unique SID
    /// so each imaged machine gets a different SID.
    /// </summary>
    private static string[] BuildArgsFromOptions(Options opts)
    {
        var args = new System.Collections.Generic.List<string>();
        if (opts.SidExplicitlySet && !string.IsNullOrEmpty(opts.NewSid) && !opts.NameOnly)
            args.Add($"/SID={opts.NewSid}");
        if (!string.IsNullOrEmpty(opts.ComputerName))
            args.Add($"/COMPNAME={opts.ComputerName}");
        if (!string.IsNullOrEmpty(opts.ComputerDescription))
            args.Add($"/COMPDESCR={opts.ComputerDescription}");
        if (opts.Force) args.Add("/F");
        if (opts.Reboot) args.Add("/R");
        if (opts.Shutdown) args.Add("/S");
        if (opts.NameOnly) args.Add("/NS");
        if (opts.SkipWsus) args.Add("/NW");
        if (opts.SkipMsdtcCid) args.Add("/NCID");
        if (opts.SkipDeviceId) args.Add("/NDI");
        if (opts.SkipMachineGuid) args.Add("/NMG");
        if (opts.SkipMachineId) args.Add("/NMID");
        if (opts.SkipDhcpDuid) args.Add("/NDUID");
        if (opts.SkipBackup) args.Add("/NOBACKUP");
        if (!string.IsNullOrEmpty(opts.BackupDirectory))
            args.Add($"/BACKUPDIR={opts.BackupDirectory}");
        if (!string.IsNullOrEmpty(opts.OfflineWindowsPath))
            args.Add($"/OS={opts.OfflineWindowsPath}");
        return args.ToArray();
    }

    /// <summary>
    /// Checks if BitLocker is active on any drive. Returns a warning message
    /// or null if BitLocker is not detected.
    /// </summary>
    private static string CheckBitLocker()
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo("manage-bde.exe", "-status")
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
            };
            using var p = System.Diagnostics.Process.Start(psi);
            if (p == null) return null;
            string output = p.StandardOutput.ReadToEnd();
            p.WaitForExit(5000);

            // Parse output for encrypted volumes
            var encrypted = new System.Collections.Generic.List<string>();
            string currentVolume = null;
            foreach (string line in output.Split('\n'))
            {
                string trimmed = line.Trim();
                // "Volume C:" or "Birim C:" (Turkish)
                if (trimmed.Contains(":") && (trimmed.StartsWith("Volume") || trimmed.StartsWith("Birim")))
                    currentVolume = trimmed;
                // "Protection Status:    Protection On" or "Koruma Durumu:    Koruma Açık"
                if (currentVolume != null &&
                    (trimmed.Contains("Protection On") || trimmed.Contains("Koruma A")))
                {
                    encrypted.Add(currentVolume);
                    currentVolume = null;
                }
            }

            if (encrypted.Count == 0) return null;

            return "  Encrypted volumes: " + string.Join(", ", encrypted);
        }
        catch
        {
            return null; // manage-bde not found = no BitLocker
        }
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    private record DomainMembershipInfo(bool IsDomainJoined, string DomainName, string DomainController);

    private static DomainMembershipInfo DetectDomainMembership()
    {
        try
        {
            // Check via registry: HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Domain
            using var tcpip = RegistryHelper.OpenRegKey(Microsoft.Win32.RegistryHive.LocalMachine,
                @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters");
            string domain = tcpip?.GetValue("Domain") as string;

            // Also check: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History\DCName
            string dc = null;
            try
            {
                using var gpKey = RegistryHelper.OpenRegKey(Microsoft.Win32.RegistryHive.LocalMachine,
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History");
                dc = gpKey?.GetValue("DCName") as string;
            }
            catch { }

            // Check if WORKGROUP vs actual domain via
            // HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\NV Domain
            // or Environment.UserDomainName
            bool isWorkgroup = string.IsNullOrWhiteSpace(domain) ||
                               domain.Equals("WORKGROUP", StringComparison.OrdinalIgnoreCase) ||
                               domain.Equals(Environment.MachineName, StringComparison.OrdinalIgnoreCase);

            // Additional check: $MACHINE.ACC secret exists = domain joined
            if (isWorkgroup)
            {
                try
                {
                    using var secrets = RegistryHelper.OpenRegKey(Microsoft.Win32.RegistryHive.LocalMachine,
                        @"SECURITY\Policy\Secrets\$MACHINE.ACC");
                    if (secrets != null) isWorkgroup = false; // has machine account = domain joined
                }
                catch { }
            }

            return new DomainMembershipInfo(!isWorkgroup, domain ?? "", dc);
        }
        catch
        {
            return new DomainMembershipInfo(false, "", null);
        }
    }

    private static bool IsAnotherInstanceRunning()
    {
        string currentExe = Path.GetFileNameWithoutExtension(
            Process.GetCurrentProcess().MainModule?.FileName ?? "EASYSID");
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                if (p.Id == Process.GetCurrentProcess().Id) continue;
                string name = p.ProcessName;
                if (string.Equals(name, currentExe, StringComparison.OrdinalIgnoreCase) ||
                    name.StartsWith("EASYSID", StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            catch { /* access denied for some processes */ }
        }
        return false;
    }

    // -----------------------------------------------------------------------
    // Command-line entry point
    // -----------------------------------------------------------------------

    public static int Main(string[] args)
    {
        var origColor = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Blue;
        Console.WriteLine("EASYSID - SID CHANGING UTILITY");
        Console.ForegroundColor = ConsoleColor.DarkYellow;
        Console.WriteLine("Recovery snapshot is enabled by default. Use /NOBACKUP to disable.");
        Console.ForegroundColor = origColor;

        Options opts;

        if (args.Length == 0)
        {
            // Interactive mode: no arguments, ask user what to do
            opts = InteractiveSetup();
            if (opts == null)
                return (int)ExitCode.Success; // user cancelled
        }
        else
        {
            opts = ParseArgs(args);
            if (opts == null)
            {
                PrintUsage();
                return (int)ExitCode.InvalidArguments;
            }
        }

        int result = (int)Run(opts);
        Console.WriteLine($"\nExit code: {result}");
        return result;
    }

    private static Options ParseArgs(string[] args)
    {
        var opts = new Options();
        foreach (string arg in args)
        {
            string upper = arg.ToUpperInvariant();
            if (upper == "/F")        { opts.Force = true; continue; }
            if (upper == "/R")        { opts.Reboot = true; continue; }
            if (upper == "/CLEARNOTICE") { opts.ClearNotice = true; continue; }
            if (upper == "/LIST")      { opts.ListSnapshots = true; continue; }
            if (upper == "/CANCEL")    { opts.Cancel = true; continue; }
            if (upper == "/S")        { opts.Shutdown = true; continue; }
            if (upper == "/NS")       { opts.NameOnly = true; continue; }
            if (upper == "/NW")       { opts.SkipWsus = true; continue; }
            if (upper == "/NCID")     { opts.SkipMsdtcCid = true; continue; }
            if (upper == "/NDI")      { opts.SkipDeviceId = true; continue; }
            if (upper == "/NMG")      { opts.SkipMachineGuid = true; continue; }
            if (upper == "/NMID")     { opts.SkipMachineId = true; continue; }
            if (upper == "/NDUID")    { opts.SkipDhcpDuid = true; continue; }
            if (upper == "/NOBACKUP") { opts.SkipBackup = true; continue; }

            if (upper.StartsWith("/COMPNAME="))
            {
                opts.ComputerName = arg.Substring("/COMPNAME=".Length);
                continue;
            }
            if (upper.StartsWith("/COMPDESCR="))
            {
                opts.ComputerDescription = arg.Substring("/COMPDESCR=".Length);
                continue;
            }
            if (upper.StartsWith("/SID="))
            {
                opts.NewSid = arg.Substring("/SID=".Length);
                opts.SidExplicitlySet = true;
                continue;
            }
            if (upper.StartsWith("/OS="))
            {
                opts.OfflineWindowsPath = arg.Substring("/OS=".Length);
                continue;
            }
            if (upper.StartsWith("/BACKUPDIR="))
            {
                opts.BackupDirectory = arg.Substring("/BACKUPDIR=".Length);
                continue;
            }
            if (upper.StartsWith("/ROLLBACK="))
            {
                opts.RollbackDirectory = arg.Substring("/ROLLBACK=".Length);
                opts.Force = true;
                continue;
            }
            if (upper.StartsWith("/OFFLINE="))
            {
                opts.OfflineRestoreTarget = arg.Substring("/OFFLINE=".Length);
                continue;
            }
            if (upper.StartsWith("/EASYSIDSERVICE="))
            {
                opts.IsBackgroundService = true;
                opts.BackgroundServiceName = arg.Substring("/EASYSIDSERVICE=".Length);
                opts.Force = true;
                continue;
            }

            if (upper == "/POSTPROCESSING" || upper.StartsWith("/POSTPROCESSING"))
                continue;

            Console.Error.WriteLine($"Unknown argument: {arg}");
            return null;
        }
        return opts;
    }

    private static void PrintUsage()
    {
        Console.WriteLine(@"
Usage: EASYSID [options]

Computer Configuration:
  /COMPNAME=<name>   New computer name (? = random PC-XXXXXX)
  /COMPDESCR=<desc>  New computer description
  /F                 Omit confirmation prompt
  /R                 Reboot after SID change
  /S                 Shut down after SID change

SID Operations:
  /NS                Change only computer name, not SID
  /SID=<sid>         Set specific new SID value (default: random)
  /OS=<path>         Target offline Windows installation (e.g. D:\Windows)

Selective Changes:
  /NW                Skip WSUS ID change
  /NCID              Skip MSDTC CID reset
  /NDI               Skip Device ID reset
  /NMG               Skip MachineGuid reset
  /NMID              Skip Machine ID reset
  /NDUID             Skip Dhcpv6 DUID reset
  /NOBACKUP          Skip automatic snapshot before SID change

Maintenance:
  /CANCEL            Cancel pending SID change (remove tasks, restore settings)
  /CLEARNOTICE       Clear WinLogon notice messages and exit
  /BACKUPDIR=<path>  Custom snapshot root (default: C:\ProgramData\EASYSID\Backups)
  /ROLLBACK=<path>   Restore from an existing snapshot directory
  /OFFLINE=<drive>   WinPE offline restore target (use with /ROLLBACK)
  /LIST              List all available snapshots

Examples:
  EASYSID /F /R                          Change SID, force, reboot
  EASYSID /COMPNAME=MYPC /F              Change name only prompt-free
  EASYSID /SID=S-1-5-21-1-2-3 /F /R     Set specific SID and reboot
  EASYSID /ROLLBACK=C:\ProgramData\EASYSID\Backups\20260305_101500
  EASYSID /ROLLBACK=D:\ProgramData\EASYSID\Backups\20260305_101500 /OFFLINE=D:
  EASYSID /LIST
");
    }
}
