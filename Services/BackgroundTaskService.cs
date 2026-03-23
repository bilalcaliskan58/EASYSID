using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

namespace EASYSID;

/// <summary>
/// Manages the background service/task lifecycle: scheduling Phase 2 via Task Scheduler,
/// cleanup of orphan tasks, task deletion/disabling, and self-deletion.
/// </summary>
internal static class BackgroundTaskService
{
    /// <summary>
    /// Schedules the SID change to run as SYSTEM via Task Scheduler after logoff,
    /// then logs the current user off.
    ///
    /// A Windows service requires ServiceMain/StartServiceCtrlDispatcher which our
    /// exe does not implement, so SCM refuses to start it (error 1053). Instead we
    /// use schtasks to register a one-shot task that runs at next system startup
    /// under SYSTEM account, then trigger an immediate logoff.
    ///
    /// Task is named EASYSID (fixed), set to run at startup, delete on completion.
    /// </summary>
    internal static bool InstallAndStartBackgroundService(string[] originalArgs, bool isForced = false, bool rebootInsteadOfShutdown = false)
    {
        // Fixed task name  -  ensures repeated runs overwrite the same task
        // instead of creating multiple orphan tasks (EASYSID1700000001, EASYSID1700000002, etc.)
        const string taskName = "EASYSID";

        // Clean up any orphan EASYSID* tasks from previous runs (including old timestamp-based names)
        Console.WriteLine("[*] Cleaning up previous EASYSID scheduled tasks...");
        CleanupOrphanEASYSIDTasks();

        string sourceExe = Process.GetCurrentProcess().MainModule?.FileName
                           ?? Path.Combine(AppContext.BaseDirectory, "EASYSID.exe");

        // Copy exe to C:\Windows\Temp so Phase 2 works even if the original
        // location is a flash drive, network share, or removable media.
        string localExe = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "Temp", "EASYSID.exe");

        try
        {
            File.Copy(sourceExe, localExe, true);
            Console.WriteLine($"[*] Copied exe to: {localExe}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[*] Could not copy exe to {localExe}: {ex.Message}");
            Console.Error.WriteLine("    Phase 2 will use original path (must be accessible at boot).");
            localExe = sourceExe;
        }

        string exePath = localExe;

        // Build argument list
        var argList = new StringBuilder();
        argList.Append($"/EASYSIDSERVICE={taskName} /F");
        foreach (string arg in originalArgs)
        {
            string u = arg.ToUpperInvariant();
            if (u == "/R" || u == "/S") continue;
            argList.Append($" \"{arg}\"");
        }
        argList.Append(" /R");

        string taskArgs = argList.ToString();

        Console.WriteLine($"[*] Scheduling background task: {taskName}");
        Console.WriteLine($"    Exe:  {exePath}");
        Console.WriteLine($"    Args: {taskArgs}");

        // Stop UCPD driver now (before reboot) so it cannot interfere on next boot startup
        SystemProtectionService.StopUcpdDriver();

        // Disable Windows Defender real-time protection before reboot so it doesn't interfere
        SystemProtectionService.DisableWindowsDefender();

        // Clear any existing logon notices before touching AutoLogon backup keys.
        // This avoids deleting the fresh AutoAdminLogon-EASYSID-sav created below.
        WinLogonService.ClearWinLogonNotice();

        // Disable AutoLogon for the next boot so the SID change task runs
        // before any user session starts. Restored by the background task when done.
        WinLogonService.DisableAutoLogon();

        // Set WinLogon notice BEFORE shutdown so it shows on the login screen after reboot.
        // This blocks user login until Phase 2 completes (when ClearWinLogonNotice is called).
        WinLogonService.SetWinLogonNotice(
            "SID CHANGE IN PROGRESS",
            "Do not interfere while the process is ongoing.\n Please wait until your computer restarts. \n It may look inviting, but absolutely do not press the OK button, as this may interrupt the SID information change process.");

        // Schedule as a boot-triggered one-shot task via plain schtasks (/SC ONSTART).
        bool taskCreated = TryCreateTaskPlain(taskName, exePath, taskArgs);

        if (!taskCreated)
        {
            Console.Error.WriteLine("  schtasks create failed.");
            WinLogonService.RestoreAutoLogon();
            WinLogonService.ClearWinLogonNotice();
            return false;
        }

        // Phase 2 runs at next boot.
        string action = rebootInsteadOfShutdown ? "reboot" : "shutdown";
        Console.WriteLine();
        Console.WriteLine("  Task scheduled successfully.");
        Console.WriteLine($"  The system needs to {action} for the SID change to complete.");
        Console.WriteLine("  Phase 2 will run automatically at next boot.");
        Console.WriteLine();

        if (!isForced)
        {
            Console.Write($"  {(rebootInsteadOfShutdown ? "Reboot" : "Shut down")} now? (Y/N): ");
            string answer = Console.ReadLine();
            if (!string.Equals(answer?.Trim(), "Y", StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine($"  Postponed. Please {action} manually before next use.");
                Console.WriteLine("  The SID change task will run at next boot.");
                return true;
            }
        }
        else
        {
            Console.WriteLine($"  /F flag set - {action} in 5 seconds...");
            System.Threading.Thread.Sleep(5000);
        }

        string reason = rebootInsteadOfShutdown
            ? "EASYSID: Phase 1 complete. Rebooting for Phase 2 (SID change)..."
            : "EASYSID: Phase 1 complete. Shutting down for imaging. Phase 2 runs at next boot.";
        ShutdownService.ForceSystemRestart(rebootInsteadOfShutdown, reason);

        return true;
    }

    /// <summary>
    /// Creates the scheduled task using XML-first approach with schtasks fallback.
    /// </summary>
    private static bool TryCreateTaskPlain(string taskName, string exePath,
                                           string taskArgs)
    {
        // Primary method: create task via XML file.
        // This is more reliable than schtasks flags because:
        //   - Battery settings (DisallowStartIfOnBatteries) are set directly in XML
        //   - No PowerShell dependency for post-creation patching
        //   - All settings applied atomically in one call
        if (TryCreateTaskViaXml(taskName, exePath, taskArgs))
            return true;

        Console.WriteLine("  XML method failed, falling back to schtasks...");

        // Fallback: plain schtasks (battery restriction may remain)
        try
        {
            string args = $"/Create /TN \"{taskName}\" " +
                          $"/TR \"\\\"{exePath}\\\" {taskArgs}\" " +
                          $"/SC ONSTART /DELAY 0000:05 " +
                          $"/RL HIGHEST /RU SYSTEM /F";
            var psi = new ProcessStartInfo("schtasks.exe", args)
            {
                UseShellExecute        = false,
                CreateNoWindow         = true,
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
            };
            using var p = Process.Start(psi)!;
            // Read stderr async to prevent deadlock
            string stderr = null;
            p.ErrorDataReceived += (_, e) => { if (e.Data != null) stderr = (stderr ?? "") + e.Data + "\n"; };
            p.BeginErrorReadLine();
            string stdout = p.StandardOutput.ReadToEnd();
            p.WaitForExit(15000);
            if (p.ExitCode != 0)
            {
                Console.WriteLine($"  schtasks fallback failed (exit {p.ExitCode}): {stderr?.Trim()}");
                return false;
            }
            Console.WriteLine("  Task created via schtasks fallback (battery restriction may apply).");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  schtasks fallback exception: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Creates the scheduled task using a Task Scheduler XML definition file.
    /// This method sets ALL task properties in one atomic operation:
    ///   - Boot trigger with 5-second delay
    ///   - SYSTEM account, highest privileges
    ///   - Battery: allowed on battery, don't stop on battery
    ///   - Network: no requirement
    ///   - Idle: no requirement
    ///   - Hidden: yes
    ///   - Execution time limit: 2 hours
    ///   - Allow start on demand
    /// </summary>
    private static bool TryCreateTaskViaXml(string taskName, string exePath, string taskArgs)
    {
        try
        {
            // Build the XML task definition
            // Command and Arguments must be separate in the XML
            string xmlContent = $@"<?xml version=""1.0"" encoding=""UTF-16""?>
<Task version=""1.4"" xmlns=""http://schemas.microsoft.com/windows/2004/02/mit/task"">
  <RegistrationInfo>
    <Description>EASYSID SID Change - Phase 2</Description>
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
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
    <WakeToRun>true</WakeToRun>
    <ExecutionTimeLimit>PT2H</ExecutionTimeLimit>
    <Priority>4</Priority>
  </Settings>
  <Actions Context=""Author"">
    <Exec>
      <Command>""{exePath}""</Command>
      <Arguments>{System.Security.SecurityElement.Escape(taskArgs)}</Arguments>
    </Exec>
  </Actions>
</Task>";

            // Write XML to a temp file
            string xmlPath = Path.Combine(Path.GetTempPath(), $"EASYSID_task_{taskName}.xml");
            File.WriteAllText(xmlPath, xmlContent, Encoding.Unicode);

            try
            {
                // Import the XML task definition
                string args = $"/Create /TN \"{taskName}\" /XML \"{xmlPath}\" /F";
                var psi = new ProcessStartInfo("schtasks.exe", args)
                {
                    UseShellExecute        = false,
                    CreateNoWindow         = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError  = true,
                };
                using var p = Process.Start(psi)!;
                string stderr = null;
                p.ErrorDataReceived += (_, e) => { if (e.Data != null) stderr = (stderr ?? "") + e.Data + "\n"; };
                p.BeginErrorReadLine();
                string stdout = p.StandardOutput.ReadToEnd();
                p.WaitForExit(15000);

                if (p.ExitCode != 0)
                {
                    Console.WriteLine($"  XML import failed (exit {p.ExitCode}): {stderr?.Trim()}");
                    return false;
                }

                Console.WriteLine("  Task created via XML (battery+idle restrictions disabled).");
                return true;
            }
            finally
            {
                try { File.Delete(xmlPath); } catch { }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  XML method exception: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Deletes a scheduled task by name using schtasks.exe.
    /// </summary>
    internal static void DeleteScheduledTask(string taskName)
    {
        Console.WriteLine($"[*] Deleting scheduled task '{taskName}'...");
        try
        {
            var psi = new ProcessStartInfo("schtasks.exe", $"/Delete /TN \"{taskName}\" /F")
            {
                UseShellExecute        = false,
                CreateNoWindow         = true,
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
            };
            using var p = Process.Start(psi);
            string stdout = p?.StandardOutput.ReadToEnd().Trim() ?? "";
            string stderr = p?.StandardError.ReadToEnd().Trim() ?? "";
            p?.WaitForExit(5000);
            int exitCode = p?.ExitCode ?? -1;
            if (exitCode == 0)
                Console.WriteLine($"  Task '{taskName}' deleted successfully.");
            else
                Console.WriteLine($"  Task delete exit={exitCode}" +
                                  (string.IsNullOrEmpty(stderr) ? "" : $" | {stderr}") +
                                  (string.IsNullOrEmpty(stdout) ? "" : $" | {stdout}"));
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  Failed to delete task '{taskName}': {ex.Message}");
        }
    }

    /// <summary>
    /// Disables a scheduled task by name using schtasks.exe.
    /// </summary>
    internal static void DisableScheduledTask(string taskName)
    {
        Console.WriteLine($"[*] Disabling scheduled task '{taskName}'...");
        try
        {
            var psi = new ProcessStartInfo("schtasks.exe", $"/Change /TN \"{taskName}\" /Disable")
            {
                UseShellExecute        = false,
                CreateNoWindow         = true,
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
            };
            using var p = Process.Start(psi);
            string stdout = p?.StandardOutput.ReadToEnd().Trim() ?? "";
            string stderr = p?.StandardError.ReadToEnd().Trim() ?? "";
            p?.WaitForExit(5000);
            int exitCode = p?.ExitCode ?? -1;
            if (exitCode == 0)
                Console.WriteLine($"  Task '{taskName}' disabled.");
            else
                Console.WriteLine($"  Task disable exit={exitCode}" +
                                  (string.IsNullOrEmpty(stderr) ? "" : $" | {stderr}") +
                                  (string.IsNullOrEmpty(stdout) ? "" : $" | {stdout}"));
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  Failed to disable task '{taskName}': {ex.Message}");
        }
    }

    /// <summary>
    /// Finds and deletes ALL scheduled tasks whose name starts with "EASYSID".
    /// This cleans up orphan tasks from previous runs that used timestamp-based names
    /// (e.g. EASYSID1700000001) as well as the current fixed "EASYSID" task.
    /// </summary>
    internal static void CleanupOrphanEASYSIDTasks()
    {
        try
        {
            // Only query root-level tasks where EASYSID tasks live.
            // Avoids scanning OneDrive, Microsoft\Office and other third-party
            // task folders that can cause "task not found" or access errors.
            var psi = new ProcessStartInfo("schtasks.exe", "/Query /FO CSV /NH /TN \\")
            {
                UseShellExecute        = false,
                CreateNoWindow         = true,
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
            };
            using var p = Process.Start(psi);
            // Read stderr async to prevent deadlock
            string stderr = null;
            p.ErrorDataReceived += (_, e) => { if (e.Data != null) stderr = (stderr ?? "") + e.Data + "\n"; };
            p.BeginErrorReadLine();
            string output = p?.StandardOutput.ReadToEnd() ?? "";
            p?.WaitForExit(10000);

            // If root query failed (some Windows versions don't support /TN \),
            // fall back to full query but ignore errors
            if (p.ExitCode != 0 && string.IsNullOrWhiteSpace(output))
            {
                var psi2 = new ProcessStartInfo("schtasks.exe", "/Query /FO CSV /NH")
                {
                    UseShellExecute        = false,
                    CreateNoWindow         = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError  = true,
                };
                using var p2 = Process.Start(psi2);
                p2.ErrorDataReceived += (_, e) => { }; // swallow stderr
                p2.BeginErrorReadLine();
                output = p2?.StandardOutput.ReadToEnd() ?? "";
                p2?.WaitForExit(10000);
            }

            foreach (string line in output.Split('\n'))
            {
                string trimmed = line.Trim();
                if (string.IsNullOrEmpty(trimmed)) continue;

                int firstQuote = trimmed.IndexOf('"');
                int secondQuote = firstQuote >= 0 ? trimmed.IndexOf('"', firstQuote + 1) : -1;
                if (firstQuote < 0 || secondQuote < 0) continue;

                string taskPath = trimmed.Substring(firstQuote + 1, secondQuote - firstQuote - 1);
                int lastSlash = taskPath.LastIndexOf('\\');
                string tn = lastSlash >= 0 ? taskPath.Substring(lastSlash + 1) : taskPath;

                if (tn.StartsWith("EASYSID", StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine($"  Cleaning up orphan task: {tn}");
                    DeleteScheduledTask(tn);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  CleanupOrphanEASYSIDTasks: {ex.Message}");
        }
    }

    /// <summary>
    /// Schedules self-deletion of this executable after the process exits.
    /// Spawns a detached cmd.exe that waits a few seconds then deletes the file.
    /// Safe to call from the finally block  -  cmd runs after this process exits.
    /// </summary>
    internal static void ScheduleSelfDelete()
    {
        try
        {
            string exePath = Process.GetCurrentProcess().MainModule?.FileName;
            if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
            {
                Console.WriteLine("  ScheduleSelfDelete: exe path not found, skipping.");
                return;
            }

            // Use ping as a portable sleep (~3 seconds), then delete the exe.
            // /c ensures cmd exits after running the command.
            // start "" /B ensures cmd itself is detached and doesn't block.
            string cmdLine = $"/c ping 127.0.0.1 -n 4 >nul & del /F /Q \"{exePath}\"";

            var psi = new ProcessStartInfo("cmd.exe", cmdLine)
            {
                UseShellExecute  = false,
                CreateNoWindow   = true,
                WindowStyle      = ProcessWindowStyle.Hidden,
            };
            Process.Start(psi);
            Console.WriteLine($"  Self-delete scheduled for: {exePath}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  ScheduleSelfDelete failed: {ex.Message}");
        }
    }
}
