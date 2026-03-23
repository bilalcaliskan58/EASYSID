using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace EASYSID;

/// <summary>
/// Handles stopping/restoring the UCPD driver and disabling Windows Defender
/// to prevent interference during SID change operations.
/// </summary>
internal static class SystemProtectionService
{
    /// <summary>
    /// Stops and disables the UCPD driver using multiple methods.
    ///
    /// UCPD is a kernel-mode driver (SERVICE_KERNEL_DRIVER). Many kernel drivers
    /// do NOT set SERVICE_ACCEPT_STOP, so "sc stop ucpd" returns error 1052
    /// (ERROR_INVALID_SERVICE_CONTROL = "bu islem gecerli degil").
    ///
    /// Fallback strategy:
    ///   1. sc stop ucpd              - works if driver accepts stop control
    ///   2. sc config ucpd start= 4   - disable for next boot (always works)
    ///   3. NtUnloadDriver            - kernel-level unload (works for current boot)
    ///   4. Registry direct disable   - failsafe if sc.exe has issues
    ///
    /// Even if stop/unload fails for current boot, disabling ensures UCPD
    /// won't load on next boot (Phase 2 runs after reboot anyway).
    /// </summary>
    internal static void StopUcpdDriver()
    {
        Console.WriteLine("[*] Stopping UCPD driver...");

        // Check if UCPD service exists at all
        bool exists = UcpdServiceExists();
        if (!exists)
        {
            Console.WriteLine("  UCPD service not found - skipped (may be normal).");
            return;
        }

        // Method 1: sc stop (works if driver accepts SERVICE_CONTROL_STOP)
        int stopResult = ProcessRunner.RunScCommand("stop ucpd");
        if (stopResult == 0)
        {
            Console.WriteLine("  sc stop ucpd: OK");
        }
        else
        {
            // 1062 = ERROR_SERVICE_NOT_ACTIVE (already stopped)
            // 1052 = ERROR_INVALID_SERVICE_CONTROL (driver doesn't accept stop)
            // 1060 = ERROR_SERVICE_DOES_NOT_EXIST
            Console.WriteLine($"  sc stop ucpd: exit {stopResult} (non-fatal)");
        }

        // Method 2: Disable for next boot via sc config
        int configResult = ProcessRunner.RunScCommand("config ucpd start= disabled");
        if (configResult == 0)
            Console.WriteLine("  sc config ucpd start= disabled: OK");
        else
            Console.WriteLine($"  sc config ucpd start= disabled: exit {configResult}");

        // Method 3: If sc stop failed (error 1052), try NtUnloadDriver
        // This unloads the driver from kernel memory for the current session
        if (stopResult != 0 && stopResult != 1062 && stopResult != 1060)
        {
            Console.WriteLine("  Trying NtUnloadDriver...");
            TryNtUnloadDriver("ucpd");
        }

        // Method 4: Registry direct disable as failsafe
        // Set Start=4 (SERVICE_DISABLED) directly in registry
        try
        {
            using var key = RegistryHelper.OpenRegKey(RegistryHive.LocalMachine,
                @"SYSTEM\CurrentControlSet\Services\UCPD", true);
            if (key != null)
            {
                key.SetValue("Start", 4, RegistryValueKind.DWord); // 4 = disabled
                Console.WriteLine("  Registry: UCPD Start=4 (disabled) set directly.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  Registry direct disable: {ex.Message}");
        }

        Console.WriteLine("  UCPD driver handling complete.");
    }

    /// <summary>
    /// Restores the UCPD driver to automatic start after SID change completes.
    /// </summary>
    internal static void RestoreUcpdDriver()
    {
        Console.WriteLine("[*] Restoring UCPD driver...");

        if (!UcpdServiceExists())
        {
            Console.WriteLine("  UCPD service not found - nothing to restore.");
            return;
        }

        // Restore Start type to 2 (SERVICE_AUTO_START) via registry
        // This is more reliable than "sc config ucpd start= auto" which
        // may fail if the service database is in a transient state after SID change.
        try
        {
            using var key = RegistryHelper.OpenRegKey(RegistryHive.LocalMachine,
                @"SYSTEM\CurrentControlSet\Services\UCPD", true);
            if (key != null)
            {
                // Only restore if we disabled it (Start == 4)
                int current = (int)(key.GetValue("Start") ?? -1);
                if (current == 4)
                {
                    key.SetValue("Start", 2, RegistryValueKind.DWord); // 2 = auto
                    Console.WriteLine("  UCPD Start restored to 2 (auto).");
                }
                else
                {
                    Console.WriteLine($"  UCPD Start is {current}, not restoring.");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  UCPD restore: {ex.Message}");
        }

        // Don't try to start the driver - it will load on next boot.
        // Starting a kernel driver after SID change can cause BSOD if
        // the driver's internal state references the old SID.
    }

    /// <summary>
    /// Checks if the UCPD service exists in the service database.
    /// </summary>
    private static bool UcpdServiceExists()
    {
        try
        {
            using var key = RegistryHelper.OpenRegKey(RegistryHive.LocalMachine,
                @"SYSTEM\CurrentControlSet\Services\UCPD");
            return key != null;
        }
        catch { return false; }
    }

    /// <summary>
    /// Attempts to unload a kernel driver using NtUnloadDriver.
    /// Requires SeLoadDriverPrivilege (index 10).
    /// </summary>
    private static void TryNtUnloadDriver(string serviceName)
    {
        try
        {
            // Acquire SeLoadDriverPrivilege
            NativeImports.RtlAdjustPrivilege(10, true, false, out _);

            // NtUnloadDriver expects a UNICODE_STRING with the registry path:
            // \Registry\Machine\System\CurrentControlSet\Services\<name>
            string regPath = $@"\Registry\Machine\System\CurrentControlSet\Services\{serviceName}";
            IntPtr strBuf = Marshal.StringToHGlobalUni(regPath);
            var us = new UNICODE_STRING
            {
                Length = (ushort)(regPath.Length * 2),
                MaximumLength = (ushort)(regPath.Length * 2 + 2),
                Buffer = strBuf
            };

            int status = NativeImports.NtUnloadDriver(ref us);
            Marshal.FreeHGlobal(strBuf);

            if (status == 0)
                Console.WriteLine($"    NtUnloadDriver({serviceName}): OK");
            else
                Console.WriteLine($"    NtUnloadDriver({serviceName}): 0x{status:X8}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    NtUnloadDriver: {ex.Message}");
        }
    }

    /// <summary>
    /// Disables Windows Defender real-time protection and tamper protection so it
    /// cannot block registry writes during SID change.
    /// Uses registry (tamper protection key) + PowerShell Set-MpPreference fallback.
    /// Non-fatal if Defender is not installed or already disabled.
    /// </summary>
    internal static void DisableWindowsDefender()
    {
        Console.WriteLine("[*] Disabling Windows Defender real-time protection...");

        // Step 1: Registry policy keys (works when tamper protection is off)
        try
        {
            using var key = RegistryHelper.CreateRegKey(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender", true);
            if (key != null)
            {
                key.SetValue("DisableAntiSpyware", 1, RegistryValueKind.DWord);
                Console.WriteLine("  Registry: DisableAntiSpyware=1 set.");
            }
            else Console.WriteLine("  Registry: could not open/create Windows Defender policy key.");

            using var rtKey = RegistryHelper.CreateRegKey(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", true);
            if (rtKey != null)
            {
                rtKey.SetValue("DisableRealtimeMonitoring", 1, RegistryValueKind.DWord);
                Console.WriteLine("  Registry: DisableRealtimeMonitoring=1 set.");
            }
            else Console.WriteLine("  Registry: could not open/create Real-Time Protection policy key.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  Registry Defender disable failed: {ex.Message}");
        }

        // Step 2: PowerShell Set-MpPreference (works if tamper protection allows it)
        try
        {
            var psi = new ProcessStartInfo("powershell.exe",
                "-NonInteractive -NoProfile -Command \"Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue\"")
            {
                UseShellExecute        = false,
                CreateNoWindow         = true,
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
            };
            using var p = Process.Start(psi);
            string psOut = p?.StandardOutput.ReadToEnd().Trim() ?? "";
            string psErr = p?.StandardError.ReadToEnd().Trim() ?? "";
            p?.WaitForExit(10000);
            int exitCode = p?.ExitCode ?? -1;
            Console.WriteLine($"  Set-MpPreference: exit={exitCode}" +
                              (string.IsNullOrEmpty(psErr) ? "" : $" | stderr: {psErr}") +
                              (string.IsNullOrEmpty(psOut) ? "" : $" | stdout: {psOut}"));
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  Set-MpPreference skipped: {ex.Message}");
        }
    }
}
