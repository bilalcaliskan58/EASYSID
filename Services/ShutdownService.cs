using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace EASYSID;

internal static class ShutdownService
{
    /// <summary>
    /// Forces a system restart or shutdown using multiple fallback methods.
    /// All methods are tried sequentially regardless of reported success,
    /// because some methods (especially shutdown.exe) can report success
    /// in SYSTEM sessions without actually triggering a reboot.
    /// <paramref name="reason"/> is shown to the user in the shutdown dialog.
    /// </summary>
    internal static void ForceSystemRestart(bool reboot, string reason = null)
    {
        string action = reboot ? "reboot" : "shutdown";
        string message = reason ?? $"EASYSID: {action} requested.";

        Console.WriteLine($"[*] Initiating system {action}...");

        // Acquire SeShutdownPrivilege (index 19) + SeRemoteShutdownPrivilege (index 24)
        NativeImports.RtlAdjustPrivilege(19, true, false, out _);
        NativeImports.RtlAdjustPrivilege(24, true, false, out _);

        bool anySucceeded = false;

        // Method 1: shutdown.exe
        try
        {
            string shutdownArgs = reboot
                ? $"/r /f /t 0 /c \"{message}\""
                : $"/s /f /t 0 /c \"{message}\"";
            var psi = new ProcessStartInfo("shutdown.exe", shutdownArgs)
            {
                UseShellExecute        = false,
                CreateNoWindow         = true,
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
            };
            using var p = Process.Start(psi);
            if (p != null)
            {
                p.WaitForExit(5000);
                if (p.ExitCode == 0)
                {
                    Console.WriteLine("  shutdown.exe: success.");
                    anySucceeded = true;
                }
                else
                    Console.WriteLine($"  shutdown.exe: exit code {p.ExitCode}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  shutdown.exe failed: {ex.Message}");
        }

        // Wait to see if Method 1 actually triggers a reboot
        if (anySucceeded)
        {
            Console.WriteLine("  Waiting 10 seconds to verify reboot...");
            System.Threading.Thread.Sleep(10000);
            Console.WriteLine("  System still running - trying additional methods...");
        }

        // Method 2: InitiateSystemShutdownEx
        try { NativeImports.AbortSystemShutdown(null); } catch { }
        System.Threading.Thread.Sleep(500);
        bool ok = NativeImports.InitiateSystemShutdownEx(null, message, 5, true, reboot, 0x00040000);
        if (ok)
        {
            Console.WriteLine("  InitiateSystemShutdownEx: success.");
            anySucceeded = true;

            // Wait to see if this method works
            Console.WriteLine("  Waiting 10 seconds to verify reboot...");
            System.Threading.Thread.Sleep(10000);
            Console.WriteLine("  System still running - trying additional methods...");
        }
        else
            Console.Error.WriteLine($"  InitiateSystemShutdownEx failed: {Marshal.GetLastWin32Error()}");

        // Method 3: ExitWindowsEx
        try { NativeImports.AbortSystemShutdown(null); } catch { }
        System.Threading.Thread.Sleep(500);
        uint ewxFlags = reboot
            ? (NativeImports.EWX_REBOOT | NativeImports.EWX_FORCE | NativeImports.EWX_FORCEIFHUNG)
            : (NativeImports.EWX_SHUTDOWN | NativeImports.EWX_POWEROFF | NativeImports.EWX_FORCE | NativeImports.EWX_FORCEIFHUNG);
        ok = NativeImports.ExitWindowsEx(ewxFlags, NativeImports.SHTDN_REASON_MAJOR_OTHER);
        if (ok)
        {
            Console.WriteLine("  ExitWindowsEx: success.");
            anySucceeded = true;

            Console.WriteLine("  Waiting 10 seconds to verify reboot...");
            System.Threading.Thread.Sleep(10000);
            Console.WriteLine("  System still running - trying kernel-level method...");
        }
        else
            Console.Error.WriteLine($"  ExitWindowsEx failed: {Marshal.GetLastWin32Error()}");

        // Method 4: NtShutdownSystem (kernel-level, last resort)
        Console.WriteLine("  Trying NtShutdownSystem (kernel-level)...");
        int ntAction = reboot ? 1 : 2;
        int status = NativeImports.NtShutdownSystem(ntAction);
        if (status == 0)
        {
            Console.WriteLine("  NtShutdownSystem: success.");
            anySucceeded = true;
        }
        else
            Console.Error.WriteLine($"  NtShutdownSystem failed: 0x{status:X8}");

        if (!anySucceeded)
            Console.Error.WriteLine("  *** ALL METHODS FAILED - Please reboot manually. ***");
        else
        {
            // If we're still here after all methods, do one final retry with shutdown.exe /t 0
            Console.Error.WriteLine("  *** Reboot was requested but system is still running. Retrying... ***");
            try
            {
                string retryArgs = reboot ? "/r /f /t 0" : "/s /f /t 0";
                Process.Start(new ProcessStartInfo("shutdown.exe", retryArgs)
                {
                    UseShellExecute = false, CreateNoWindow = true
                });
            }
            catch { }
            Console.Error.WriteLine("  *** If the system does not restart, please reboot manually. ***");
        }
    }
}
