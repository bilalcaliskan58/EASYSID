using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace EASYSID;

internal static class ShutdownService
{
    /// <summary>
    /// Forces a system restart or shutdown using multiple fallback methods.
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

        // Method 1: shutdown.exe
        try
        {
            string shutdownArgs = reboot
                ? $"/r /f /t 5 /c \"{message}\""
                : $"/s /f /t 5 /c \"{message}\"";
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
                    return;
                }
                Console.WriteLine($"  shutdown.exe: exit code {p.ExitCode}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  shutdown.exe failed: {ex.Message}");
        }

        // Method 2: InitiateSystemShutdownEx
        // Abort any pending shutdown from Method 1 before trying a new method
        try { NativeImports.AbortSystemShutdown(null); } catch { }
        System.Threading.Thread.Sleep(500);
        bool ok = NativeImports.InitiateSystemShutdownEx(null, message, 10, true, reboot, 0x00040000);
        if (ok)
        {
            Console.WriteLine("  InitiateSystemShutdownEx: success.");
            return;
        }
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
            return;
        }
        Console.Error.WriteLine($"  ExitWindowsEx failed: {Marshal.GetLastWin32Error()}");

        // Method 4: NtShutdownSystem (kernel-level, last resort)
        Console.WriteLine("  Trying NtShutdownSystem (kernel-level)...");
        int ntAction = reboot ? 1 : 2;
        int status = NativeImports.NtShutdownSystem(ntAction);
        if (status == 0)
        {
            Console.WriteLine("  NtShutdownSystem: success.");
            return;
        }
        Console.Error.WriteLine($"  NtShutdownSystem failed: 0x{status:X8}");

        Console.Error.WriteLine("  *** ALL METHODS FAILED - Please reboot manually. ***");
    }
}
