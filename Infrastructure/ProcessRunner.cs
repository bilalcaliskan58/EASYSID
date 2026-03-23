using System;
using System.Diagnostics;
using System.IO;

namespace EASYSID;

internal static class ProcessRunner
{
    internal static bool RunHiddenProcess(string fileName, string arguments)
    {
        try
        {
            var psi = new ProcessStartInfo(fileName, arguments)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var p = Process.Start(psi);
            // Read stderr asynchronously to prevent deadlock when buffer fills
            string stderr = null;
            p.ErrorDataReceived += (_, e) => { if (e.Data != null) stderr = (stderr == null ? "" : stderr + "\n") + e.Data; };
            p.BeginErrorReadLine();
            string stdout = p.StandardOutput.ReadToEnd();
            p.WaitForExit(30000);

            if (p.ExitCode != 0)
            {
                Console.WriteLine($"  Command failed: {fileName} {arguments}");
                if (!string.IsNullOrWhiteSpace(stdout)) Console.WriteLine($"    OUT: {stdout.Trim()}");
                if (!string.IsNullOrWhiteSpace(stderr)) Console.WriteLine($"    ERR: {stderr.Trim()}");
                return false;
            }
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  Command exception: {fileName} {arguments} ({ex.Message})");
            return false;
        }
    }

    internal static int RunScCommand(string arguments)
    {
        try
        {
            var psi = new ProcessStartInfo("sc.exe", arguments)
            {
                UseShellExecute        = false,
                CreateNoWindow         = true,
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
            };
            using var p = Process.Start(psi)!;
            string stderr = null;
            p.ErrorDataReceived += (_, e) => { if (e.Data != null) stderr = (stderr ?? "") + e.Data; };
            p.BeginErrorReadLine();
            string stdout = p.StandardOutput.ReadToEnd().Trim();
            p.WaitForExit(5000);
            string output = string.IsNullOrEmpty(stdout) ? stderr?.Trim() : stdout;
            if (!string.IsNullOrEmpty(output))
                Console.WriteLine($"    sc.exe {arguments}: {output}");
            return p.ExitCode;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    sc.exe {arguments}: exception: {ex.Message}");
            return -1;
        }
    }

    internal static void CopyIfExists(string source, string destination)
    {
        try
        {
            if (!File.Exists(source))
                return;
            string? dir = Path.GetDirectoryName(destination);
            if (string.IsNullOrWhiteSpace(dir))
                return;
            Directory.CreateDirectory(dir);
            File.Copy(source, destination, true);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  File copy failed: '{source}' -> '{destination}' ({ex.Message})");
        }
    }

    internal static void CopyDirectoryRecursive(string source, string destination)
    {
        Directory.CreateDirectory(destination);
        foreach (string file in Directory.GetFiles(source))
            File.Copy(file, Path.Combine(destination, Path.GetFileName(file)), true);
        foreach (string dir in Directory.GetDirectories(source))
            CopyDirectoryRecursive(dir, Path.Combine(destination, Path.GetFileName(dir)));
    }
}
