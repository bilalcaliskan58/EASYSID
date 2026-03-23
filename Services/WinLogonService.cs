using System;
using System.IO;
using System.Text;
using Microsoft.Win32;

namespace EASYSID;

internal static class WinLogonService
{
    internal static readonly string[] WinLogonNoticePaths = new[]
    {
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Authentication\LogonUI",
    };

    // Note: legalnoticecaption / legalnoticetext are NOT in this list.
    // They are handled exclusively by SetWinLogonNotice / ClearWinLogonNotice,
    // which back up to and restore from the same *-sav naming. Including them
    // here would cause RestoreWinLogonSettings to consume the -sav keys before
    // ClearWinLogonNotice gets a chance to restore them in the finally block.
    internal static readonly string[] WinLogonValueNames = new[]
    {
        "ForceAutoLogon", "ShutdownWithoutLogon", "DisableCAD", "IdleTimeOut"
    };

    internal static readonly string[] WinLogonKeyPaths = new[]
    {
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Authentication\LogonUI"
    };

    /// <summary>
    /// Sets legalnoticecaption + legalnoticetext on the WinLogon screen.
    /// This displays a dialog at login that the user must dismiss  -  effectively
    /// blocking login until the SID change completes and the notice is cleared.
    /// </summary>
    internal static void SetWinLogonNotice(string caption, string text)
    {
        // Write legal notice to BOTH registry paths so the message shows on logon screen.
        // Policies\System takes precedence (Group Policy), so we must set both.
        foreach (string path in WinLogonNoticePaths)
        {
            try
            {
                using var key = RegistryHelper.OpenRegKey(RegistryHive.LocalMachine, path, true);
                if (key == null) continue;

                // Back up existing values once so they can be restored on cleanup.
                foreach (string name in new[] { "legalnoticecaption", "legalnoticetext" })
                {
                    string savName = name + "-sav";
                    if (key.GetValue(savName) == null)
                    {
                        object current = key.GetValue(name);
                        if (current != null)
                            key.SetValue(savName, current, key.GetValueKind(name));
                    }
                }

                key.SetValue("legalnoticecaption", caption, RegistryValueKind.String);
                key.SetValue("legalnoticetext",    text,    RegistryValueKind.String);

                // StatusMsg only exists in the Winlogon path
                if (path.Contains("Winlogon", StringComparison.OrdinalIgnoreCase))
                {
                    if (key.GetValue("StatusMsg-sav") == null)
                    {
                        object oldStatus = key.GetValue("StatusMsg");
                        if (oldStatus != null)
                            key.SetValue("StatusMsg-sav", oldStatus, key.GetValueKind("StatusMsg"));
                    }
                    key.SetValue("StatusMsg", text, RegistryValueKind.String);
                }
            }
            catch { }
        }
    }

    /// <summary>
    /// Clears the WinLogon legal notice set by SetWinLogonNotice,
    /// restoring backed-up values if they exist (from BackupWinLogonSettings).
    /// </summary>
    /// <summary>
    /// Called at every EASYSID startup to clean up stale notices from crashed/failed runs.
    /// Only clears notices that contain "EASYSID" or "SID Change" - won't touch
    /// legitimate legal notices set by Group Policy or IT admins.
    /// </summary>
    internal static void ClearStaleNotices()
    {
        foreach (string path in WinLogonNoticePaths)
        {
            try
            {
                using var key = RegistryHelper.OpenRegKey(RegistryHive.LocalMachine, path, true);
                if (key == null) continue;

                string caption = key.GetValue("legalnoticecaption") as string ?? "";
                string text = key.GetValue("legalnoticetext") as string ?? "";

                // Only clear if it's our notice (contains EASYSID or SID Change markers)
                bool isOurs = caption.Contains("SID", StringComparison.OrdinalIgnoreCase) ||
                              caption.Contains("EASYSID", StringComparison.OrdinalIgnoreCase) ||
                              text.Contains("EASYSID", StringComparison.OrdinalIgnoreCase);

                if (isOurs)
                {
                    ClearWinLogonNotice();
                    return; // only need to detect once
                }
            }
            catch { }
        }
    }

    internal static void ClearWinLogonNotice()
    {
        // Clear or restore ONLY notice/progress values from every relevant path.
        // Do not touch AutoLogon/other backup keys here.
        foreach (string path in WinLogonNoticePaths)
        {
            try
            {
                using var key = RegistryHelper.OpenRegKey(RegistryHive.LocalMachine, path, true);
                if (key == null) continue;

                // Notice / progress values written by SetWinLogonNotice / WinLogonProgressWriter
                foreach (string name in new[] { "legalnoticecaption", "legalnoticetext" })
                {
                    string savName = name + "-sav";
                    object saved = key.GetValue(savName);
                    if (saved != null)
                    {
                        key.SetValue(name, saved, key.GetValueKind(savName));
                        key.DeleteValue(savName, false);
                    }
                    else
                    {
                        key.DeleteValue(name, false);
                    }
                }

                // StatusMsg lives only in the Winlogon path
                if (path.Contains("Winlogon", StringComparison.OrdinalIgnoreCase) &&
                    !path.Contains("Authentication", StringComparison.OrdinalIgnoreCase))
                {
                    object savedStatus = key.GetValue("StatusMsg-sav");
                    if (savedStatus != null)
                    {
                        key.SetValue("StatusMsg", savedStatus, key.GetValueKind("StatusMsg-sav"));
                        key.DeleteValue("StatusMsg-sav", false);
                    }
                    else
                    {
                        key.DeleteValue("StatusMsg", false);
                    }
                }
            }
            catch { }
        }
    }

    internal static void BackupWinLogonSettings()
    {
        int totalBacked = 0;
        foreach (string keyPath in WinLogonKeyPaths)
        {
            try
            {
                using var key = RegistryHelper.OpenRegKey(RegistryHive.LocalMachine, keyPath, true);
                if (key == null) { Console.WriteLine($"  Backup WinLogon: key not found '{keyPath}'."); continue; }
                foreach (string name in WinLogonValueNames)
                {
                    object val = key.GetValue(name);
                    if (val != null)
                    {
                        key.SetValue(name + "-sav", val, key.GetValueKind(name));
                        Console.WriteLine($"  Backup WinLogon [{keyPath}] {name}={val}");
                        totalBacked++;
                    }
                }
            }
            catch (Exception ex) { Console.WriteLine($"  Backup WinLogon '{keyPath}' failed: {ex.Message}"); }
        }
        Console.WriteLine($"  WinLogon backup: {totalBacked} value(s) saved.");
    }

    internal static void RestoreWinLogonSettings()
    {
        int totalRestored = 0;
        foreach (string keyPath in WinLogonKeyPaths)
        {
            try
            {
                using var key = RegistryHelper.OpenRegKey(RegistryHive.LocalMachine, keyPath, true);
                if (key == null) { Console.WriteLine($"  Restore WinLogon: key not found '{keyPath}'."); continue; }
                foreach (string name in WinLogonValueNames)
                {
                    string savName = name + "-sav";
                    object val = key.GetValue(savName);
                    if (val != null)
                    {
                        key.SetValue(name, val, key.GetValueKind(savName));
                        key.DeleteValue(savName, false);
                        Console.WriteLine($"  Restore WinLogon [{keyPath}] {name}={val}");
                        totalRestored++;
                    }
                }
            }
            catch (Exception ex) { Console.WriteLine($"  Restore WinLogon '{keyPath}' failed: {ex.Message}"); }
        }
        Console.WriteLine($"  WinLogon restore: {totalRestored} value(s) restored.");
    }

    internal static void DisableAutoLogon()
    {
        try
        {
            const string path = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
            using var key = RegistryHelper.OpenRegKey(RegistryHive.LocalMachine, path, true);
            if (key == null) return;

            // Backup current values
            string cur = key.GetValue("AutoAdminLogon")?.ToString() ?? "0";
            key.SetValue("AutoAdminLogon-EASYSID-sav", cur, RegistryValueKind.String);

            // Disable auto logon for next boot only
            key.SetValue("AutoAdminLogon", "0", RegistryValueKind.String);
            Console.WriteLine($"  AutoLogon disabled (was: {cur}), will restore after SID change.");
        }
        catch (Exception ex) { Console.WriteLine($"  DisableAutoLogon: {ex.Message}"); }
    }

    internal static void RestoreAutoLogon()
    {
        try
        {
            const string path = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
            using var key = RegistryHelper.OpenRegKey(RegistryHive.LocalMachine, path, true);
            if (key == null) return;

            object saved = key.GetValue("AutoAdminLogon-EASYSID-sav");
            if (saved != null)
            {
                key.SetValue("AutoAdminLogon", saved.ToString(), RegistryValueKind.String);
                key.DeleteValue("AutoAdminLogon-EASYSID-sav", false);
                Console.WriteLine($"  AutoLogon restored to: {saved}");
            }
        }
        catch (Exception ex) { Console.WriteLine($"  RestoreAutoLogon: {ex.Message}"); }
    }

    // -----------------------------------------------------------------------
    // WinLogon live progress writer
    // Writes all Console output to a log file AND mirrors the last N lines
    // to the WinLogon legal notice text so the user can watch progress on
    // the login screen in real time (updated after every WriteLine call).
    // -----------------------------------------------------------------------

    internal sealed class WinLogonProgressWriter : TextWriter
    {
        private readonly StreamWriter _file;
        private readonly System.Collections.Generic.Queue<string> _lines
            = new System.Collections.Generic.Queue<string>();
        private const int MaxLines = 12; // lines visible on login screen

        public WinLogonProgressWriter(string logPath)
        {
            _file = new StreamWriter(logPath, append: false, Encoding.UTF8)
                { AutoFlush = true };
        }

        public override Encoding Encoding => Encoding.UTF8;

        public override void WriteLine(string? value)
        {
            string line = value ?? "";
            _file.WriteLine(line);

            // Keep last MaxLines lines for the notice text
            _lines.Enqueue(line);
            while (_lines.Count > MaxLines) _lines.Dequeue();

            FlushToWinLogon();
        }

        public override void Write(string? value)
        {
            _file.Write(value);
            // Don't update WinLogon on partial writes  -  only on full lines
        }

        private void FlushToWinLogon()
        {
            // Use the last line as a status message - shown on logon screen without OK button
            string allLines = string.Join("\r\n", _lines);

            // Write to BOTH registry paths so the message shows regardless of policy
            foreach (string path in WinLogonNoticePaths)
            {
                try
                {
                    using var key = RegistryKey
                        .OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
                        .OpenSubKey(path, true);
                    if (key == null) continue;

                    key.SetValue("legalnoticecaption", "SID Change in Progress", RegistryValueKind.String);
                    key.SetValue("legalnoticetext", allLines, RegistryValueKind.String);

                    // StatusMsg only exists in Winlogon path
                    if (path.Contains("Winlogon", StringComparison.OrdinalIgnoreCase))
                        key.SetValue("StatusMsg", allLines, RegistryValueKind.String);
                }
                catch { }
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) _file.Dispose();
            base.Dispose(disposing);
        }
    }
}
