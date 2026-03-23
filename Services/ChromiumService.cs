using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace EASYSID;

/// <summary>
/// Chromium browser profile cleanup after SID change.
///
/// Removes machine-binding identifiers from Local State and
/// sign-out markers from profile Preferences.
///
/// DPAPI limitation:
///   Chrome/Edge saved passwords are encrypted with DPAPI which is bound to the SID.
///   After SID change, DPAPI cannot decrypt old data - saved passwords are lost.
///   Users should enable Chrome Sync before SID change to restore passwords after reboot.
/// </summary>
internal static class ChromiumService
{
    private static readonly (string relPath, string name)[] BrowserPaths =
    {
        (@"AppData\Local\Google\Chrome\User Data", "Chrome"),
        (@"AppData\Local\Microsoft\Edge\User Data", "Edge"),
        (@"AppData\Local\BraveSoftware\Brave-Browser\User Data", "Brave"),
        (@"AppData\Roaming\Opera Software\Opera Stable", "Opera"),
        (@"AppData\Local\Vivaldi\User Data", "Vivaldi"),
    };

    internal static void PatchChromiumProfiles(string profilePath)
    {
        Console.WriteLine($"[*] Patching Chromium browser profiles for: {Path.GetFileName(profilePath)}");

        int patched = 0;
        foreach (var (relPath, name) in BrowserPaths)
        {
            string userDataDir = Path.Combine(profilePath, relPath);
            if (!Directory.Exists(userDataDir)) continue;

            // 1. Patch Local State (remove machine IDs)
            string localStatePath = Path.Combine(userDataDir, "Local State");
            if (File.Exists(localStatePath))
            {
                try
                {
                    string json = File.ReadAllText(localStatePath, Encoding.UTF8);
                    bool modified = false;

                    json = RemoveJsonField(json, "machine_id", ref modified);
                    json = RemoveJsonField(json, "device_id", ref modified);
                    json = RemoveJsonField(json, "uninstall_metrics_machine_id", ref modified);

                    if (modified)
                    {
                        File.WriteAllText(localStatePath, json, Encoding.UTF8);
                        Console.WriteLine($"    {name}: Local State patched.");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"    {name}: Local State failed: {ex.Message}");
                }
            }

            // 2. Clean sign-out markers in each profile
            try
            {
                foreach (string profileDir in Directory.GetDirectories(userDataDir))
                {
                    string dirName = Path.GetFileName(profileDir);
                    if (!dirName.Equals("Default", StringComparison.OrdinalIgnoreCase) &&
                        !dirName.StartsWith("Profile ", StringComparison.OrdinalIgnoreCase))
                        continue;

                    string prefsPath = Path.Combine(profileDir, "Preferences");
                    if (!File.Exists(prefsPath)) continue;

                    try
                    {
                        string prefs = File.ReadAllText(prefsPath, Encoding.UTF8);
                        bool modified = false;
                        prefs = RemoveJsonField(prefs, "signin_allowed_on_next_startup", ref modified);
                        prefs = RemoveJsonField(prefs, "gaia_cookie_last_machine_id", ref modified);
                        if (modified)
                            File.WriteAllText(prefsPath, prefs, Encoding.UTF8);
                    }
                    catch { }
                }
            }
            catch { }

            patched++;
        }

        Console.WriteLine($"  Chromium profiles: {patched} browser(s) patched.");
    }

    private static string RemoveJsonField(string json, string fieldName, ref bool modified)
    {
        string pattern = $@",?\s*""{Regex.Escape(fieldName)}""\s*:\s*(?:""[^""]*""|[^,\}}\]]+)\s*,?";
        string result = Regex.Replace(json, pattern, match =>
        {
            string m = match.Value;
            if (m.TrimStart().StartsWith(",") && m.TrimEnd().EndsWith(",")) return ",";
            return "";
        });
        if (result != json)
        {
            modified = true;
            result = Regex.Replace(result, @",\s*([}\]])", "$1");
            result = Regex.Replace(result, @",\s*,", ",");
        }
        return result;
    }
}
