using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32;

namespace EASYSID;

internal static class ProfileMigrationService
{
    internal static bool RemapProfileList(string oldSid, string newSid)
    {
        Console.WriteLine("[*] Remapping ProfileList...");
        try
        {
            const string profileListPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
            using var profileList = RegistryHelper.OpenRegKey(RegistryHive.LocalMachine, profileListPath, true);
            if (profileList == null) return true; // not fatal

            // Find subkey that starts with oldSid and rename it
            string[] subkeys = profileList.GetSubKeyNames();
            Console.WriteLine($"  ProfileList: {subkeys.Length} subkey(s) found.");
            int remapped = 0;
            foreach (string sk in subkeys)
            {
                if (!sk.StartsWith(oldSid, StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine($"  ProfileList: skipping '{sk}' (no SID match).");
                    continue;
                }

                string newKey = newSid + sk.Substring(oldSid.Length);

                // Check if profile directory exists - if not, this is an orphan profile
                // from a previously deleted user. Remove it instead of remapping.
                try
                {
                    using var checkKey = profileList.OpenSubKey(sk);
                    string checkPath = checkKey?.GetValue("ProfileImagePath") as string;
                    if (checkPath != null)
                    {
                        string resolvedCheck = Environment.ExpandEnvironmentVariables(checkPath);
                        if (!Directory.Exists(resolvedCheck))
                        {
                            Console.ForegroundColor = ConsoleColor.Yellow;
                            Console.WriteLine($"  ProfileList: ORPHAN detected '{sk}' -> '{resolvedCheck}' (directory missing)");
                            Console.WriteLine($"    Removing orphan profile entry from registry.");
                            Console.ResetColor();
                            profileList.DeleteSubKeyTree(sk, false);
                            continue;
                        }
                    }
                }
                catch { }

                Console.WriteLine($"  ProfileList: remapping '{sk}' -> '{newKey}'");
                try
                {
                    using var srcKey = profileList.OpenSubKey(sk, true);
                    using var dstKey = profileList.CreateSubKey(newKey);
                    if (srcKey != null && dstKey != null)
                    {
                        RegistryHelper.CopyRegistryKey(srcKey, dstKey);

                        // Log all values in destination key for diagnostics
                        Console.WriteLine($"    Copied values:");
                        foreach (string vn in dstKey.GetValueNames())
                        {
                            try
                            {
                                var vk = dstKey.GetValueKind(vn);
                                object vv = dstKey.GetValue(vn);
                                string display = vk == RegistryValueKind.Binary && vv is byte[] bArr
                                    ? $"[{bArr.Length} bytes]"
                                    : vv?.ToString() ?? "(null)";
                                Console.WriteLine($"      {(string.IsNullOrEmpty(vn) ? "(Default)" : vn)} [{vk}] = {display}");
                            }
                            catch { }
                        }

                        // Fix ProfileImagePath: replace old SID with new SID in path
                        string path = dstKey.GetValue("ProfileImagePath") as string;
                        if (path != null)
                        {
                            string newPath = path.Replace(oldSid, newSid, StringComparison.OrdinalIgnoreCase);
                            dstKey.SetValue("ProfileImagePath", newPath, RegistryValueKind.ExpandString);
                            Console.WriteLine($"    ProfileImagePath: '{path}' -> '{newPath}'");
                        }

                        // Reset State to 0 (profile ready)  -  copied State may be 256/512 (temp/failed)
                        // which would cause "Hesabiniza oturum acamiyoruz" on every login.
                        object oldState = dstKey.GetValue("State");
                        dstKey.SetValue("State", 0, RegistryValueKind.DWord);
                        Console.WriteLine($"    State: {oldState ?? "(not set)"} -> 0 (profile ready)");

                        // Reset RefCount to 0  -  if > 0 Windows considers profile still loaded
                        object oldRef = dstKey.GetValue("RefCount");
                        dstKey.SetValue("RefCount", 0, RegistryValueKind.DWord);
                        Console.WriteLine($"    RefCount: {oldRef ?? "(not set)"} -> 0");

                        // Update Sid binary value  -  this REG_BINARY contains the user's full SID
                        // in binary form. After copy it still has the old machine SID sub-authorities.
                        try
                        {
                            if (NativeImports.ConvertStringSidToSid(newKey, out IntPtr newUserSidPtr))
                            {
                                // Get SID length: a SID with 5 sub-authorities = 28 bytes
                                // S-1-5-21-X-Y-Z-RID = 6 bytes header + 5*4 sub-auth = 28
                                int sidLen = NativeImports.GetLengthSid(newUserSidPtr);
                                byte[] sidBytes = new byte[sidLen];
                                Marshal.Copy(newUserSidPtr, sidBytes, 0, sidLen);
                                dstKey.SetValue("Sid", sidBytes, RegistryValueKind.Binary);
                                NativeImports.LocalFree(newUserSidPtr);
                                Console.WriteLine($"    Sid binary: updated to {newKey} ({sidLen} bytes)");
                            }
                            else
                            {
                                Console.WriteLine($"    Sid binary: ConvertStringSidToSid failed for '{newKey}'  -  skipped.");
                            }
                        }
                        catch (Exception sidEx)
                        {
                            Console.WriteLine($"    Sid binary update: {sidEx.Message}");
                        }

                        // Delete old SID .bak subkey if present (prevents profile conflict)
                        string bakKey = sk + ".bak";
                        if (Array.Exists(subkeys, k => string.Equals(k, bakKey, StringComparison.OrdinalIgnoreCase)))
                        {
                            profileList.DeleteSubKeyTree(bakKey, false);
                            Console.WriteLine($"    Backup key '{bakKey}' deleted.");
                        }

                        // Delete stale new-SID .bak subkey if present
                        string newBakKey = newKey + ".bak";
                        if (profileList.OpenSubKey(newBakKey) != null)
                        {
                            profileList.DeleteSubKeyTree(newBakKey, false);
                            Console.WriteLine($"    Stale new-SID backup key '{newBakKey}' deleted.");
                        }

                        profileList.DeleteSubKeyTree(sk, false);
                        Console.WriteLine($"    Old key '{sk}' deleted.");

                        // Fix file system ACLs on the profile directory
                        string resolvedPath = path != null
                            ? Environment.ExpandEnvironmentVariables(path)
                            : null;
                        if (resolvedPath != null)
                        {
                            FixProfileAcls(resolvedPath, sk, newKey);
                            PatchUserHiveFiles(resolvedPath, oldSid, newSid);
                            MigrateDpapiMasterKeys(resolvedPath, sk, newKey);
                            ChromiumService.PatchChromiumProfiles(resolvedPath);
                        }

                        remapped++;
                    }
                    else
                    {
                        Console.Error.WriteLine($"    Could not open src or create dst for '{sk}'.");
                    }
                }
                catch (Exception exInner)
                {
                    Console.Error.WriteLine($"    Remap '{sk}' failed: {exInner.Message}");
                }
            }
            Console.WriteLine($"  ProfileList: {remapped} profile(s) remapped.");

            // Update ProfileGuid cross-references
            if (remapped > 0)
                UpdateProfileGuid(oldSid, newSid);

            // Verification: dump final ProfileList state
            Console.WriteLine("  ProfileList final state:");
            try
            {
                string[] finalKeys = profileList.GetSubKeyNames();
                foreach (string fk in finalKeys)
                {
                    using var fkSub = profileList.OpenSubKey(fk);
                    if (fkSub == null) continue;
                    string pip = fkSub.GetValue("ProfileImagePath") as string ?? "(none)";
                    object st = fkSub.GetValue("State");
                    object rc = fkSub.GetValue("RefCount");
                    byte[] sidBin = fkSub.GetValue("Sid") as byte[];
                    string sidHex = sidBin != null ? BitConverter.ToString(sidBin).Replace("-", " ") : "(none)";
                    Console.WriteLine($"    {fk}: Path={pip} State={st ?? "?"} RefCount={rc ?? "?"} SidBin=[{sidHex}]");
                }
            }
            catch { }

            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"  ProfileList remap failed: {ex.Message}");
            return false;
        }
    }

    private static void UpdateProfileGuid(string oldSid, string newSid)
    {
        Console.WriteLine("[*] Updating ProfileGuid cross-references...");
        try
        {
            const string guidPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileGuid";
            using var guidRoot = RegistryHelper.OpenRegKey(RegistryHive.LocalMachine, guidPath, true);
            if (guidRoot == null)
            {
                Console.WriteLine("    ProfileGuid key not found  -  skipped (may be normal).");
                return;
            }

            int updated = 0;
            foreach (string guidName in guidRoot.GetSubKeyNames())
            {
                try
                {
                    using var sub = guidRoot.OpenSubKey(guidName, true);
                    if (sub == null) continue;

                    string sidStr = sub.GetValue("SidString") as string;
                    if (sidStr != null && sidStr.Contains(oldSid, StringComparison.OrdinalIgnoreCase))
                    {
                        string newSidStr = sidStr.Replace(oldSid, newSid, StringComparison.OrdinalIgnoreCase);
                        sub.SetValue("SidString", newSidStr, RegistryValueKind.String);
                        Console.WriteLine($"    ProfileGuid\\{guidName}: '{sidStr}' -> '{newSidStr}'");
                        updated++;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"    ProfileGuid\\{guidName}: {ex.Message}");
                }
            }
            Console.WriteLine($"    ProfileGuid: {updated} entry(ies) updated.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    UpdateProfileGuid failed: {ex.Message}");
        }
    }

    private static void FixProfileAcls(string profilePath, string oldFullSid, string newFullSid)
    {
        Console.WriteLine($"[*] Fixing profile file ACLs: '{profilePath}'");
        Console.WriteLine($"    Old SID: {oldFullSid}  New SID: {newFullSid}");

        if (!Directory.Exists(profilePath))
        {
            Console.WriteLine($"    Profile directory does not exist  -  skipped.");
            return;
        }

        // The old/newFullSid may be user SIDs like S-1-5-21-X-Y-Z-RID
        // We want the machine part: X, Y, Z  -  which are parts[4], [5], [6]
        var oldParts = oldFullSid.Split('-');
        var newParts = newFullSid.Split('-');
        if (oldParts.Length < 7 || newParts.Length < 7)
        {
            Console.WriteLine("    Cannot parse SID sub-authorities  -  skipped.");
            return;
        }

        byte[] old16 = SidOperations.BuildSidPattern16(new[] {
            uint.Parse(oldParts[4]), uint.Parse(oldParts[5]), uint.Parse(oldParts[6])
        });
        byte[] new16 = SidOperations.BuildSidPattern16(new[] {
            uint.Parse(newParts[4]), uint.Parse(newParts[5]), uint.Parse(newParts[6])
        });

        int changed = 0, failed = 0, skipped = 0;

        // Only fix critical paths  -  NO recursive traversal
        string[] criticalPaths = new[]
        {
            profilePath,
            Path.Combine(profilePath, "NTUSER.DAT"),
            Path.Combine(profilePath, "ntuser.dat.LOG1"),
            Path.Combine(profilePath, "ntuser.dat.LOG2"),
            Path.Combine(profilePath, "ntuser.ini"),
            Path.Combine(profilePath, "AppData"),
            Path.Combine(profilePath, @"AppData\Local"),
            Path.Combine(profilePath, @"AppData\Local\Microsoft"),
            Path.Combine(profilePath, @"AppData\Local\Microsoft\Windows"),
            Path.Combine(profilePath, @"AppData\Local\Microsoft\Windows\UsrClass.dat"),
            Path.Combine(profilePath, @"AppData\Local\Microsoft\Windows\UsrClass.dat.LOG1"),
            Path.Combine(profilePath, @"AppData\Local\Microsoft\Windows\UsrClass.dat.LOG2"),
            Path.Combine(profilePath, @"AppData\Roaming"),
            Path.Combine(profilePath, @"AppData\LocalLow"),
            Path.Combine(profilePath, "Desktop"),
            Path.Combine(profilePath, "Documents"),
            Path.Combine(profilePath, "Downloads"),
        };

        foreach (string path in criticalPaths)
        {
            if (!File.Exists(path) && !Directory.Exists(path))
            {
                skipped++;
                continue;
            }
            FixSingleFileSD(path, old16, new16, ref changed, ref failed);
        }

        Console.WriteLine($"    File ACL fix: {changed} patched, {failed} failed, {skipped} skipped.");
    }

    private static void FixSingleFileSD(string path, byte[] old16, byte[] new16,
                                         ref int changed, ref int failed)
    {
        const uint SD_ALL = 0xF; // OWNER|GROUP|DACL|SACL
        const uint SD_BUF = 0x4000;

        IntPtr sdBuf = Marshal.AllocHGlobal((int)SD_BUF);
        try
        {
            // GetNamedSecurityInfoW returns a self-relative SD
            uint err = NativeImports.GetNamedSecurityInfoW(path, 1 /*SE_FILE_OBJECT*/,
                SD_ALL, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out IntPtr sdPtr);
            if (err != 0 || sdPtr == IntPtr.Zero)
            {
                // Fall back: just set owner with new SID
                if (!NativeImports.ConvertStringSidToSid("S-1-5-18", out IntPtr sysSid)) // SYSTEM
                {
                    failed++;
                    return;
                }
                // At least set owner to SYSTEM so profile service can access
                NativeImports.SetNamedSecurityInfoW(path, 1 /*SE_FILE_OBJECT*/, 1 /*OWNER*/, sysSid, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                NativeImports.LocalFree(sysSid);
                failed++;
                return;
            }

            // Copy SD to our writable buffer (GetNamedSecurityInfoW returns allocated SD)
            uint sdLen = NativeImports.GetSecurityDescriptorLength(sdPtr);
            if (sdLen > SD_BUF)
            {
                Marshal.FreeHGlobal(sdBuf);
                sdBuf = Marshal.AllocHGlobal((int)sdLen);
            }

            // Copy to our buffer so we can modify in-place
            unsafe
            {
                Buffer.MemoryCopy((void*)sdPtr, (void*)sdBuf, sdLen, sdLen);
            }
            NativeImports.LocalFree(sdPtr);

            uint mask = SidOperations.ReplaceSidInSecurityDescriptor(sdBuf, old16, new16);
            if (mask != 0)
            {
                // Extract new owner if changed
                IntPtr newOwner = IntPtr.Zero, newDacl = IntPtr.Zero;
                if ((mask & 1) != 0) // owner changed
                    NativeImports.RtlGetOwnerSecurityDescriptor(sdBuf, out newOwner, out _);
                if ((mask & 4) != 0) // DACL changed
                    NativeImports.RtlGetDaclSecurityDescriptor(sdBuf, out _, out newDacl, out _);

                uint setMask = 0;
                if (newOwner != IntPtr.Zero) setMask |= 1;
                if (newDacl != IntPtr.Zero) setMask |= 4;

                if (setMask != 0)
                {
                    err = NativeImports.SetNamedSecurityInfoW(path, 1, setMask, newOwner, IntPtr.Zero, newDacl, IntPtr.Zero);
                    if (err == 0)
                    {
                        changed++;
                        Console.WriteLine($"    File SD OK: {Path.GetFileName(path)} (mask=0x{mask:X})");
                    }
                    else
                    {
                        failed++;
                        Console.WriteLine($"    File SD FAIL: {Path.GetFileName(path)} err={err}");
                    }
                }
                else
                {
                    changed++;
                }
            }
            else
            {
                Console.WriteLine($"    File SD: {Path.GetFileName(path)}  -  no old SID found.");
            }
        }
        catch (Exception ex)
        {
            failed++;
            Console.WriteLine($"    File SD ERR: {Path.GetFileName(path)}: {ex.Message}");
        }
        finally
        {
            Marshal.FreeHGlobal(sdBuf);
        }
    }

    private static void PatchUserHiveFiles(string profilePath, string oldSid, string newSid)
    {
        Console.WriteLine($"[*] Patching user hive files in '{profilePath}'...");

        // 1. NTUSER.DAT
        string ntuserPath = Path.Combine(profilePath, "NTUSER.DAT");
        PatchSingleHiveFile(ntuserPath, "NTUSER.DAT", oldSid, newSid);

        // 2. UsrClass.dat
        string usrClassPath = Path.Combine(profilePath, @"AppData\Local\Microsoft\Windows\UsrClass.dat");
        PatchSingleHiveFile(usrClassPath, "UsrClass.dat", oldSid, newSid);
    }

    private static void PatchSingleHiveFile(string hivePath, string displayName, string oldSid, string newSid)
    {
        if (!File.Exists(hivePath))
        {
            Console.WriteLine($"    {displayName}: file not found  -  skipped.");
            return;
        }

        Console.WriteLine($"    {displayName}: file size = {new FileInfo(hivePath).Length} bytes");
        string tempKeyName = "EASYSID_TEMP_" + displayName.Replace(".", "_").ToUpperInvariant();
        Console.WriteLine($"    {displayName}: loading as HKU\\{tempKeyName}...");

        try
        {
            // Force GC and wait briefly to release any lingering handles
            GC.Collect();
            GC.WaitForPendingFinalizers();

            // Load hive under HKEY_USERS  -  retry up to 3 times with delay
            int rc = -1;
            for (int attempt = 1; attempt <= 3; attempt++)
            {
                rc = NativeImports.RegLoadKeyW(NativeMethods.HKEY_USERS, tempKeyName, hivePath);
                if (rc == 0) break;
                Console.WriteLine($"    {displayName}: RegLoadKey attempt {attempt} failed: 0x{rc:X8} (Win32={rc})");
                if (attempt < 3) Thread.Sleep(1000);
            }
            if (rc != 0)
            {
                Console.WriteLine($"    {displayName}: RegLoadKey failed after 3 attempts  -  skipped.");
                return;
            }

            try
            {
                using var hiveKey = RegistryHelper.OpenRegKey(RegistryHive.Users, tempKeyName, true);
                if (hiveKey != null)
                {
                    int replaced = RegistryHelper.ReplaceUserHiveSidStrings(hiveKey, oldSid, newSid);
                    Console.WriteLine($"    {displayName}: {replaced} SID string reference(s) replaced.");
                }
                else
                {
                    Console.WriteLine($"    {displayName}: could not open loaded hive  -  skipped.");
                }
            }
            finally
            {
                // Always unload
                int unloadRc = NativeMethods.RegUnLoadKeyW(NativeMethods.HKEY_USERS, tempKeyName);
                if (unloadRc != 0)
                    Console.WriteLine($"    {displayName}: RegUnLoadKey returned 0x{unloadRc:X8}.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    {displayName}: {ex.Message}");
        }
    }

    private static void MigrateDpapiMasterKeys(string profilePath, string oldFullSid, string newFullSid)
    {
        Console.WriteLine($"[*] Migrating DPAPI master keys for profile: {Path.GetFileName(profilePath)}");

        // Primary location: %AppData%\Microsoft\Protect\<SID>
        string roamingProtect = Path.Combine(profilePath, @"AppData\Roaming\Microsoft\Protect");
        RenameSidDirectory(roamingProtect, oldFullSid, newFullSid, "DPAPI Roaming");

        // Secondary location: %LocalAppData%\Microsoft\Protect\<SID>
        string localProtect = Path.Combine(profilePath, @"AppData\Local\Microsoft\Protect");
        RenameSidDirectory(localProtect, oldFullSid, newFullSid, "DPAPI Local");

        // SystemCertificates per-user store (used by EFS, code signing, etc.)
        string roamingCerts = Path.Combine(profilePath, @"AppData\Roaming\Microsoft\SystemCertificates");
        RenameSidDirectory(roamingCerts, oldFullSid, newFullSid, "Certs Roaming");

        // Credentials directory: %AppData%\Microsoft\Credentials
        // These files are DPAPI-encrypted and don't use SID in folder names,
        // but their ACLs need to reference the new SID (handled by FixProfileAcls).
    }

    private static void RenameSidDirectory(string parentDir, string oldSid, string newSid, string label)
    {
        if (!Directory.Exists(parentDir)) return;

        string oldDir = Path.Combine(parentDir, oldSid);
        string newDir = Path.Combine(parentDir, newSid);

        if (!Directory.Exists(oldDir))
        {
            Console.WriteLine($"    {label}: old SID folder not found - skipped.");
            return;
        }

        try
        {
            if (Directory.Exists(newDir))
            {
                // Merge: copy files from old to new, don't overwrite existing
                foreach (string file in Directory.GetFiles(oldDir))
                {
                    string dest = Path.Combine(newDir, Path.GetFileName(file));
                    if (!File.Exists(dest))
                        File.Copy(file, dest);
                }
                foreach (string dir in Directory.GetDirectories(oldDir))
                {
                    string dest = Path.Combine(newDir, Path.GetFileName(dir));
                    if (!Directory.Exists(dest))
                        Directory.Move(dir, dest);
                }
                Console.WriteLine($"    {label}: merged old SID folder into existing new SID folder.");
            }
            else
            {
                Directory.Move(oldDir, newDir);
                Console.WriteLine($"    {label}: renamed '{oldSid}' -> '{newSid}'.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"    {label}: rename failed: {ex.Message}");
            // Fallback: try copy
            try
            {
                CopyDirectoryRecursive(oldDir, newDir);
                Console.WriteLine($"    {label}: fallback copy succeeded.");
            }
            catch (Exception ex2)
            {
                Console.WriteLine($"    {label}: fallback copy also failed: {ex2.Message}");
            }
        }
    }

    private static void CopyDirectoryRecursive(string source, string destination)
    {
        Directory.CreateDirectory(destination);
        foreach (string file in Directory.GetFiles(source))
            File.Copy(file, Path.Combine(destination, Path.GetFileName(file)), true);
        foreach (string dir in Directory.GetDirectories(source))
            CopyDirectoryRecursive(dir, Path.Combine(destination, Path.GetFileName(dir)));
    }
}
