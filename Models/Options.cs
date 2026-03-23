namespace EASYSID;

/// <summary>
/// Public options controlling EASYSID behaviour.
/// </summary>
public class Options
{
    /// <summary>New computer name (null = keep current, "?" = random hex, "*" = MAC address)</summary>
    public string ComputerName { get; set; }

    /// <summary>New computer description</summary>
    public string ComputerDescription { get; set; }

    /// <summary>New SID value (null = generate random)</summary>
    public string NewSid { get; set; }

    /// <summary>Skip user confirmation prompt</summary>
    public bool Force { get; set; }

    /// <summary>Reboot after SID change</summary>
    public bool Reboot { get; set; }

    /// <summary>Shut down after SID change</summary>
    public bool Shutdown { get; set; }

    /// <summary>Clear WinLogon notice messages and exit</summary>
    public bool ClearNotice { get; set; }

    /// <summary>Change only computer name, not SID</summary>
    public bool NameOnly { get; set; }

    /// <summary>Target offline Windows installation path (e.g. D:\Windows)</summary>
    public string OfflineWindowsPath { get; set; }

    /// <summary>Skip WSUS ID change</summary>
    public bool SkipWsus { get; set; }

    /// <summary>Skip MSDTC CID reset</summary>
    public bool SkipMsdtcCid { get; set; }

    /// <summary>Skip Device ID reset</summary>
    public bool SkipDeviceId { get; set; }

    /// <summary>Skip MachineGuid reset</summary>
    public bool SkipMachineGuid { get; set; }

    /// <summary>Skip Machine ID reset</summary>
    public bool SkipMachineId { get; set; }

    /// <summary>Skip Dhcpv6 DUID reset</summary>
    public bool SkipDhcpDuid { get; set; }

    /// <summary>Skip automatic pre-change snapshot creation.</summary>
    public bool SkipBackup { get; set; }

    /// <summary>Custom backup root directory (default: ProgramData\EASYSID\Backups).</summary>
    public string BackupDirectory { get; set; }

    /// <summary>Restore profile/registry state from an existing snapshot directory.</summary>
    public string RollbackDirectory { get; set; }

    /// <summary>List all available snapshots and exit.</summary>
    public bool ListSnapshots { get; set; }

    /// <summary>Cancel pending SID change: remove scheduled tasks, clear WinLogon notices, restore AutoLogon.</summary>
    public bool Cancel { get; set; }

    /// <summary>
    /// Offline restore mode for WinPE: restore a snapshot to an offline Windows installation.
    /// Value is the target Windows drive letter (e.g. "D:" or "D:\Windows").
    /// Used with /ROLLBACK to specify both snapshot and target.
    /// </summary>
    public string OfflineRestoreTarget { get; set; }

    /// <summary>
    /// Set when running as a background service (via /EASYSIDSERVICE= argument).
    /// In this mode the process was launched by a transient Windows service and
    /// should perform changes immediately without installing another service.
    /// </summary>
    public bool IsBackgroundService { get; set; }

    /// <summary>The service name under which this instance runs (from /EASYSIDSERVICE=).</summary>
    public string BackgroundServiceName { get; set; }
}
