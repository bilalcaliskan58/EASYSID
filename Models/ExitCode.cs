namespace EASYSID;

/// <summary>
/// Return / exit codes (mirrors EASYSID exit codes).
/// </summary>
public enum ExitCode : int
{
    Success = 0,
    InvalidArguments = 1,
    NotAdministrator = 2,
    MissingPrivilege = 3,
    FailedToChangeSid = 4,
    AlreadyRunning = 5,
    InvalidWindowsDirectory = 6,
    NeedReboot = 10,
    RegistryError = 11,
}
