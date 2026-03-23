namespace EASYSID;

/// <summary>
/// Default app associations cannot be preserved after SID change.
/// Windows validates UserChoice hashes using a proprietary algorithm
/// bound to the user's SID. No known reliable method exists to
/// recompute these hashes programmatically.
///
/// Users are warned in interactive mode to re-set their defaults
/// after reboot (Settings > Default Apps).
/// </summary>
internal static class UserDefaultsService
{
    internal const string DefaultsFilePath = @"C:\ProgramData\EASYSID\UserDefaults.txt";

    internal static void CleanupDismPolicy() { }
}
