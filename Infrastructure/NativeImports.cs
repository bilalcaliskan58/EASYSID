using System;
using System.Runtime.InteropServices;

namespace EASYSID;

internal static class NativeImports
{
    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    internal const uint EWX_LOGOFF   = 0x00000000;
    internal const uint EWX_SHUTDOWN = 0x00000001;
    internal const uint EWX_REBOOT   = 0x00000002;
    internal const uint EWX_FORCE    = 0x00000004;
    internal const uint EWX_POWEROFF = 0x00000008;
    internal const uint EWX_FORCEIFHUNG = 0x00000010;
    internal const uint SHTDN_REASON_MAJOR_OTHER = 0x00000000;

    internal const int TOKEN_QUERY = 8;
    internal const int TokenUser = 1;

    internal static readonly IntPtr HKEY_LOCAL_MACHINE = new IntPtr(unchecked((int)0x80000002));

    // -----------------------------------------------------------------------
    // advapi32.dll
    // -----------------------------------------------------------------------

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    internal static extern uint LsaOpenPolicy(IntPtr SystemName, ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
        uint DesiredAccess, out IntPtr PolicyHandle);

    [DllImport("advapi32.dll")]
    internal static extern uint LsaQueryInformationPolicy(IntPtr PolicyHandle, int InformationClass,
        out IntPtr Buffer);

    [DllImport("advapi32.dll")]
    internal static extern uint LsaSetInformationPolicy(IntPtr PolicyHandle, int InformationClass,
        IntPtr Buffer);

    [DllImport("advapi32.dll")]
    internal static extern uint LsaClose(IntPtr ObjectHandle);

    [DllImport("advapi32.dll")]
    internal static extern uint LsaFreeMemory(IntPtr Buffer);

    [DllImport("advapi32.dll")]
    internal static extern uint LsaEnumerateAccounts(IntPtr PolicyHandle, ref IntPtr EnumerationContext,
        out IntPtr Buffer, uint PreferedMaximumLength, out uint CountReturned);

    [DllImport("advapi32.dll")]
    internal static extern uint LsaEnumerateAccountRights(IntPtr PolicyHandle, IntPtr AccountSid,
        out IntPtr UserRights, out uint CountOfRights);

    [DllImport("advapi32.dll")]
    internal static extern uint LsaAddAccountRights(IntPtr PolicyHandle, IntPtr AccountSid,
        LSA_UNICODE_STRING[] UserRights, uint CountOfRights);

    [DllImport("advapi32.dll")]
    internal static extern uint LsaRemoveAccountRights(IntPtr PolicyHandle, IntPtr AccountSid,
        bool AllRights, LSA_UNICODE_STRING[] UserRights, uint CountOfRights);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern bool ConvertSidToStringSid(IntPtr pSid, out string strSid);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern bool ConvertStringSidToSid(string StringSid, out IntPtr Sid);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern int GetLengthSid(IntPtr pSid);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern bool GetTokenInformation(
        IntPtr TokenHandle, int TokenInformationClass,
        IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern bool CredWriteW(ref CREDENTIALW Credential, uint Flags);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern bool CredReadW(string TargetName, uint Type, uint Flags, out IntPtr Credential);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern bool InitiateSystemShutdownEx(
        string lpMachineName, string lpMessage, uint dwTimeout,
        bool bForceAppsClosed, bool bRebootAfterShutdown, uint dwReason);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern bool AbortSystemShutdown(string lpMachineName);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern int RegOpenKeyExW(IntPtr hKey, string lpSubKey, int ulOptions, int samDesired, out IntPtr phkResult);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern int RegCloseKey(IntPtr hKey);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern int RegGetKeySecurity(IntPtr hKey, uint SecurityInformation, IntPtr pSecurityDescriptor, ref uint lpcbSecurityDescriptor);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern int RegSetKeySecurity(IntPtr hKey, uint SecurityInformation, IntPtr pSecurityDescriptor);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool InitializeSecurityDescriptor(IntPtr pSecurityDescriptor, uint dwRevision);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string StringSecurityDescriptor, uint StringSDRevision,
        out IntPtr SecurityDescriptor, out uint SecurityDescriptorSize);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern uint GetNamedSecurityInfoW(
        string pObjectName, int ObjectType, uint SecurityInfo,
        IntPtr ppsidOwner, IntPtr ppsidGroup, IntPtr ppDacl, IntPtr ppSacl,
        out IntPtr ppSecurityDescriptor);

    [DllImport("advapi32.dll")]
    internal static extern uint GetSecurityDescriptorLength(IntPtr pSecurityDescriptor);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern uint SetNamedSecurityInfoW(
        string pObjectName, int ObjectType, uint SecurityInfo,
        IntPtr psidOwner, IntPtr psidGroup, IntPtr pDacl, IntPtr pSacl);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern bool SetSecurityInfo(
        IntPtr handle, uint ObjectType, uint SecurityInfo,
        IntPtr psidOwner, IntPtr psidGroup, IntPtr pDacl, IntPtr pSacl);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool RevertToSelf();

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool DuplicateTokenEx(
        IntPtr hExistingToken, uint dwDesiredAccess,
        IntPtr lpTokenAttributes, int ImpersonationLevel,
        int TokenType, out IntPtr phNewToken);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern int RegLoadKeyW(IntPtr hKey, string lpSubKey, string lpFile);

    // -----------------------------------------------------------------------
    // ntdll.dll
    // -----------------------------------------------------------------------

    [DllImport("ntdll.dll")]
    internal static extern int RtlAdjustPrivilege(int Privilege, bool Enable, bool CurrentThread, out bool Enabled);

    [DllImport("ntdll.dll")]
    internal static extern int NtShutdownSystem(int Action);

    [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
    internal static extern int NtSetInformationKey(IntPtr KeyHandle, int KeySetInformationClass,
        IntPtr KeySetInformation, int KeySetInformationLength);

    [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
    internal static extern int NtRenameKey(IntPtr KeyHandle, ref UNICODE_STRING NewName);

    [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
    internal static extern int NtUnloadDriver(ref UNICODE_STRING DriverServiceName);

    [DllImport("ntdll.dll")]
    internal static extern int NtOpenKey(out IntPtr KeyHandle, uint DesiredAccess,
        ref OBJECT_ATTRIBUTES ObjectAttributes);

    [DllImport("ntdll.dll")]
    internal static extern int NtSetSecurityObject(IntPtr Handle, uint SecurityInformation,
        IntPtr SecurityDescriptor);

    [DllImport("ntdll.dll")]
    internal static extern int NtQuerySecurityObject(IntPtr Handle, uint SecurityInformation,
        IntPtr SecurityDescriptor, uint Length, out uint LengthNeeded);

    [DllImport("ntdll.dll")]
    internal static extern int NtOpenKeyEx(out IntPtr KeyHandle, uint DesiredAccess,
        ref OBJECT_ATTRIBUTES ObjectAttributes, uint OpenOptions);

    [DllImport("ntdll.dll")]
    internal static extern int NtEnumerateKey(IntPtr KeyHandle, uint Index,
        int KeyInformationClass, IntPtr KeyInformation, uint Length, out uint ResultLength);

    [DllImport("ntdll.dll")]
    internal static extern int NtClose(IntPtr Handle);

    [DllImport("ntdll.dll")]
    internal static extern int NtFlushKey(IntPtr KeyHandle);

    [DllImport("ntdll.dll")]
    internal static extern int RtlGetOwnerSecurityDescriptor(IntPtr SD, out IntPtr Owner, out byte Defaulted);

    [DllImport("ntdll.dll")]
    internal static extern int RtlGetGroupSecurityDescriptor(IntPtr SD, out IntPtr Group, out byte Defaulted);

    [DllImport("ntdll.dll")]
    internal static extern int RtlGetDaclSecurityDescriptor(IntPtr SD, out byte Present, out IntPtr Dacl, out byte Defaulted);

    [DllImport("ntdll.dll")]
    internal static extern int RtlGetSaclSecurityDescriptor(IntPtr SD, out byte Present, out IntPtr Sacl, out byte Defaulted);

    [DllImport("ntdll.dll")]
    internal static extern int RtlQueryInformationAcl(IntPtr Acl, IntPtr AclInfo, uint AclInfoLength, int AclInformationClass);

    [DllImport("ntdll.dll")]
    internal static extern int RtlGetAce(IntPtr Acl, uint AceIndex, out IntPtr Ace);

    // -----------------------------------------------------------------------
    // user32.dll
    // -----------------------------------------------------------------------

    [DllImport("user32.dll", SetLastError = true)]
    internal static extern bool ExitWindowsEx(uint uFlags, uint dwReason);

    // -----------------------------------------------------------------------
    // kernel32.dll
    // -----------------------------------------------------------------------

    [DllImport("kernel32.dll")]
    internal static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    internal static extern IntPtr LocalFree(IntPtr hMem);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern bool CreateProcessAsUserW(
        IntPtr hToken, string lpApplicationName, string lpCommandLine,
        IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
        bool bInheritHandles, uint dwCreationFlags,
        IntPtr lpEnvironment, string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern uint WTSGetActiveConsoleSessionId();

    // -----------------------------------------------------------------------
    // wtsapi32.dll
    // -----------------------------------------------------------------------

    [DllImport("wtsapi32.dll")]
    internal static extern bool WTSQueryUserToken(uint SessionId, out IntPtr phToken);
}

// -----------------------------------------------------------------------
// NativeMethods - Service Control Manager and Registry Unload
// -----------------------------------------------------------------------

internal static class NativeMethods
{
    public static readonly IntPtr HKEY_USERS = new IntPtr(unchecked((int)0x80000003));
    public static readonly IntPtr HKEY_LOCAL_MACHINE = new IntPtr(unchecked((int)0x80000002));

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr OpenSCManagerW(string lpMachineName, string lpDatabaseName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CreateServiceW(
        IntPtr hSCManager, string lpServiceName, string lpDisplayName,
        uint dwDesiredAccess, uint dwServiceType, uint dwStartType,
        uint dwErrorControl, string lpBinaryPathName,
        string lpLoadOrderGroup, IntPtr lpdwTagId,
        string lpDependencies, string lpServiceStartName, string lpPassword);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool StartServiceW(IntPtr hService, uint dwNumServiceArgs, string[] lpServiceArgVectors);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool DeleteService(IntPtr hService);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool CloseServiceHandle(IntPtr hSCObject);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int RegUnLoadKeyW(IntPtr hKey, string lpSubKey);
}
