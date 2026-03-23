using System;
using System.Runtime.InteropServices;

namespace EASYSID;

[StructLayout(LayoutKind.Sequential)]
internal struct LSA_OBJECT_ATTRIBUTES
{
    public uint   Length;
    public IntPtr RootDirectory;
    public IntPtr ObjectName;
    public uint   Attributes;
    public IntPtr SecurityDescriptor;
    public IntPtr SecurityQualityOfService;
}

[StructLayout(LayoutKind.Sequential)]
internal struct LSA_ACCOUNT_DOMAIN_INFO
{
    public LSA_UNICODE_STRING DomainName;
    public IntPtr             Sid;          // PSID
}

[StructLayout(LayoutKind.Sequential)]
internal struct LSA_UNICODE_STRING
{
    public ushort Length;
    public ushort MaximumLength;
    public IntPtr Buffer;
}

[StructLayout(LayoutKind.Sequential)]
internal struct UNICODE_STRING
{
    public ushort Length;
    public ushort MaximumLength;
    public IntPtr Buffer;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct CREDENTIALW
{
    public uint Flags;
    public uint Type;
    [MarshalAs(UnmanagedType.LPWStr)] public string TargetName;
    [MarshalAs(UnmanagedType.LPWStr)] public string Comment;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
    public uint CredentialBlobSize;
    public IntPtr CredentialBlob;
    public uint Persist;
    public uint AttributeCount;
    public IntPtr Attributes;
    [MarshalAs(UnmanagedType.LPWStr)] public string TargetAlias;
    [MarshalAs(UnmanagedType.LPWStr)] public string UserName;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct STARTUPINFO
{
    public int    cb;
    public string lpReserved;
    public string lpDesktop;   // "Winsta0\\Winlogon"
    public string lpTitle;
    public uint   dwX, dwY, dwXSize, dwYSize;
    public uint   dwXCountChars, dwYCountChars;
    public uint   dwFillAttribute, dwFlags;
    public ushort wShowWindow;
    public ushort cbReserved2;
    public IntPtr lpReserved2;
    public IntPtr hStdInput, hStdOutput, hStdError;
}

[StructLayout(LayoutKind.Sequential)]
internal struct PROCESS_INFORMATION
{
    public IntPtr hProcess, hThread;
    public uint   dwProcessId, dwThreadId;
}

[StructLayout(LayoutKind.Sequential)]
internal struct OBJECT_ATTRIBUTES
{
    public int    Length;
    public IntPtr RootDirectory;
    public IntPtr ObjectName;   // pointer to UNICODE_STRING
    public uint   Attributes;
    public IntPtr SecurityDescriptor;
    public IntPtr SecurityQualityOfService;
}
