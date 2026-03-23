using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace EASYSID;

internal static class SidOperations
{
    public static string GenerateRandomSid()
    {
        using var rng = RandomNumberGenerator.Create();
        uint sa1 = GenerateNonZeroUInt32(rng);
        uint sa2 = GenerateNonZeroUInt32(rng);
        uint sa3 = GenerateNonZeroUInt32(rng);
        return $"S-1-5-21-{sa1}-{sa2}-{sa3}";
    }

    private static uint GenerateNonZeroUInt32(RandomNumberGenerator rng)
    {
        byte[] buf = new byte[4];
        uint val = 0;
        while (val == 0)
        {
            rng.GetBytes(buf);
            val = BitConverter.ToUInt32(buf, 0);
        }
        return val;
    }

    internal static uint[] ParseSidSubAuthorities(string sid)
    {
        // Format: S-1-5-21-X-Y-Z
        // parts[0]=S, [1]=1, [2]=5, [3]=21, [4]=X, [5]=Y, [6]=Z
        var parts = sid.Split('-');
        if (parts.Length < 7) return null;
        try
        {
            return new[]
            {
                uint.Parse(parts[4]),
                uint.Parse(parts[5]),
                uint.Parse(parts[6])
            };
        }
        catch { return null; }
    }

    internal static byte[] BuildSidPattern16(uint[] subAuth3)
    {
        byte[] pattern = new byte[16];
        // subAuth[0] = 21 (constant), subAuth[1] = X, subAuth[2] = Y, subAuth[3] = Z
        BitConverter.GetBytes((uint)21).CopyTo(pattern, 0);
        BitConverter.GetBytes(subAuth3[0]).CopyTo(pattern, 4);
        BitConverter.GetBytes(subAuth3[1]).CopyTo(pattern, 8);
        BitConverter.GetBytes(subAuth3[2]).CopyTo(pattern, 12);
        return pattern;
    }

    internal static bool ReplaceSidInBlob(IntPtr sidPtr, byte[] oldPattern16, byte[] newPattern16)
    {
        if (sidPtr == IntPtr.Zero) return false;

        // Read SID header
        byte revision = Marshal.ReadByte(sidPtr, 0);
        if (revision != 1) return false;

        byte subAuthCount = Marshal.ReadByte(sidPtr, 1);
        if (subAuthCount < 4) return false;

        // Check identifier authority = {0,0,0,0,0,5} (SECURITY_NT_AUTHORITY)
        // IdentifierAuthority is 6 bytes at offset 2, big-endian: value 5 = {0,0,0,0,0,5}
        if (Marshal.ReadByte(sidPtr, 2) != 0 || Marshal.ReadByte(sidPtr, 3) != 0 ||
            Marshal.ReadByte(sidPtr, 4) != 0 || Marshal.ReadByte(sidPtr, 5) != 0 ||
            Marshal.ReadByte(sidPtr, 6) != 0 || Marshal.ReadByte(sidPtr, 7) != 5)
            return false;

        // Check first sub-authority = 21 (at offset 8, 4 bytes LE)
        if (Marshal.ReadInt32(sidPtr, 8) != 21) return false;

        // Compare 16 bytes at offset 8: {21(LE), X(LE), Y(LE), Z(LE)}
        byte[] current = new byte[16];
        Marshal.Copy(sidPtr + 8, current, 0, 16);

        for (int i = 0; i < 16; i++)
        {
            if (current[i] != oldPattern16[i]) return false;
        }

        // Match! Replace in-place
        Marshal.Copy(newPattern16, 0, sidPtr + 8, 16);
        return true;
    }

    internal static uint ReplaceSidInSecurityDescriptor(IntPtr sd, byte[] old16, byte[] new16)
    {
        // Parse self-relative security descriptor directly from binary layout.
        // Self-relative SD header (20 bytes):
        //   offset 0:  BYTE  Revision
        //   offset 1:  BYTE  Sbz1
        //   offset 2:  WORD  Control
        //   offset 4:  DWORD OffsetOwner
        //   offset 8:  DWORD OffsetGroup
        //   offset 12: DWORD OffsetSacl
        //   offset 16: DWORD OffsetDacl

        uint mask = 0;

        uint offsetOwner = (uint)Marshal.ReadInt32(sd, 4);
        uint offsetGroup = (uint)Marshal.ReadInt32(sd, 8);
        uint offsetSacl  = (uint)Marshal.ReadInt32(sd, 12);
        uint offsetDacl  = (uint)Marshal.ReadInt32(sd, 16);

        // Owner SID
        if (offsetOwner != 0)
        {
            IntPtr ownerSid = sd + (int)offsetOwner;
            if (ReplaceSidInBlob(ownerSid, old16, new16))
                mask |= 1; // OWNER_SECURITY_INFORMATION
        }

        // Group SID
        if (offsetGroup != 0)
        {
            IntPtr groupSid = sd + (int)offsetGroup;
            if (ReplaceSidInBlob(groupSid, old16, new16))
                mask |= 2; // GROUP_SECURITY_INFORMATION
        }

        // DACL  -  ACL header: {BYTE Rev, BYTE Sbz, WORD AclSize, WORD AceCount, WORD Sbz2}
        if (offsetDacl != 0)
        {
            IntPtr dacl = sd + (int)offsetDacl;
            int aceCount = Marshal.ReadInt16(dacl, 4); // AceCount at offset 4 in ACL header
            // First ACE starts at ACL header + 8
            int aceOffset = 8;
            for (int i = 0; i < aceCount; i++)
            {
                IntPtr ace = dacl + aceOffset;
                byte aceType = Marshal.ReadByte(ace, 0);
                short aceSize = Marshal.ReadInt16(ace, 2);
                if (aceSize <= 0) break; // safety

                if (aceType <= 3) // ACCESS_ALLOWED, ACCESS_DENIED, SYSTEM_AUDIT, SYSTEM_ALARM
                {
                    IntPtr aceSid = ace + 8; // SID at ACE + 8 (after ACE_HEADER(4) + ACCESS_MASK(4))
                    if (ReplaceSidInBlob(aceSid, old16, new16))
                        mask |= 4; // DACL_SECURITY_INFORMATION
                }
                aceOffset += aceSize;
            }
        }

        // SACL
        if (offsetSacl != 0)
        {
            IntPtr sacl = sd + (int)offsetSacl;
            int aceCount = Marshal.ReadInt16(sacl, 4);
            int aceOffset = 8;
            for (int i = 0; i < aceCount; i++)
            {
                IntPtr ace = sacl + aceOffset;
                byte aceType = Marshal.ReadByte(ace, 0);
                short aceSize = Marshal.ReadInt16(ace, 2);
                if (aceSize <= 0) break;

                if (aceType <= 3)
                {
                    IntPtr aceSid = ace + 8;
                    if (ReplaceSidInBlob(aceSid, old16, new16))
                        mask |= 8; // SACL_SECURITY_INFORMATION
                }
                aceOffset += aceSize;
            }
        }

        return mask;
    }

    internal static string ReplaceSidInString(string str, string oldSid, string newSid)
    {
        int idx = 0;
        while (true)
        {
            int pos = str.IndexOf(oldSid, idx, StringComparison.OrdinalIgnoreCase);
            if (pos < 0) break;
            int afterPos = pos + oldSid.Length;
            // If next char is a digit, skip this match (partial sub-authority match guard)
            if (afterPos < str.Length && char.IsDigit(str[afterPos]))
            {
                idx = pos + 1;
                continue;
            }
            str = str.Substring(0, pos) + newSid + str.Substring(afterPos);
            idx = pos + newSid.Length;
        }
        return str;
    }
}
