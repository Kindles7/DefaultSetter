//Version       : 1.0.0
//Author        : Nuliax
//Description   : Default app installer to associate with file/protocol type in Windows 10/11.
//Origin        : https://github.com/DanysysTeam/PS-SFTA
//License       : MIT License
//Copyright     : 2022 Inseries.dev

using Microsoft.Win32;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace InseriesDEV
{
    public static class DefaultSetter
    {
        public static string? UserSID { get; set; } = null;

        private static string UpdateRegistry(string registrySubKey, string progId, string assocType)
        {
            try
            {
                using RegistryKey? key = Registry.CurrentUser.OpenSubKey(registrySubKey, true);

                if (key == null)
                    return $"Registry key for \"{assocType}\" not found.";

                if (GenerateHash(progId, assocType) is not string hash)
                    return "Hash generation failed.";

                key.SetValue("Hash", hash, RegistryValueKind.String);
                key.SetValue("ProgId", progId, RegistryValueKind.String);
                key.Close();
                return string.Empty;
            }
            catch (Exception e)
            {
                return assocType + ": " + e.Message;
            }
        }

        private static string? GetUserSID()
            => UserSID ??= WindowsIdentity.GetCurrent().User?.Value;

        private static string GetExperience()
        {
            using FileStream stream = File.OpenRead($"{Environment.SystemDirectory}\\shell32.dll");
            using BinaryReader reader = new(stream);
            string shellData = Encoding.Unicode.GetString(reader.ReadBytes(ToInt32(stream.Length)));
            string anchor = "User Choice set via Windows User Experience";
            int startPosition = shellData.IndexOf(anchor);
            int endPosition = shellData.IndexOf("}", startPosition);
            return shellData.Substring(startPosition, endPosition - startPosition + 1);
        }

        private static string GetHexDateTime()
        {
            DateTime now = DateTime.Now;
            long fileTime = new DateTime(now.Year, now.Month, now.Day, now.Hour, now.Minute, 0).ToFileTime();
            return ((fileTime >> 32).ToString("X8") + (fileTime & 0xffffffffL).ToString("X8")).ToLower();
        }

        private static string? GetHash(string baseInfo)
        {
            byte[] baseInfoBytes = Encoding.Unicode.GetBytes(baseInfo + "".PadRight(1, '\0'));
            long length = GetShiftRight(baseInfoBytes.Length, 2) - ((baseInfoBytes.Length & 4) <= 1 ? 0 : 1);

            if (length > 1)
            {
                using MD5 MD5 = MD5.Create();
                byte[] MD5Bytes = MD5.ComputeHash(baseInfoBytes);
                int[] hashParts = new int[2];
                int[] temp = new int[13];
                long cache = 0;
                long index = GetShiftRight(length - 2, 1);
                long counter = index + 1;
                long MD51 = (ToInt32(MD5Bytes) | 1) + 0x69FB0000L;
                long MD52 = (ToInt32(MD5Bytes, 4) | 1) + 0x13DB0000L;

                while (counter > 0)
                {
                    temp[0] = ToInt32(ToInt32(baseInfoBytes, temp[12]) + (long)hashParts[0]);
                    temp[1] = ToInt32(ToInt32(baseInfoBytes, temp[12] + 4));
                    temp[12] = temp[12] + 8;
                    temp[3] = ToInt32((temp[0] * MD51) - (0x10FA9605L * GetShiftRight(temp[0], 16)));
                    temp[4] = ToInt32((0x79F8A395L * temp[3]) + (0x689B6B9FL * GetShiftRight(temp[3], 16)));
                    temp[5] = ToInt32((0xEA970001L * temp[4]) - (0x3C101569L * GetShiftRight(temp[4], 16)));
                    temp[6] = ToInt32(temp[5] + temp[1]);
                    temp[8] = ToInt32(cache + temp[5]);
                    temp[10] = ToInt32((temp[6] * MD52) - (0x3CE8EC25L * GetShiftRight(temp[6], 16)));
                    temp[11] = ToInt32((0x59C3AF2DL * temp[10]) - (0x2232E0F1L * GetShiftRight(temp[10], 16)));
                    hashParts[0] = ToInt32((0x1EC90001L * temp[11]) + (0x35BD1EC9L * GetShiftRight(temp[11], 16)));
                    hashParts[1] = ToInt32((long)temp[8] + hashParts[0]);
                    cache = hashParts[1];
                    counter--;
                }

                byte[] hashBytes = new byte[16];
                BitConverter.GetBytes(hashParts[0]).CopyTo(hashBytes, 0);
                BitConverter.GetBytes(hashParts[1]).CopyTo(hashBytes, 4);
                hashParts = new int[2];
                temp = new int[13];
                cache = 0;
                index = GetShiftRight(length - 2, 1);
                counter = index + 1;
                MD51 = ToInt32(MD5Bytes) | 1;
                MD52 = ToInt32(MD5Bytes, 4) | 1;

                while (counter > 0)
                {
                    temp[0] = ToInt32(ToInt32(baseInfoBytes, temp[12]) + (long)hashParts[0]);
                    temp[12] = temp[12] + 8;
                    temp[1] = ToInt32(temp[0] * MD51);
                    temp[2] = ToInt32((0xB1110000L * temp[1]) - (0x30674EEFL * GetShiftRight(temp[1], 16)));
                    temp[3] = ToInt32((0x5B9F0000L * temp[2]) - (0x78F7A461L * GetShiftRight(temp[2], 16)));
                    temp[4] = ToInt32((0x12CEB96DL * GetShiftRight(temp[3], 16)) - (0x46930000L * temp[3]));
                    temp[5] = ToInt32((0x1D830000L * temp[4]) + (0x257E1D83L * GetShiftRight(temp[4], 16)));
                    temp[6] = ToInt32(MD52 * ((long)temp[5] + ToInt32(baseInfoBytes, temp[12] - 4)));
                    temp[7] = ToInt32((0x16F50000L * temp[6]) - (0x5D8BE90BL * GetShiftRight(temp[6], 16)));
                    temp[8] = ToInt32((0x96FF0000L * temp[7]) - (0x2C7C6901L * GetShiftRight(temp[7], 16)));
                    temp[9] = ToInt32((0x2B890000L * temp[8]) + (0x7C932B89L * GetShiftRight(temp[8], 16)));
                    hashParts[0] = ToInt32((0x9F690000L * temp[9]) - (0x405B6097L * GetShiftRight(temp[9], 16)));
                    hashParts[1] = ToInt32(hashParts[0] + cache + temp[5]);
                    cache = hashParts[1];
                    counter--;
                }

                BitConverter.GetBytes(hashParts[0]).CopyTo(hashBytes, 8);
                BitConverter.GetBytes(hashParts[1]).CopyTo(hashBytes, 12);
                int hashValue1 = ToInt32(ToInt32(hashBytes, 8) ^ ToInt32(hashBytes));
                int hashValue2 = ToInt32(ToInt32(hashBytes, 12) ^ ToInt32(hashBytes, 4));
                hashBytes = new byte[8];
                BitConverter.GetBytes(hashValue1).CopyTo(hashBytes, 0);
                BitConverter.GetBytes(hashValue2).CopyTo(hashBytes, 4);
                return Convert.ToBase64String(hashBytes);
            }

            return null;
        }

        private static long GetShiftRight(long value, int count)
            => (value & 0x80000000) != 0
            ? (value >> count) ^ 0xFFFF0000 : value >> count;

        private static int ToInt32(byte[] bytes, int index = 0)
            => BitConverter.ToInt32(bytes, index);

        private static int ToInt32(long value)
            => BitConverter.ToInt32(BitConverter.GetBytes(value), 0);

        /// <summary>
        /// Get the generated hash without registry changes.
        /// </summary>
        /// <param name="progId"></param>
        /// <param name="assocType"></param>
        /// <returns>The generated hash or null if unsuccessful.</returns>
        public static string? GenerateHash(string progId, string assocType)
        {
            if (GetUserSID() is not string userSID)
                return null;

            return GetHash($"{assocType}{userSID}{progId}{GetHexDateTime()}{GetExperience()}".ToLower());
        }

        /// <summary>
        /// Sets the default application for the specified protocol.
        /// </summary>
        /// <param name="progId"></param>
        /// <param name="protocol"></param>
        /// <returns>Error message or empty if successful.</returns>
        public static string TrySetProtocolDefaultApp(string progId, string protocol)
            => UpdateRegistry($"Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\{protocol}\\UserChoice", progId, protocol);

        /// <summary>
        /// Sets the default application for the specified extension.
        /// </summary>
        /// <param name="progId"></param>
        /// <param name="extension"></param>
        /// <returns>Error message or empty if successful.</returns>
        public static string TrySetExtensionDefaultApp(string progId, string extension)
            => UpdateRegistry($"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\{extension}\\UserChoice", progId, extension);
    }
}