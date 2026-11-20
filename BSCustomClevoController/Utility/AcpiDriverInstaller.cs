using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace BSCustomClevoController.Utility
{
    public static class AcpiDriverInstaller
    {
        private readonly struct ExpectedDriverFile
        {
            public readonly string FileName;
            public readonly long Length;
            public readonly string Sha256;
            public readonly string CertThumbprint;

            public ExpectedDriverFile(string fileName, long length, string sha256, string certThumbprint)
            {
                FileName = fileName;
                Length = length;
                Sha256 = sha256;
                CertThumbprint = certThumbprint;
            }
        }

        private const string PrimaryInfName = "AcpiBridge.inf";
        private const long AcpiBridgeSysLength = 83736L;
        private const string AcpiBridgeSysSha256 = "BE879AF2EF1BEAA3AD041C30ABD103C5E9E872D23EA8442B57682BB0D06EA153";

        private static readonly ExpectedDriverFile[] ExpectedDriverFiles = new ExpectedDriverFile[]
        {
            new ExpectedDriverFile("AcpiBridge.inf", 2531L, "BF668F7EB0031E4AABF6B364830E2AACD2397EE4B2997AA3EB82D0013671437F", null),
            new ExpectedDriverFile("AcpiBridge.sys", AcpiBridgeSysLength, AcpiBridgeSysSha256, "426510225A68B9260814230B37E289BFE0566F28"),
            new ExpectedDriverFile("acpibridge.cat", 11177L, "7C1203904101E6A3FDAAB3305318B3F3141A81AA53BED50EA3FBE9CFB483F873", "426510225A68B9260814230B37E289BFE0566F28"),
            new ExpectedDriverFile("AcpiBridge1.Inf", 2350L, "0A4F87B4AFB76057DFA2F84BE2C06111E8181383AFEE9105B1AEF272EB5D6396", null),
            new ExpectedDriverFile("AcpiBridge1.sys", 71792L, "33EDDC7F90E5394B7671BFCD7B5E8615BDD11930373BC7880330ADABE88E0496", "CA5296E9D87044679D0B405104B8DB2C8D56EB03"),
            new ExpectedDriverFile("acpibridge1.cat", 16649L, "DE0D8842FD497EEDD24FB6F5A20FA352F566CED551008B693ABFE76194F799BB", "CA5296E9D87044679D0B405104B8DB2C8D56EB03")
        };

        private static readonly object InstalledSysCacheLock = new object();
        private static long _cachedSysLength = -1;
        private static long _cachedSysWriteTicks = -1;
        private static bool _cachedSysAuthentic;

        private const string AcpiBridgeDevicePath = @"\\?\ACPI#CLV0001#1#{86994c74-ad43-4812-b7e7-0c420b5c5fd7}";
        private const uint GENERIC_READ = 0x80000000;
        private const uint GENERIC_WRITE = 0x40000000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint OPEN_EXISTING = 3;

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct Luid
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct TokenPrivileges
        {
            public uint PrivilegeCount;
            public Luid Luid;
            public uint Attributes;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out Luid lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TokenPrivileges NewState, uint BufferLengthInBytes, IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool ExitWindowsEx(uint uFlags, uint dwReason);

        private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private const uint TOKEN_QUERY = 0x0008;
        private const string SE_SHUTDOWN_NAME = "SeShutdownPrivilege";
        private const uint SE_PRIVILEGE_ENABLED = 0x00000002;
        private const uint EWX_REBOOT = 0x00000002;
        private const uint EWX_FORCE = 0x00000004;

        /// <summary>
        /// Checks whether the authentic Clevo/Insyde ACPI bridge driver is installed and responding.
        /// </summary>
        public static bool IsDriverWorking()
        {
            try
            {
                if (!IsInstalledSysAuthentic())
                {
                    return false;
                }

                IntPtr hDevice = CreateFile(
                    AcpiBridgeDevicePath,
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    IntPtr.Zero,
                    OPEN_EXISTING,
                    0,
                    IntPtr.Zero);

                if (hDevice != IntPtr.Zero && hDevice != new IntPtr(-1))
                {
                    CloseHandle(hDevice);
                    return true;
                }
            }
            catch (Exception ex)
            {
                AppLogger.Log("AcpiDriverInstaller.IsDriverWorking", ex);
            }

            return false;
        }

        /// <summary>
        /// Verifies the default AcpiBridge driver folder under a read lock and installs the WHQL-signed Clevo/Insyde driver.
        /// </summary>
        public static bool InstallDriver(out bool rebootRequired, bool force = false)
        {
            rebootRequired = false;
            if (!force && IsDriverWorking())
            {
                return true;
            }

            string driverDir = GetExpectedDriverDirectory();
            List<FileStream> lockedStreams;
            string integrityError;
            if (!LockAndVerifyDriverPackage(driverDir, out lockedStreams, out integrityError))
            {
                AppLogger.Log(
                    "AcpiDriverInstaller.IntegrityViolation",
                    new UnauthorizedAccessException(integrityError ?? "AcpiBridge driver folder failed integrity verification."));
                return false;
            }

            int installExitCode;
            try
            {
                string infPrimary = Path.Combine(driverDir, PrimaryInfName);
                installExitCode = RunPnpUtil(string.Format("/add-driver \"{0}\" /install", infPrimary), out _);
                // 0 = Success, 3010 = Reboot required, 259 = ERROR_NO_MORE_ITEMS (package added, devices already current or waiting for restart)
                bool primaryOk = installExitCode == 0 || installExitCode == 3010 || installExitCode == 259;
                if (!primaryOk)
                {
                    return false;
                }

                if (installExitCode == 3010)
                {
                    rebootRequired = true;
                }

                RunPnpUtil("/scan-devices");
                EnsureEventLogSource();
            }
            finally
            {
                DisposeStreams(lockedStreams);
            }

            Thread.Sleep(500);

            if (force)
            {
                StartupManager.SetRunAtStartup(true);
                rebootRequired = true;
                return true;
            }

            if (IsDriverWorking())
            {
                return true;
            }

            if (installExitCode != 3010 && !IsInstalledSysAuthentic())
            {
                return false;
            }

            rebootRequired = true;
            return true;
        }

        /// <summary>
        /// Verifies that the default AcpiBridge driver folder next to the application executable is unmodified and complete.
        /// </summary>
        public static bool VerifyDriverPackage(out string failureReason)
        {
            return VerifyDriverPackage(GetExpectedDriverDirectory(), out failureReason);
        }

        /// <summary>
        /// Verifies that <paramref name="driverDir"/> is the default AcpiBridge folder and contains only the pinned Clevo/Insyde driver files.
        /// </summary>
        public static bool VerifyDriverPackage(string driverDir, out string failureReason)
        {
            List<FileStream> lockedStreams;
            bool ok = LockAndVerifyDriverPackage(driverDir, out lockedStreams, out failureReason);
            DisposeStreams(lockedStreams);
            return ok;
        }

        private static string GetExpectedDriverDirectory()
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            return NormalizeFullPath(Path.Combine(baseDir, "AcpiBridge"));
        }

        private static string NormalizeFullPath(string path)
        {
            string fullPath = Path.GetFullPath(path);
            if (fullPath.Length > 3)
            {
                fullPath = fullPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            }
            return fullPath;
        }

        private static bool IsReparsePoint(string path)
        {
            try
            {
                return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
            }
            catch (Exception ex)
            {
                AppLogger.Log("AcpiDriverInstaller.IsReparsePoint", ex);
                return true;
            }
        }

        private static string ResolveInstalledSysPath()
        {
            string primary = Path.Combine(Environment.SystemDirectory, @"drivers\AcpiBridge.sys");
            if (File.Exists(primary))
            {
                return primary;
            }

            string secondary = Path.Combine(Environment.SystemDirectory, @"drivers\AcpiBridge1.sys");
            if (File.Exists(secondary))
            {
                return secondary;
            }

            foreach (string serviceName in new[] { "AcpiBridge", "AcpiBridge1" })
            {
                try
                {
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + serviceName))
                    {
                        string imagePath = key?.GetValue("ImagePath") as string;
                        if (string.IsNullOrWhiteSpace(imagePath))
                        {
                            continue;
                        }

                        string expanded = imagePath.Trim();
                        if (expanded.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
                        {
                            string winDir = Path.GetDirectoryName(Environment.SystemDirectory) ?? @"C:\Windows";
                            expanded = Path.Combine(winDir, expanded.Substring(@"\SystemRoot\".Length));
                        }
                        if (File.Exists(expanded))
                        {
                            return expanded;
                        }
                    }
                }
                catch (Exception ex)
                {
                    AppLogger.Log("AcpiDriverInstaller.ResolveInstalledSysPath", ex);
                }
            }

            return null;
        }

        private static bool IsInstalledSysAuthentic()
        {
            try
            {
                string sysPath = ResolveInstalledSysPath();
                if (string.IsNullOrEmpty(sysPath) || IsReparsePoint(sysPath))
                {
                    lock (InstalledSysCacheLock)
                    {
                        _cachedSysLength = -1;
                        _cachedSysWriteTicks = -1;
                        _cachedSysAuthentic = false;
                    }
                    return false;
                }

                var info = new FileInfo(sysPath);
                long length = info.Length;
                long writeTicks = info.LastWriteTimeUtc.Ticks;
                lock (InstalledSysCacheLock)
                {
                    if (_cachedSysLength == length && _cachedSysWriteTicks == writeTicks)
                    {
                        return _cachedSysAuthentic;
                    }
                }

                bool authentic = false;
                foreach (ExpectedDriverFile expected in ExpectedDriverFiles)
                {
                    if (!expected.FileName.EndsWith(".sys", StringComparison.OrdinalIgnoreCase) || expected.Length != length)
                    {
                        continue;
                    }

                    using (var fs = new FileStream(sysPath, FileMode.Open, FileAccess.Read, FileShare.Read))
                    {
                        if (fs.Length == expected.Length &&
                            string.Equals(ComputeStreamSha256Hex(fs), expected.Sha256, StringComparison.OrdinalIgnoreCase))
                        {
                            authentic = true;
                            break;
                        }
                    }
                }

                lock (InstalledSysCacheLock)
                {
                    _cachedSysLength = length;
                    _cachedSysWriteTicks = writeTicks;
                    _cachedSysAuthentic = authentic;
                }

                return authentic;
            }
            catch (Exception ex)
            {
                AppLogger.Log("AcpiDriverInstaller.IsInstalledSysAuthentic", ex);
                return false;
            }
        }

        private static bool LockAndVerifyDriverPackage(string driverDir, out List<FileStream> lockedStreams, out string failureReason)
        {
            lockedStreams = new List<FileStream>();
            failureReason = null;

            try
            {
                if (string.IsNullOrWhiteSpace(driverDir))
                {
                    failureReason = LocalizationManager.T("DriverErrEmptyPath", "AcpiBridge driver directory path is empty.");
                    return false;
                }

                string expectedDir = GetExpectedDriverDirectory();
                string normalizedDir = NormalizeFullPath(driverDir);
                if (!string.Equals(normalizedDir, expectedDir, StringComparison.OrdinalIgnoreCase))
                {
                    failureReason = LocalizationManager.T("DriverErrWrongDir", "Driver directory does not match the pinned application AcpiBridge folder.");
                    return false;
                }

                string baseDir = NormalizeFullPath(AppDomain.CurrentDomain.BaseDirectory);
                if (!Directory.Exists(normalizedDir) || IsReparsePoint(baseDir) || IsReparsePoint(normalizedDir))
                {
                    failureReason = LocalizationManager.T("DriverErrMissingOrReparse", "AcpiBridge driver folder is missing or uses an unsafe reparse point.");
                    return false;
                }

                if (Directory.GetDirectories(normalizedDir).Length != 0)
                {
                    failureReason = LocalizationManager.T("DriverErrSubdir", "Unexpected subdirectory detected inside AcpiBridge driver folder.");
                    return false;
                }

                string[] actualFiles = Directory.GetFiles(normalizedDir);
                if (actualFiles.Length != ExpectedDriverFiles.Length)
                {
                    failureReason = LocalizationManager.T("DriverErrFileCount", "AcpiBridge driver folder file count does not match the pinned manifest.");
                    return false;
                }

                var expectedByName = new Dictionary<string, ExpectedDriverFile>(StringComparer.OrdinalIgnoreCase);
                foreach (ExpectedDriverFile expected in ExpectedDriverFiles)
                {
                    expectedByName[expected.FileName] = expected;
                }

                var verifiedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (string actualPath in actualFiles)
                {
                    string fileName = Path.GetFileName(actualPath);
                    if (!expectedByName.TryGetValue(fileName, out ExpectedDriverFile expected))
                    {
                        failureReason = LocalizationManager.Format("DriverErrUnauthorizedFileFmt", fileName);
                        DisposeStreams(lockedStreams);
                        return false;
                    }

                    if (!VerifySingleDriverFile(actualPath, expected, lockedStreams, out failureReason))
                    {
                        DisposeStreams(lockedStreams);
                        return false;
                    }

                    verifiedNames.Add(expected.FileName);
                }

                if (verifiedNames.Count != ExpectedDriverFiles.Length)
                {
                    failureReason = LocalizationManager.T("DriverErrMissingFile", "One or more required AcpiBridge driver files are missing.");
                    DisposeStreams(lockedStreams);
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                failureReason = ex.Message;
                DisposeStreams(lockedStreams);
                return false;
            }
        }

        private static bool VerifySingleDriverFile(
            string filePath,
            ExpectedDriverFile expected,
            List<FileStream> lockedStreams,
            out string failureReason)
        {
            failureReason = null;

            if (IsReparsePoint(filePath))
            {
                failureReason = LocalizationManager.Format("DriverErrReparseFileFmt", expected.FileName);
                return false;
            }

            // Keep read-share lock held until verification/installation completes to block concurrent tampering.
            var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            lockedStreams.Add(fs);

            if (fs.Length != expected.Length)
            {
                failureReason = LocalizationManager.Format("DriverErrSizeFmt", expected.FileName);
                return false;
            }

            string actualHash = ComputeStreamSha256Hex(fs);
            if (!string.Equals(actualHash, expected.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                failureReason = LocalizationManager.Format("DriverErrHashFmt", expected.FileName);
                return false;
            }

            if (expected.CertThumbprint != null)
            {
                using (X509Certificate baseCert = X509Certificate.CreateFromSignedFile(filePath))
                using (var cert2 = new X509Certificate2(baseCert))
                {
                    if (!string.Equals(cert2.Thumbprint, expected.CertThumbprint, StringComparison.OrdinalIgnoreCase))
                    {
                        failureReason = LocalizationManager.Format("DriverErrCertFmt", expected.FileName);
                        return false;
                    }
                }
            }

            return true;
        }

        private static string ComputeStreamSha256Hex(FileStream stream)
        {
            stream.Position = 0;
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(stream);
                var sb = new StringBuilder(hash.Length * 2);
                foreach (byte b in hash)
                {
                    sb.Append(b.ToString("X2"));
                }
                return sb.ToString();
            }
        }

        private static void DisposeStreams(List<FileStream> streams)
        {
            if (streams == null)
            {
                return;
            }

            foreach (FileStream stream in streams)
            {
                try
                {
                    stream?.Dispose();
                }
                catch (Exception ex)
                {
                    AppLogger.Log("AcpiDriverInstaller.DisposeStreams", ex);
                }
            }

            streams.Clear();
        }

        private static void EnableShutdownPrivilege()
        {
            try
            {
                using (Process current = Process.GetCurrentProcess())
                {
                    if (OpenProcessToken(current.Handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out IntPtr hToken))
                    {
                        try
                        {
                            TokenPrivileges tp = new TokenPrivileges
                            {
                                PrivilegeCount = 1,
                                Attributes = SE_PRIVILEGE_ENABLED
                            };
                            if (LookupPrivilegeValue(null, SE_SHUTDOWN_NAME, out tp.Luid))
                            {
                                AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                            }
                        }
                        finally
                        {
                            CloseHandle(hToken);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                AppLogger.Log("AcpiDriverInstaller.EnableShutdownPrivilege", ex);
            }
        }

        public static void RestartComputer()
        {
            try
            {
                EnableShutdownPrivilege();

                string shutdownPath = ProcessRunner.ResolveSystemTool("shutdown.exe");
                if (ProcessRunner.Run(shutdownPath, "/r /t 0 /f", 3000, out _) == 0)
                {
                    return;
                }

                if (ExitWindowsEx(EWX_REBOOT | EWX_FORCE, 0x00020000 | 0x00000004 | 0x40000000))
                {
                    return;
                }
            }
            catch (Exception ex)
            {
                AppLogger.Log("RestartComputer", ex);
            }

            try
            {
                string psPath = ProcessRunner.ResolveSystemTool("powershell.exe");
                ProcessRunner.Run(psPath, "-NoProfile -ExecutionPolicy Bypass -Command Restart-Computer -Force", 3000, out _);
            }
            catch (Exception ex)
            {
                AppLogger.Log("RestartComputerFallback", ex);
            }
        }

        public static bool UninstallDriver()
        {
            try
            {
                StartupManager.SetRunAtStartup(false);

                string scPath = ProcessRunner.ResolveSystemTool("sc.exe");
                ProcessRunner.Run(scPath, "stop AcpiBridge", 10000, out _);
                ProcessRunner.Run(scPath, "delete AcpiBridge", 10000, out _);
                ProcessRunner.Run(scPath, "stop AcpiBridge1", 10000, out _);
                ProcessRunner.Run(scPath, "delete AcpiBridge1", 10000, out _);

                RunPnpUtil("/remove-device /deviceid \"ACPI\\CLV0001\"");
                RunPnpUtil("/remove-device /deviceid \"ACPI\\CLV0002\"");
                RunPnpUtil("/remove-device \"ACPI\\CLV0001\\1\"");

                DeletePublishedDriversMatching("acpibridge");

                RunPnpUtil("/scan-devices");
                return true;
            }
            catch (Exception ex)
            {
                AppLogger.Log("UninstallDriver", ex);
                return false;
            }
        }

        private static void DeletePublishedDriversMatching(string pattern)
        {
            try
            {
                string pnpPath = ProcessRunner.ResolveSystemTool("pnputil.exe");
                if (ProcessRunner.Run(pnpPath, "/enum-drivers", 10000, out string output) >= 0 && !string.IsNullOrEmpty(output))
                {
                    var lines = output.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
                    string currentPublishedName = null;

                    foreach (string line in lines)
                    {
                        string trimmed = line.Trim();
                        if (trimmed.StartsWith("Published Name:", StringComparison.OrdinalIgnoreCase))
                        {
                            currentPublishedName = trimmed.Substring(trimmed.IndexOf(':') + 1).Trim();
                        }
                        else if (trimmed.StartsWith("Original Name:", StringComparison.OrdinalIgnoreCase))
                        {
                            string origName = trimmed.Substring(trimmed.IndexOf(':') + 1).Trim();
                            if (origName.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0 && IsSafePublishedInfName(currentPublishedName))
                            {
                                RunPnpUtil(string.Format("/delete-driver {0} /uninstall /force", currentPublishedName));
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                AppLogger.Log("DeletePublishedDriversMatching", ex);
            }
        }

        private static bool IsSafePublishedInfName(string name)
        {
            if (string.IsNullOrEmpty(name) || name.Length < 8 || name.Length > 32)
            {
                return false;
            }
            if (!name.StartsWith("oem", StringComparison.OrdinalIgnoreCase) ||
                !name.EndsWith(".inf", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
            for (int i = 3; i < name.Length - 4; i++)
            {
                if (name[i] < '0' || name[i] > '9')
                {
                    return false;
                }
            }
            return true;
        }

        private static int RunPnpUtil(string arguments, out string output)
        {
            output = string.Empty;
            try
            {
                string pnpPath = ProcessRunner.ResolveSystemTool("pnputil.exe");
                int code = ProcessRunner.Run(pnpPath, arguments, 15000, out string raw);
                output = raw.Trim();
                return code;
            }
            catch (Exception ex)
            {
                AppLogger.Log("RunPnpUtil", ex);
                return -1;
            }
        }

        private static void RunPnpUtil(string arguments)
        {
            RunPnpUtil(arguments, out _);
        }

        private static void EnsureEventLogSource()
        {
            try
            {
                if (!EventLog.SourceExists("PowerBIOSServer_Out"))
                {
                    EventLog.CreateEventSource("PowerBIOSServer_Out", "OutLog");
                }
            }
            catch (Exception ex)
            {
                AppLogger.Log("AcpiDriverInstaller.EnsureEventLogSource", ex);
            }
        }
    }
}
