import { describe, expect, it } from "vitest";
import {
  classifyPath,
  classifyWindowsPath,
  mapWindowsToWslPath,
  mapWslToWindowsPath,
  stripProviderDrive,
} from "../../../server/paths/index.js";

const winCtx = {
  os: "windows" as const,
  cwd: "C:\\repo",
  worktreeRoot: "C:\\repo",
  home: "C:\\Users\\alice",
  pluginDataDir: "C:\\Users\\alice\\.paseo\\permission-guardian",
  envSnapshot: {
    USERPROFILE: "C:\\Users\\alice",
    APPDATA: "C:\\Users\\alice\\AppData\\Roaming",
    LOCALAPPDATA: "C:\\Users\\alice\\AppData\\Local",
    PROGRAMDATA: "C:\\ProgramData",
    TEMP: "C:\\Users\\alice\\AppData\\Local\\Temp",
    TMP: "C:\\Users\\alice\\AppData\\Local\\Temp",
    SYSTEMROOT: "C:\\Windows",
    WINDIR: "C:\\Windows",
  },
};

describe("Windows & WSL bidirectional Path Model", () => {
  it("strips PowerShell provider drives and classifies Env/Cert/Registry targets", () => {
    expect(stripProviderDrive("Env:OPENAI_API_KEY")).toEqual({
      provider: "env",
      remainder: "OPENAI_API_KEY",
    });
    expect(stripProviderDrive("Microsoft.PowerShell.Core\\Environment::")).toEqual({
      provider: "env",
      remainder: "",
    });
    expect(stripProviderDrive("HKLM:\\SAM\\Domains")).toEqual({
      provider: "hklm",
      remainder: "\\SAM\\Domains",
    });
    expect(stripProviderDrive("C:\\repo\\src")).toBeNull();

    const envDump = classifyWindowsPath("Env:*", winCtx);
    expect(envDump.providerDrive).toBe("env");
    expect(envDump.isSensitive).toBe(true);

    const hklmSam = classifyWindowsPath("HKLM:\\SAM\\Domains", winCtx);
    expect(hklmSam.isSensitive).toBe(true);
    expect(hklmSam.isProtected).toBe(true);

    const hkcuEnv = classifyWindowsPath("HKCU:\\Environment", winCtx);
    expect(hkcuEnv.isSensitive).toBe(true);
    expect(hkcuEnv.isProtected).toBe(true);
  });

  it("normalizes NTFS trailing dots/spaces unless verbatim \\\\?\\ prefix is used", () => {
    const trailingGitDot = classifyWindowsPath("C:\\repo\\.git.\\hooks\\pre-commit", winCtx);
    expect(trailingGitDot.isProtected).toBe(true);

    const trailingGitSpace = classifyWindowsPath("C:\\repo\\.git \\config", winCtx);
    expect(trailingGitSpace.isProtected).toBe(true);

    const trailingEnvDot = classifyWindowsPath(".env. ", winCtx);
    expect(trailingEnvDot.isSensitive).toBe(true);

    const verbatimEnv = classifyWindowsPath("\\\\?\\C:\\repo\\.env.", winCtx);
    expect(verbatimEnv.normalized).toBe("C:\\repo\\.env.");
  });

  it("handles NTFS Alternate Data Streams (::$DATA and Zone.Identifier) and reserved devices", () => {
    const envAds = classifyWindowsPath("C:\\repo\\.env::$DATA", winCtx);
    expect(envAds.isSensitive).toBe(true);
    expect(envAds.adsStream).toBe(":$DATA");

    const zoneAds = classifyWindowsPath("C:\\repo\\download.exe:Zone.Identifier", winCtx);
    expect(zoneAds.adsStream).toBe("Zone.Identifier");

    const nulDev = classifyWindowsPath("C:\\repo\\NUL.txt", winCtx);
    expect(nulDev.isReservedDevice).toBe(true);
    expect(classifyWindowsPath("CON", winCtx).isReservedDevice).toBe(true);
  });

  it("flags drive-relative paths and unresolved 8.3 short names", () => {
    const driveRel = classifyWindowsPath("C:foo.txt", winCtx);
    expect(driveRel.isDriveRelative).toBe(true);

    const shortName = classifyWindowsPath("C:\\PROGRA~1\\secret.pem", winCtx);
    expect(shortName.hasUnresolvedShortName).toBe(true);
    expect(shortName.isSensitive).toBe(true);
  });

  it("handles remote UNC, loopback admin share, and WSL UNC safely", () => {
    const remoteUnc = classifyWindowsPath("\\\\evil.example.com\\share\\doc.txt", winCtx);
    expect(remoteUnc.isRemoteUnc).toBe(true);

    const remoteWebDav = classifyWindowsPath("\\\\evil.example.com@SSL\\DavWWWRoot\\x", winCtx);
    expect(remoteWebDav.isRemoteUnc).toBe(true);

    const loopbackSsh = classifyWindowsPath("\\\\localhost\\c$\\Users\\alice\\.ssh\\id_rsa", winCtx);
    expect(loopbackSsh.isRemoteUnc).toBeFalsy();
    expect(loopbackSsh.isSensitive).toBe(true);

    const wslUnc = classifyWindowsPath("\\\\wsl.localhost\\Ubuntu\\home\\alice\\.ssh\\id_rsa", winCtx);
    expect(wslUnc.isWslUnc).toBe(true);
    expect(wslUnc.isRemoteUnc).toBeFalsy();
    expect(wslUnc.wslMappedLinuxPath).toBe("/home/alice/.ssh/id_rsa");
    expect(wslUnc.isSensitive).toBe(true);
  });

  it("maps Windows <-> WSL paths bidirectionally and checks DrvFs case-insensitively", () => {
    expect(mapWindowsToWslPath("C:\\repo\\src")).toBe("/mnt/c/repo/src");
    expect(mapWindowsToWslPath("\\\\wsl$\\Ubuntu\\etc\\shadow")).toBe("/etc/shadow");
    expect(mapWslToWindowsPath("/mnt/c/repo/src")).toBe("C:\\repo\\src");

    const drvfsGit = classifyPath("/mnt/c/repo/.GIT/hooks/pre-commit", {
      cwd: "/mnt/c/repo",
      worktreeRoot: "/mnt/c/repo",
      home: "/home/alice",
    });
    expect(drvfsGit.isProtected).toBe(true);

    const drvfsCreds = classifyPath("/mnt/c/Users/alice/AppData/Roaming/Microsoft/Credentials/blob", {
      cwd: "/mnt/c/repo",
      worktreeRoot: "/mnt/c/repo",
      home: "/home/alice",
    });
    expect(drvfsCreds.isSensitive).toBe(true);
  });

  it("identifies Windows sensitive and protected catalogs (DPAPI, browsers, PSReadLine, Startup, PATH hijack)", () => {
    const sensitiveCases = [
      "%APPDATA%\\Microsoft\\Credentials\\DF123",
      "%LOCALAPPDATA%\\Microsoft\\Vault\\4BF4C442",
      "%APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
      "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data",
      "%APPDATA%\\Mozilla\\Firefox\\Profiles\\abc.default\\key4.db",
      "%APPDATA%\\NuGet\\NuGet.Config",
      "C:\\Windows\\System32\\config\\SAM",
      "C:\\keys\\mykey.ppk",
      "C:\\vault\\work.kdbx",
    ];
    for (const p of sensitiveCases) {
      expect(classifyWindowsPath(p, winCtx).isSensitive, `expected sensitive: ${p}`).toBe(true);
    }

    const protectedCases = [
      "C:\\Users\\alice\\Documents\\PowerShell\\Microsoft.PowerShell_profile.ps1",
      "C:\\Users\\alice\\OneDrive\\Documents\\WindowsPowerShell\\profile.ps1",
      "C:\\Users\\alice\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.bat",
      "C:\\Windows\\System32\\Tasks\\MyTask",
      "%LOCALAPPDATA%\\Microsoft\\WindowsApps\\git.exe",
      "C:\\Users\\alice\\scoop\\shims\\python.exe",
      "C:\\repo\\.GIT\\config",
    ];
    for (const p of protectedCases) {
      expect(classifyWindowsPath(p, winCtx).isProtected, `expected protected: ${p}`).toBe(true);
    }
  });
});
