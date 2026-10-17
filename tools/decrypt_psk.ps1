<#
.SYNOPSIS
    Decrypts the Goodix 27c6:5e0a DPAPI blob to recover the machine's TLS Pre-Shared Key (PSK).

.DESCRIPTION
    The Goodix 5e0a sensor stores the TLS PSK sealed via Windows DPAPI under the SYSTEM
    account (WbioSrvc). This script reads dpapi_blob.bin, calls CryptUnprotectData() under
    SYSTEM privileges, verifies the 32-byte key against the MCU SHA-256 hash, and saves
    the resulting key to goodix-5e0a.psk.

.USAGE
    1. Copy dpapi_blob.bin (and optionally mcu_hash.txt) to this directory.
    2. Open PowerShell as Administrator.
    3. Run:
       powershell -ExecutionPolicy Bypass -File .\decrypt_psk.ps1
#>

param(
    [string]$BlobPath = "dpapi_blob.bin",
    [string]$HashPath = "mcu_hash.txt",
    [string]$OutputPath = "goodix-5e0a.psk",
    [switch]$Force,
    [switch]$RunAsSystem
)

$ErrorActionPreference = "Stop"

function Decrypt-BlobCore {
    param([byte[]]$EncryptedBytes)

    $definition = @"
using System;
using System.Runtime.InteropServices;
using System.ComponentModel;

public class GoodixDpapi {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct DATA_BLOB {
        public int cbData;
        public IntPtr pbData;
    }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool CryptUnprotectData(
        ref DATA_BLOB pDataIn,
        string ppszDataDescr,
        ref DATA_BLOB pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        int dwFlags,
        ref DATA_BLOB pDataOut
    );

    [DllImport("kernel32.dll")]
    public static extern IntPtr LocalFree(IntPtr hMem);

    public static byte[] Unprotect(byte[] cipherText) {
        DATA_BLOB inBlob = new DATA_BLOB();
        DATA_BLOB outBlob = new DATA_BLOB();
        DATA_BLOB emptyEntropy = new DATA_BLOB();

        inBlob.cbData = cipherText.Length;
        inBlob.pbData = Marshal.AllocHGlobal(cipherText.Length);
        Marshal.Copy(cipherText, 0, inBlob.pbData, cipherText.Length);

        try {
            if (!CryptUnprotectData(ref inBlob, null, ref emptyEntropy, IntPtr.Zero, IntPtr.Zero, 0, ref outBlob)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            byte[] plain = new byte[outBlob.cbData];
            Marshal.Copy(outBlob.pbData, plain, 0, outBlob.cbData);
            if (outBlob.pbData != IntPtr.Zero) {
                LocalFree(outBlob.pbData);
            }
            return plain;
        } finally {
            if (inBlob.pbData != IntPtr.Zero) {
                Marshal.FreeHGlobal(inBlob.pbData);
            }
        }
    }
}
"@

    if (-not ([System.Management.Automation.PSTypeName]'GoodixDpapi').Type) {
        Add-Type -TypeDefinition $definition
    }

    return [GoodixDpapi]::Unprotect($EncryptedBytes)
}

$currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$isSystem = $currentIdentity.IsSystem

# Resolve paths
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ScriptDir) { $ScriptDir = Get-Location }
$ResolvedBlob = Join-Path $ScriptDir $BlobPath
$ResolvedHash = Join-Path $ScriptDir $HashPath
$ResolvedOutput = Join-Path $ScriptDir $OutputPath
$ResolvedLog = Join-Path $ScriptDir "system-log.txt"

if (-not (Test-Path $ResolvedBlob)) {
    Write-Error "ERROR: '$BlobPath' not found in $ScriptDir. Please extract it from Linux first."
    exit 1
}

function Get-DpapiBlobLength {
    param([byte[]]$data)
    if ($null -eq $data -or $data.Length -lt 48) { return $null }
    try {
        $descLen = [System.BitConverter]::ToUInt32($data, 44)
        $pos = 48 + $descLen
        if ($data.Length -lt $pos + 12) { return $null }
        $saltLen = [System.BitConverter]::ToUInt32($data, $pos + 8)
        $pos += 12 + $saltLen
        if ($data.Length -lt $pos + 4) { return $null }
        $promptLen = [System.BitConverter]::ToUInt32($data, $pos)
        $pos += 4 + $promptLen
        if ($data.Length -lt $pos + 12) { return $null }
        $signAlgoLen = [System.BitConverter]::ToUInt32($data, $pos + 4)
        $signSaltLen = [System.BitConverter]::ToUInt32($data, $pos + 8)
        $pos += 12 + $signSaltLen
        if ($data.Length -lt $pos + 4) { return $null }
        $dataLen = [System.BitConverter]::ToUInt32($data, $pos)
        $pos += 4 + $dataLen
        $signBytes = if ($signAlgoLen -gt 0) { [int]($signAlgoLen / 8) } else { 64 }
        $totalExp = $pos + 4 + $signBytes
        if ($data.Length -lt $pos + 4) {
            # pbData is complete, dwSignLen / HMAC signature is truncated
            return $totalExp
        }
        $signLen = [System.BitConverter]::ToUInt32($data, $pos)
        $pos += 4 + $signLen
        return $pos
    } catch {
        return $null
    }
}


# If not running as SYSTEM, self-elevate via a one-off SYSTEM scheduled task
if (-not $isSystem -and -not $RunAsSystem) {
    Write-Host "================================================================="
    Write-Host "Goodix 5e0a Key Unlocker"
    Write-Host "Current identity: $($currentIdentity.Name) (elevation required)"
    Write-Host "================================================================="

    $taskName = "GoodixPskExtractTemp"
    $scriptFile = $MyInvocation.MyCommand.Path
    $forceArg = if ($Force) { " -Force" } else { "" }
    $action = "powershell.exe -ExecutionPolicy Bypass -NoProfile -File `"$scriptFile`" -RunAsSystem$forceArg"

    if (Test-Path $ResolvedLog) {
        Remove-Item -Path $ResolvedLog -Force -ErrorAction SilentlyContinue
    }

    Write-Host "[*] Requesting system privilege to unlock the key..."
    # PowerShell 5.1 treats stderr redirection (2>&1) with $ErrorActionPreference='Stop'
    # as a terminating NativeCommandError when schtasks prints harmless warnings (e.g. German locale /ST warning).
    $origPref = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $createOutput = schtasks /create /tn $taskName /tr $action /sc once /st 00:00 /ru "NT AUTHORITY\SYSTEM" /rl HIGHEST /f 2>&1
    $createExit = $LASTEXITCODE
    $ErrorActionPreference = $origPref
    if ($createExit -ne 0) {
        Write-Error "Failed to elevate. Please run PowerShell as Administrator! Details: $createOutput"
        exit 1
    }

    try {
        Write-Host "[*] Unlocking key..."
        $ErrorActionPreference = "Continue"
        schtasks /run /tn $taskName 2>&1 | Out-Null
        $ErrorActionPreference = $origPref
        # Poll up to 20 seconds for the decrypted key output
        for ($i = 0; $i -lt 20 -and -not (Test-Path $ResolvedOutput); $i++) {
            Start-Sleep -Seconds 1
        }
    } finally {
        $ErrorActionPreference = "Continue"
        schtasks /delete /tn $taskName /f 2>&1 | Out-Null
        $ErrorActionPreference = $origPref
    }

    if (Test-Path $ResolvedOutput) {
        if (Test-Path $ResolvedLog) {
            Remove-Item -Path $ResolvedLog -Force -ErrorAction SilentlyContinue
        }
        $extractedKey = (Get-Content $ResolvedOutput).Trim()
        Write-Host ""
        Write-Host "[+] Extracted sensor encryption key:"
        Write-Host "    $extractedKey"
        Write-Host ""
        Write-Host "[+] Saved to: $ResolvedOutput"
        Write-Host "Next step: Copy '$OutputPath' back to Linux and place it at:"
        Write-Host "    /etc/libfprint/goodix-5e0a.psk"
        exit 0
    } else {
        if (Test-Path $ResolvedLog) {
            Write-Host "[-] SYSTEM task execution details:"
            Get-Content $ResolvedLog | ForEach-Object { Write-Host "    $_" }
        }
        Write-Error "[-] Decryption did not produce $OutputPath. Check if this is the original Windows installation that set up the fingerprint sensor."
        exit 1
    }
}

# Execution under SYSTEM
try {
    $logLines = [System.Collections.Generic.List[string]]::new()
    $bytes = [System.IO.File]::ReadAllBytes($ResolvedBlob)
    $logLines.Add("Read $($bytes.Length) bytes from $ResolvedBlob")

    $expectedLen = Get-DpapiBlobLength -data $bytes
    if ($null -ne $expectedLen) {
        if ($bytes.Length -gt $expectedLen) {
            $logLines.Add("Trimming trailing padding from $($bytes.Length) to $expectedLen bytes")
            $trimmed = [byte[]]::new($expectedLen)
            [System.Array]::Copy($bytes, 0, $trimmed, 0, $expectedLen)
            $bytes = $trimmed
        } elseif ($bytes.Length -lt $expectedLen) {
            $msg = "Blob appears truncated ($($bytes.Length) of $expectedLen bytes; dwSignLen / HMAC signature is missing). Re-dump using updated dump_dpapi_blob.py."
            $logLines.Add("ERROR: $msg")
            [System.IO.File]::WriteAllLines($ResolvedLog, $logLines)
            throw $msg
        }
    }

    $plain = Decrypt-BlobCore -EncryptedBytes $bytes

    if ($plain.Length -ne 32) {
        $logLines.Add("Warning: Decrypted payload length is $($plain.Length) bytes (expected 32 bytes).")
    }

    # Format as lowercase hex
    $hex = [System.BitConverter]::ToString($plain).Replace("-", "").ToLower()

    # Verify against mcu_hash.txt if present
    if (Test-Path $ResolvedHash) {
        $expectedHash = (Get-Content $ResolvedHash).Trim().ToLower()
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $computedHashBytes = $sha.ComputeHash($plain)
        $computedHashHex = [System.BitConverter]::ToString($computedHashBytes).Replace("-", "").ToLower()

        if ($computedHashHex -eq $expectedHash) {
            $logLines.Add("[+] Hash verification MATCHED: $computedHashHex")
        } elseif ($Force) {
            $logLines.Add("[-] WARNING: Key hash ($computedHashHex) does not match expected ($expectedHash). Writing output because -Force was specified.")
        } else {
            $msg = "Key hash mismatch ($computedHashHex vs $expectedHash). If you want to write the key anyway, re-run with -Force"
            $logLines.Add("ERROR: $msg")
            [System.IO.File]::WriteAllLines($ResolvedLog, $logLines)
            throw $msg
        }
    }

    [System.IO.File]::WriteAllText($ResolvedOutput, $hex + "`n")
    $logLines.Add("[+] Written to $ResolvedOutput")
    [System.IO.File]::WriteAllLines($ResolvedLog, $logLines)
} catch {
    $logLines.Add("Decryption failed under SYSTEM: $_")
    [System.IO.File]::WriteAllLines($ResolvedLog, $logLines)
    Write-Error "Decryption failed under SYSTEM: $_"
    exit 1
}
