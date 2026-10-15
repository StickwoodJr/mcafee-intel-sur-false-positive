<#
.SYNOPSIS
    Verifies if your McAfee "fileless threat" / RealProtect alert was triggered by Intel's QUEENCREEK telemetry task.

.DESCRIPTION
    This script inspects:
    1. The \USER_ESRV_SVC_QUEENCREEK scheduled task and its command line.
    2. The Authenticode digital signature on Intel's task.exe binary.
    3. McAfee's internal detection.log for RealProtect.DetectEncAndObfusPowershell events.
    4. Task Scheduler operational logs for Event ID 203 / 101 with error code 2147942625 (0x800700E1).

.EXAMPLE
    .\verify-intel-task.ps1
#>

[CmdletBinding()]
param()

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Intel SUR / McAfee RealProtect False Positive Verifier  " -ForegroundColor Cyan
Write-Host "==========================================================`n" -ForegroundColor Cyan

# 1. Check Scheduled Task
Write-Host "[1/4] Checking Scheduled Task \USER_ESRV_SVC_QUEENCREEK..." -ForegroundColor Yellow
$task = Get-ScheduledTask -TaskName "USER_ESRV_SVC_QUEENCREEK" -ErrorAction SilentlyContinue

if ($task) {
    Write-Host "  [+] Task found!" -ForegroundColor Green
    Write-Host "      State   : $($task.State)"
    Write-Host "      Action  : $($task.Actions.Execute) $($task.Actions.Arguments)"
    Write-Host "      Working : $($task.Actions.WorkingDirectory)"
} else {
    Write-Host "  [-] Task \USER_ESRV_SVC_QUEENCREEK was not found on this system." -ForegroundColor Red
}

# 2. Check task.exe Authenticode Signature
Write-Host "`n[2/4] Verifying Intel Authenticode Signature..." -ForegroundColor Yellow
$taskExePath = "C:\Program Files\Intel\SUR\QUEENCREEK\x64\task.exe"

if (Test-Path -LiteralPath $taskExePath) {
    $sig = Get-AuthenticodeSignature -LiteralPath $taskExePath
    if ($sig.Status -eq "Valid") {
        Write-Host "  [+] Signature: VALID" -ForegroundColor Green
        Write-Host "      Subject    : $($sig.SignerCertificate.Subject)"
        Write-Host "      Thumbprint : $($sig.SignerCertificate.Thumbprint)"
    } else {
        Write-Host "  [!] Signature status: $($sig.Status) ($($sig.StatusMessage))" -ForegroundColor Red
    }
} else {
    Write-Host "  [-] File not found at expected path: $taskExePath" -ForegroundColor DarkGray
}

# 3. Check McAfee detection.log
Write-Host "`n[3/4] Checking McAfee detection.log for RealProtect blocks..." -ForegroundColor Yellow
$mcafeeLog = "C:\ProgramData\McAfee\wps\detection.log"

if (Test-Path -LiteralPath $mcafeeLog) {
    $matches = Get-Content -LiteralPath $mcafeeLog -ErrorAction SilentlyContinue |
        Where-Object { $_ -match "RealProtect\.DetectEncAndObfusPowershell" }

    if ($matches) {
        Write-Host "  [+] Found $($matches.Count) matching RealProtect detection entry/entries in McAfee logs:" -ForegroundColor Green
        foreach ($entry in ($matches | Select-Object -Last 3)) {
            Write-Host "      $entry" -ForegroundColor DarkCyan
        }
    } else {
        Write-Host "  [-] No RealProtect.DetectEncAndObfusPowershell entries found in $mcafeeLog." -ForegroundColor DarkGray
    }
} else {
    Write-Host "  [-] McAfee detection log not accessible or not found at $mcafeeLog." -ForegroundColor DarkGray
}

# 4. Check Task Scheduler Event Log for blocked launches (Error 2147942625 / 0x800700E1)
Write-Host "`n[4/4] Checking Windows Task Scheduler logs for blocked task launches..." -ForegroundColor Yellow
try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-TaskScheduler/Operational'
        Id      = @(101, 203)
    } -MaxEvents 50 -ErrorAction Stop |
    Where-Object { $_.Message -match "USER_ESRV_SVC_QUEENCREEK" -and $_.Message -match "2147942625" }

    if ($events) {
        Write-Host "  [+] Found blocked task events (Error 2147942625 = ERROR_VIRUS_INFECTED):" -ForegroundColor Green
        foreach ($e in ($events | Select-Object -First 3)) {
            Write-Host "      [$($e.TimeCreated)] ID $($e.Id): $($e.Message.Trim())" -ForegroundColor DarkYellow
        }
    } else {
        Write-Host "  [-] No failed launch events (error 2147942625) recorded for USER_ESRV_SVC_QUEENCREEK." -ForegroundColor DarkGray
    }
} catch {
    Write-Host "  [!] Unable to query Task Scheduler operational event log (requires admin or log is empty)." -ForegroundColor DarkGray
}

Write-Host "`nDone." -ForegroundColor Cyan
