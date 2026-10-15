<#
.SYNOPSIS
    Disables the Intel QUEENCREEK telemetry task that triggers McAfee RealProtect false positives.

.DESCRIPTION
    Intel's System Usage Report (SUR) registers a scheduled task \USER_ESRV_SVC_QUEENCREEK
    that spawns powershell.exe with -WindowStyle Hidden to launch task.bat.
    McAfee RealProtect flags this hidden PowerShell call as obfuscated malware on logon.
    
    Disabling this task stops the false alert from popping up on reboot/logon.
    It does NOT affect display drivers, Intel Graphics Software UI, or graphics performance.

.EXAMPLE
    # Run from an elevated (Administrator) PowerShell terminal:
    .\silence-telemetry-alert.ps1
#>

[CmdletBinding()]
param(
    [Switch]$ReEnable
)

$taskName = "USER_ESRV_SVC_QUEENCREEK"

# Check elevation
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "This script requires Administrator privileges to modify scheduled tasks. Please restart PowerShell as Administrator."
    exit 1
}

$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

if (-not $task) {
    Write-Host "Task '\$taskName' was not found on this system. Nothing to do." -ForegroundColor Yellow
    exit 0
}

if ($ReEnable) {
    Enable-ScheduledTask -TaskName $taskName
    Write-Host "[+] Task '\$taskName' has been re-enabled." -ForegroundColor Green
} else {
    Disable-ScheduledTask -TaskName $taskName
    Write-Host "[+] Successfully disabled '\$taskName'." -ForegroundColor Green
    Write-Host "    McAfee RealProtect will no longer be triggered on user logon." -ForegroundColor Cyan
    Write-Host "    (To re-enable later, run: .\silence-telemetry-alert.ps1 -ReEnable)" -ForegroundColor DarkGray
}
