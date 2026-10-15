# Technical Analysis & Forensic Correlation

This document breaks down the log evidence I pulled while connecting the recurring McAfee alerts to Intel's QUEENCREEK scheduled task.

---

## 1. McAfee Local Detection Log

When McAfee's toast notification appeared, the desktop UI provided zero details—no filename, no process ID, and no threat family name. However, McAfee's RealProtect engine writes raw JSON lines to `C:\ProgramData\McAfee\wps\detection.log`.

Here are the entries recorded on my machine on October 14, 2026:

```json
{"timestamp":"2026-10-14T15:25:34.349Z","target_name":"\\\\?\\C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","initiator_name":"\\\\?\\C:\\Windows\\System32\\svchost.exe","sensor":"process create","target_hash":"60c9b29843624dd8af6b6a7b26147753be6aeef65098b9a503cc50850afe410f","target_url":"","tlsh":"","detection_name":"RealProtect.DetectEncAndObfusPowershell!72b6875643f7","final_result":"infected","all":[{"final_detection_source":"rp-d","file_rep":0,"hti_rep":1,"url_rep":0,"cert_rep":[]}]}
{"timestamp":"2026-10-14T15:33:22.063Z","target_name":"\\\\?\\C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","initiator_name":"\\\\?\\C:\\Windows\\System32\\svchost.exe","sensor":"process create","target_hash":"60c9b29843624dd8af6b6a7b26147753be6aeef65098b9a503cc50850afe410f","target_url":"","tlsh":"","detection_name":"RealProtect.DetectEncAndObfusPowershell!72b6875643f7","final_result":"infected","all":[{"final_detection_source":"rp-d","file_rep":0,"hti_rep":1,"url_rep":0,"cert_rep":[]}]}
{"timestamp":"2026-10-14T17:38:21.186Z","target_name":"\\\\?\\C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","initiator_name":"\\\\?\\C:\\Windows\\System32\\svchost.exe","sensor":"process create","target_hash":"60c9b29843624dd8af6b6a7b26147753be6aeef65098b9a503cc50850afe410f","target_url":"","tlsh":"","detection_name":"RealProtect.DetectEncAndObfusPowershell!72b6875643f7","final_result":"infected","all":[{"final_detection_source":"rp-d","file_rep":0,"hti_rep":1,"url_rep":0,"cert_rep":[]}]}
{"timestamp":"2026-10-14T21:07:15.067Z","target_name":"\\\\?\\C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","initiator_name":"\\\\?\\C:\\Windows\\System32\\svchost.exe","sensor":"process create","target_hash":"60c9b29843624dd8af6b6a7b26147753be6aeef65098b9a503cc50850afe410f","target_url":"","tlsh":"","detection_name":"RealProtect.DetectEncAndObfusPowershell!72b6875643f7","final_result":"infected","all":[{"final_detection_source":"rp-d","file_rep":0,"hti_rep":1,"url_rep":0,"cert_rep":[]}]}
```

### Key takeaways from McAfee's log:
- **Initiator:** `C:\Windows\System32\svchost.exe`. This is the Windows service host process running the Task Scheduler service (`Schedule`).
- **Target:** `powershell.exe` (SHA256: `60c9b29843624dd8af6b6a7b26147753be6aeef65098b9a503cc50850afe410f`). This is the clean, Microsoft-signed Windows PowerShell binary.
- **Sensor:** `process create`. McAfee intercepted the `CreateProcess` call before PowerShell actually initialized.
- **Rule:** `RealProtect.DetectEncAndObfusPowershell!72b6875643f7` from the `rp-d` (RealProtect Dynamic) heuristic engine.

---

## 2. Windows Task Scheduler Operational Logs

Checking `Microsoft-Windows-TaskScheduler/Operational` around those exact seconds revealed what `svchost.exe` was trying to launch.

At **11:25:33.975 AM EDT** (right as Intel Graphics Software completed setup):

```
TimeCreated : 2026-10-14T11:25:33.9753042-04:00
Event ID    : 119 (LogonTrigger)
Message     : Task Scheduler launched "{2b4700f0-8adb-4b67-a3bf-a6d55a4a72b2}" instance of task "\USER_ESRV_SVC_QUEENCREEK" due to user logon.

TimeCreated : 2026-10-14T11:25:33.9976099-04:00
Event ID    : 203 (ActionLaunchFailure)
Message     : Task Scheduler failed to launch action "C:\windows\System32\WindowsPowerShell\v1.0\powershell.EXE" in instance "{2b4700f0-8adb-4b67-a3bf-a6d55a4a72b2}" of task "\USER_ESRV_SVC_QUEENCREEK". Additional Data: Error Value: 2147942625.

TimeCreated : 2026-10-14T11:25:33.9977348-04:00
Event ID    : 101 (TaskStartFailed)
Message     : Task Scheduler failed to start "\USER_ESRV_SVC_QUEENCREEK" task for user "NT AUTHORITY\SYSTEM". Additional Data: Error Value: 2147942625.
```

The exact same three-event sequence repeated at:
- **11:33:21 AM EDT** (following the post-update reboot)
- **1:38:20 PM EDT** (following a later restart)
- **5:07:14 PM EDT** (following background evaluation)

### Decoding Error Value `2147942625`:
- `2147942625` in decimal = `0x800700E1` in hexadecimal.
- Win32 facility code `7` (`0x0007`) with error `0x00E1` (`225`).
- Win32 Error 225: `ERROR_VIRUS_INFECTED`
- Official Windows description: *"Operation did not complete successfully because the file contains a virus or potentially unwanted software."*

This confirms that Windows didn't fail due to file permissions or missing paths; the OS was explicitly told by McAfee's minifilter driver to abort process creation because it considered PowerShell infected.

---

## 3. Deconstructing the Intel QUEENCREEK Task

Checking the task definition in PowerShell:

```powershell
Get-ScheduledTask -TaskName "USER_ESRV_SVC_QUEENCREEK" | Select-Object -ExpandProperty Actions
```

Returns:
- **Execute:** `powershell`
- **Arguments:** `-Command "Start-Process -WindowStyle Hidden task.bat"`
- **WorkingDirectory:** `C:\Program Files\Intel\SUR\QUEENCREEK\x64\`

Looking inside `C:\Program Files\Intel\SUR\QUEENCREEK\x64\task.bat`:

```bat
"C:\Program Files\Intel\SUR\QUEENCREEK\x64\task.exe"
```

And checking `task.exe` with `Get-AuthenticodeSignature`:

```powershell
Get-AuthenticodeSignature 'C:\Program Files\Intel\SUR\QUEENCREEK\x64\task.exe' | Format-List
```

```
Path          : C:\Program Files\Intel\SUR\QUEENCREEK\x64\task.exe
Status        : Valid
StatusMessage : Signature verified.
SignerCertificate:
    Subject    : CN=Intel Corporation, O=Intel Corporation, L=Santa Clara, S=California, C=US
    Thumbprint : E52C200602123A38F63E072B02CE5DD877E4C6F6
```

### The Execution Chain:
1. I log into Windows.
2. Windows Task Scheduler (`svchost.exe`) evaluates triggers and fires `\USER_ESRV_SVC_QUEENCREEK`.
3. Task Scheduler executes:
   ```cmd
   powershell.exe -Command "Start-Process -WindowStyle Hidden task.bat"
   ```
4. Intel wrote it this way so a black Command Prompt window wouldn't flash on my screen when launching their telemetry binary.
5. McAfee's RealProtect driver inspects the process creation. It sees `svchost.exe` spawning `powershell.exe` with `-WindowStyle Hidden`.
6. RealProtect assumes that any hidden PowerShell launched from Task Scheduler is an obfuscated dropper/malware (`DetectEncAndObfusPowershell`), kills the process, returns `ERROR_VIRUS_INFECTED`, and displays a generic warning about "fileless threats".
7. Because the block happened at the process creation layer before PowerShell loaded its engine, PowerShell's own event log (`Microsoft-Windows-PowerShell/Operational`, Event ID 4104) has zero record of any script block execution.
