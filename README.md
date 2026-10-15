# McAfee RealProtect False Positive: Intel QUEENCREEK / SUR

[![Status](https://img.shields.io/badge/Status-False%20Positive%20Confirmed-brightgreen)](#)
[![OS](https://img.shields.io/badge/OS-Windows%2011-blue)](#)
[![Component](https://img.shields.io/badge/Component-Intel%20SUR%20%7C%20QUEENCREEK-informational)](#)
[![Engine](https://img.shields.io/badge/Engine-McAfee%20RealProtect-red)](#)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A personal post-mortem, forensic log analysis, and remediation toolkit for a recurring McAfee false positive (`RealProtect.DetectEncAndObfusPowershell`) that started hitting my Windows 11 laptop immediately after an Intel graphics driver update.

---

## What Happened

Earlier today, I got a desktop notification from the Intel Graphics Software app letting me know an updated graphics driver was available. I clicked the notification, downloaded the official installer from Intel's website, ran the update, and everything looked completely normal.

A few minutes later, McAfee popped up a desktop alert that immediately caught my attention:

> **We blocked a fileless threat**  
> We stopped suspicious activity and terminated the app to keep your PC safe.

Clicking through brought me to a McAfee support page (`article/000001839`) explaining that "fileless threats exist only in the computer's memory (RAM) and not on the hard drive," which is why on-demand disk scans won't detect them.

Given the timing right after a driver update, I wanted to rule out a compromised download or a real attack. I immediately ran a full McAfee scan. **0 threats found.**  
To be safe, I downloaded Microsoft Safety Scanner (MSERT) and ran a scan. **0 threats found.**  
I rebooted my machine. About four minutes after logging back into Windows, **the exact same notification popped up again.**

McAfee's UI gave me literally nothing to work with. It told me it blocked a "fileless threat," but refused to show me:
- Which executable or script was blocked.
- What process initiated the call.
- The command-line arguments.
- Which specific detection rule or heuristic triggered.

The toast notification made it sound like my machine had persistent in-memory malware executing on every logon, so I started digging into the underlying logs to find out what was actually being blocked.

---

## What I Found: Intel's Wrapper vs. McAfee's Heuristic

After tracing the timestamps between McAfee's internal logs and Windows Task Scheduler, I proved my machine was completely clean. What I was actually seeing was an aggressive behavioral heuristic in McAfee clashing with a lazy wrapper script from Intel:

```
Windows Logon
     │
     ▼
svchost.exe (Task Scheduler Engine)
     │
     ▼ fires scheduled task: \USER_ESRV_SVC_QUEENCREEK
powershell.exe -Command "Start-Process -WindowStyle Hidden task.bat"
     │
     ├──────────────────────────────────────────────┐
     │                                              ▼
     │                                    McAfee RealProtect (rp-d)
     │                                    Flags: "svchost spawning hidden PowerShell"
     │                                    Blocks CreateProcess!
     │                                    Returns: 0x800700E1 (ERROR_VIRUS_INFECTED)
     ▼
task.bat (Never got to execute)
     │
     ▼
task.exe (Signed Intel SUR telemetry binary)
```

### 1. The Intel Task
When Intel's graphics software and driver utilities are installed, they register a scheduled task named `\USER_ESRV_SVC_QUEENCREEK`. This task belongs to Intel's **System Usage Report (SUR)** / Energy Server Service (`esrv_svc.exe`), which gathers system usage and power telemetry.

Looking at how Intel configured the task on my system, I found this command line:
```cmd
powershell.exe -Command "Start-Process -WindowStyle Hidden task.bat"
```
Working directory: `C:\Program Files\Intel\SUR\QUEENCREEK\x64\`

Inside `task.bat`, there was only a single line:
```bat
"C:\Program Files\Intel\SUR\QUEENCREEK\x64\task.exe"
```

I checked the digital signature on `task.exe` using `Get-AuthenticodeSignature`, and it was completely valid, signed directly by **Intel Corporation** (`CN=Intel Corporation, O=Intel Corporation, L=Santa Clara, S=California, C=US`).

Intel literally wrapped the execution in a hidden PowerShell command just so a black console window wouldn't flash on the screen for a split second when logging in.

### 2. Why McAfee RealProtect Flagged It
McAfee's RealProtect engine uses a process-creation sensor (`rp-d`) to catch suspicious behavior in real time. When it saw `svchost.exe` (Task Scheduler) invoking `powershell.exe` with `-WindowStyle Hidden`, the heuristic jumped to the conclusion that this was an obfuscated script dropper:

- **Detection Name:** `RealProtect.DetectEncAndObfusPowershell!72b6875643f7`
- **Result:** `infected`

Because malware authors often spawn hidden PowerShell instances from scheduled tasks to drop payloads, McAfee's heuristic blocked the process creation entirely. But the rule had no awareness of the context—it didn't check that the working directory was an Intel directory or that the batch file pointed to a signed Intel binary. It simply blocked PowerShell at the OS API level and showed a generic "fileless threat" popup.

---

## The Forensic Evidence

To connect the dots with certainty, I pulled the logs from both McAfee and Windows Event Viewer.

### 1. McAfee's Internal `detection.log`
While the McAfee GUI hides technical data, I found that RealProtect writes raw JSON events to `C:\ProgramData\McAfee\wps\detection.log`:

```json
{
  "timestamp": "2026-10-14T15:25:34.349Z",
  "initiator_name": "\\\\?\\C:\\Windows\\System32\\svchost.exe",
  "target_name": "\\\\?\\C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "sensor": "process create",
  "detection_name": "RealProtect.DetectEncAndObfusPowershell!72b6875643f7",
  "final_result": "infected"
}
```

This gave me the exact millisecond timestamps and proved that:
- The initiator was `svchost.exe` (Task Scheduler).
- The target was the legitimate Windows `powershell.exe` (SHA256: `60c9b29843624dd8af6b6a7b26147753be6aeef65098b9a503cc50850afe410f`).
- The block happened at the `process create` sensor before PowerShell could even run any code.

### 2. Windows Task Scheduler Operational Logs
Next, I cross-referenced those timestamps with `Microsoft-Windows-TaskScheduler/Operational`. At the exact same millisecond of each McAfee block, I found these events:

1. **Event ID 119:** Task Scheduler launched task `\USER_ESRV_SVC_QUEENCREEK` triggered by user logon.
2. **Event ID 203:** Task Scheduler failed to launch action `powershell.EXE`. Additional Data: Error Value: `2147942625`.
3. **Event ID 101:** Task Scheduler failed to start `\USER_ESRV_SVC_QUEENCREEK`. Additional Data: Error Value: `2147942625`.

#### Decoding Error `2147942625`:
Converting `2147942625` to hexadecimal gives **`0x800700E1`**.  
In the Windows API, `0x800700E1` translates to Win32 Error 225: **`ERROR_VIRUS_INFECTED`** (*"Operation did not complete successfully because the file contains a virus or potentially unwanted software"*).

This was the smoking gun. Task Scheduler attempted to launch the Intel task, McAfee intercepted the system call, returned `ERROR_VIRUS_INFECTED` to the operating system, and killed the launch.

---

## Why I Solved It the Way I Did

Once I understood the root cause, I evaluated my options:

### 1. Why I Refused to Whitelist PowerShell
McAfee's interface only allows excluding specific files or folders from on-access scanning; it does not allow whitelisting specific command lines. Adding an exclusion for `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` would create a massive security hole, preventing McAfee from inspecting any future malicious PowerShell activity.

### 2. Why I Left RealProtect Enabled
I could have toggled off RealProtect / behavioral protection in McAfee's settings, but disabling zero-day heuristic protection across my entire system just to silence a false positive on an Intel background task would be a terrible security trade-off.

### 3. What I Did Instead: Disabled the QUEENCREEK Task
The `\USER_ESRV_SVC_QUEENCREEK` task belongs entirely to Intel's System Usage Report telemetry service. It has zero role in display output, graphics driver stability, GPU switching, or game performance.

I opened an elevated PowerShell terminal and ran:
```powershell
Disable-ScheduledTask -TaskName "USER_ESRV_SVC_QUEENCREEK"
```

Disabling this single task stopped the hidden PowerShell command from firing on logon, which completely stopped McAfee from triggering the alert on reboot. My graphics driver and the Intel Graphics Software app continue to run with zero issues.

---

## Tools & Verification Scripts I Put Together

To make this easy to verify and manage, I wrote a couple of scripts:

- **[`scripts/verify-intel-task.ps1`](scripts/verify-intel-task.ps1)**: The script I used to inspect the scheduled task, verify the Authenticode signature on `task.exe`, check McAfee's `detection.log`, and search for Event ID 203 / error `2147942625`.
- **[`scripts/silence-telemetry-alert.ps1`](scripts/silence-telemetry-alert.ps1)**: A clean script to safely disable (or re-enable) `\USER_ESRV_SVC_QUEENCREEK` with proper administrator permission checks.
- **[`docs/technical-analysis.md`](docs/technical-analysis.md)**: The raw event correlation and JSON logs from my testing session.

---

## License

MIT © 2026 Golden Stickwood
