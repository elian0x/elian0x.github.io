---
title: "TITLE — short descriptive name of the incident/lab"
date: 2026-01-01 10:00:00 +0300
categories: [Network Forensics, CyberDefenders]   # [Main Category, Platform] — max 2 levels
# Main Category options: Network Forensics | Endpoint Forensics | Memory Forensics | Log Analysis | Malware Analysis | Threat Hunting
# Platform options: LetsDefend | CyberDefenders | TryHackMe | HTB | Internal Lab | Other
tags: [t1059, persistence, phishing]              # free-form: tools, MITRE technique IDs, keywords
description: "One-sentence summary used for SEO and link previews."
---

<!--
  HOW TO USE THIS TEMPLATE
  1. Copy this file into _posts/ and rename it, e.g.:
     _posts/2026-07-27-suspicious-powershell-execution.md
     (filename MUST start with YYYY-MM-DD matching the `date` above)
  2. Fill in the front matter above.
  3. Fill in the sections below. Delete any section that doesn't apply.
  4. Delete this comment block before publishing.
-->

> **Platform:** CyberDefenders &nbsp;·&nbsp; **Difficulty:** Medium &nbsp;·&nbsp; **Tools:** Wireshark, Volatility3, Zeek
{: .prompt-info }

## Scenario

Describe the alert/ticket/scenario as given by the lab or SOC platform.
What triggered the investigation? (e.g. SIEM alert, EDR detection, user report)

## Objective

What questions does this investigation need to answer? e.g.:
- How did the attacker gain initial access?
- What was the scope of compromise?
- Was data exfiltrated?

## Tools Used

| Tool | Purpose |
|------|---------|
| Wireshark | PCAP analysis |
| Volatility3 | Memory image analysis |
| ... | ... |

## Investigation Steps

### Step 1: Initial Triage

What you looked at first and why.

```text
# commands / queries you ran
```

Findings.

### Step 2: ...

Continue documenting each investigative step with evidence (screenshots, log excerpts, command output).

> Drop images in `assets/img/` and reference them as `![alt](/assets/img/your-image.png)`.
{: .prompt-tip }

## Indicators of Compromise (IOCs)

| Type | Value | Description |
|------|-------|-------------|
| IP | 203.0.113.10 | C2 server |
| Hash (SHA256) | ... | Malicious payload |
| Domain | ... | Phishing domain |

## Timeline

| Time (UTC) | Event |
|------------|-------|
| 2026-01-01 10:00 | Initial phishing email received |
| 2026-01-01 10:05 | Malicious macro executed |
| ... | ... |

## MITRE ATT&CK Mapping

| Tactic | Technique |
|--------|-----------|
| Initial Access | T1566 – Phishing |
| Execution | T1059 – Command and Scripting Interpreter |

## Root Cause / Conclusion

Summarize what happened, how, and the overall impact.

## Lessons Learned / Recommendations

- Detection gaps identified
- Suggested mitigations / hardening
- Suggested detection rules (Sigma, YARA, etc.)
