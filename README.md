# Case 02 — Suspicious Scheduled Task Persistence

## Objective
Investigate suspicious Scheduled Task Persistence activity using Splunk within a Windows Lab VM environment.

## Environment
* Windows 10 Lab VM (VirtualBox)
* Splunk Enterprise for log analysis
* EVTX-ATTACK-SAMPLES dataset used to simulate real-world attack log data

## Hypothesis
**IF**: In this event, a suspicious hidden command line was detected, operating under `NT AUTHORITY\SYSTEM` privileges.
**THEN**: The attacker uses `tasklist` output to check whether antivirus/EDR processes are running on the host, in order to evade detection before continuing the attack.
**SO**: Search Splunk using `index=main EventCode=4698 Message="*tasklist*" | table _time host TaskName Message`.

## Timeline
* Enabled Advanced Audit Policy to capture Scheduled Task creation events (Event ID 4698).
* Verified the log source using a test scheduled task, confirming events were forwarded correctly to Splunk.
* Ingested real-world EVTX data from the EVTX-ATTACK-SAMPLES dataset.
* Queried `EventCode=4698` and identified a suspicious hidden task named `\CYAlyNSS`.
* Analyzed the event content, revealing execution under `NT AUTHORITY\SYSTEM` and a `tasklist` command used for defense evasion reconnaissance.
* Mapped the observed behavior to MITRE ATT&CK techniques T1053.003 and T1518.001.

## MITRE ATT&CK Mapping
| Technique | ID | Tactic |
|---|---|---|
| Scheduled Task | T1053.003 | Persistence |
| Security Software Discovery | T1518.001 | Discovery |

## Findings
* A hidden Scheduled Task named `\CYAlyNSS` was identified.
* The task executed the command `cmd.exe /C tasklist > %windir%\Temp\CYAlyNSS.tmp` and operated under `NT AUTHORITY\SYSTEM` privileges.
* This suggests that the attacker aimed to enumerate running processes in order to detect active defense mechanisms (e.g. antivirus or EDR).

## Evidence
**Search Query**
```spl
index=main EventCode=4698 Message="*tasklist*"
| table _time host TaskName Message
```

**Evidence 1**
* Task Name: `\CYAlyNSS`

**Evidence 2**
* Command Line: `cmd.exe /C tasklist > %windir%\Temp\CYAlyNSS.tmp 2>&1`

**Evidence 3**
* Execution Context: `NT AUTHORITY\SYSTEM`

**Evidence 4**
* Source: `temp_scheduled_task_4698_4699.evtx`
* Sourcetype: `WinEventLog:Security`

*(Screenshots supporting this evidence are available in the `evidence/` folder.)*

## IOC (Indicators of Compromise)
* Task Name: `\CYAlyNSS`
* Command Line: `cmd.exe /C tasklist > %windir%\Temp\CYAlyNSS.tmp 2>&1`
* Dropped File Path: `%windir%\Temp\CYAlyNSS.tmp`

## Detection Logic

```yaml
title: Hidden Scheduled Task Executing Discovery Command
id: <UUID>
status: experimental
description: Detects a hidden scheduled task configured to run reconnaissance commands (e.g. tasklist) to identify active defense mechanisms, indicating potential Persistence and Defense Evasion behavior.
author: MIRGANI AMMAR
date: 2026/08/09
logsource:
  product: windows
  service: security
detection:
  selection1:
    EventID: 4698
    Message|contains: '<Hidden>true</Hidden>'
  selection2:
    Message|contains: 'tasklist'
  condition: selection1 and selection2
falsepositives:
  - Legitimate IT-administered scheduled tasks (e.g. software updates or cleanup scripts) configured as hidden to avoid user interference
level: medium
tags:
  - attack.persistence
  - attack.t1053.003
  - attack.discovery
  - attack.t1518.001
```

## Recommendations
* Monitor for any Scheduled Task with `Hidden=true` as a persistence indicator.
* Enable Advanced Audit Policy (Object Access → Other Object Access Events) across all machines in the network, not just individual hosts.
* Deploy the Sigma detection rule as a live alert in the SIEM to automatically flag similar hidden task creation in the future.

## Conclusion
A hidden Scheduled Task (`\CYAlyNSS`) was identified, executing a Discovery command (`tasklist`) under `NT AUTHORITY\SYSTEM` privileges. This behavior aligns with MITRE ATT&CK techniques T1053.003 (Scheduled Task) and T1518.001 (Security Software Discovery), and was classified as **Medium** severity. No evidence of further malicious action (e.g. lateral movement or data exfiltration) was observed at this stage; continuous monitoring using the deployed Sigma rule is recommended.
