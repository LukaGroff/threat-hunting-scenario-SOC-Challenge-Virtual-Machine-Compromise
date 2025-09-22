 # 🎯 Threat-Hunting-Scenario-SOC Challenge: Virtual Machine Compromise

 <img width="400" src="https://github.com/user-attachments/assets/3e99b9c3-0d44-4656-a55c-449be3a730b7" alt="screen with incorrect password written on it."/>

**Participant:** Luka Groff

**Date:** 21 September 2025

## Platforms and Languages Leveraged

**Platforms:**

* Microsoft Defender for Endpoint (MDE)
* Log Analytics Workspace

**Languages/Tools:**

* Kusto Query Language (KQL) for querying device events, registry modifications, and persistence artifacts

---


 # 📖 **Scenario**

Incident Response Scenario - where DeviceName contains "flare" Incident Date 14-September-2025
Suspicious activity has been detected on one of our cloud virtual machines. As a Security Analyst, you’ve been assigned to investigate this incident and determine the scope and impact of the breach.


This is an active investigation. Your objective is to reconstruct the attack timeline, identify key indicators, and answer targeted questions related to the compromise.

---

## 🟩 Flag 1 – Attacker IP Address

**Objective:**

Suspicious RDP login activity has been detected on a cloud-hosted Windows server. Multiple failed attempts were followed by a successful login, suggesting brute-force or password spraying behaviour.


**What to Hunt:**

Identify the external IP address that successfully logged in via RDP after a series of failures.


 🕵️ **What is the earliest external IP address successfully logged in via RDP after multiple failed login attempts?**

Query used:
```
DeviceLogonEvents
| where DeviceName contains "flare" //slflarewinsysmo //accname==slflare
| where ActionType == "LogonSuccess"
| project Timestamp, ActionType, LogonType, AccountName, RemoteIP
```

🧠 **Thought process:** The assignment gives us the hints like the DeviceName and time when initial access occured, so it was fairly easy to find the IP of the culprit in the DeviceLogonEvents. I also added comments of the full DeviceName which is slflarewinsysmo and the AccountName that was compromised which is slflare to help me with the hunt.

<img width="600" src="https://github.com/user-attachments/assets/7f2f8ddd-4092-4065-8bcf-e211024a58d5"/>


**Answer: 159.26.106.84**

---

## 🟩 Flag 2 – Compromised Account

**Objective:**

Determine the username that was used during the successful RDP login associated with the attacker’s IP.

**What to Hunt:**

Pivot from the successful login identified in Flag 1. Analyse the associated account used in that authentication event.


 🕵️ **What user account was successfully used to access the system via RDP?**

Query used:
```
DeviceLogonEvents
| where DeviceName contains "flare" //slflarewinsysmo //accname==slflare
| where ActionType == "LogonSuccess"
| project Timestamp, ActionType, LogonType, AccountName, RemoteIP
```

🧠 **Thought process:** The answer was already found in the first flag where I made sure to add the AccountName in the kql comment.

**Answer: slflare**

---

## 🟩 Flag 3 – Executed Binary Name

**Objective:**

Identify the name of the binary executed by the attacker.

**What to Hunt:**

Focus your investigation on process execution under the compromised user account from flag 2. Look for binaries launched from unusual paths like Public, Temp, or Downloads folders.


 🕵️ **What binary was executed by the attacker after gaining RDP access?**

Query used:
```
DeviceProcessEvents
| where DeviceName == "slflarewinsysmo"
| where AccountName == "slflare"
| where FolderPath has_any ("\\users\\public\\","\\downloads\\","\\temp\\","\\programdata\\")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by Timestamp asc
```

<img width="800" src="https://github.com/user-attachments/assets/790effb4-9e7e-4bb2-801e-24387c77dbf6"/>


🧠 **Thought process:** This one was a bit of a head-scratcher but I eventually managed to find the right binary after applying enough filters.


**Answer: msupdate.exe**

---

## 🟩 Flag 4 – Command Line Used to Execute the Binary

**Objective:**

Provide the full command line used to launch the binary from Flag 3.

**What to Hunt:**

Review command-line arguments associated with process execution under the compromised account. Pay attention to how the attacker invoked the binary and any parameters used.


 🕵️ **What was the full command line used by the attacker to execute the binary?**

🧠 **Thought process:** Very simple question, the answer is visible in the flag 3 picture.

**Answer: "msupdate.exe" -ExecutionPolicy Bypass -File C:\Users\Public\update_check.ps1**

---

## 🟩 Flag 5 – Persistence Mechanism Created

**Objective:**

Identify the name of the scheduled task created by the attacker.

**What to Hunt:**

Investigate task creation activity by examining both process execution events and registry modifications. Look for newly registered scheduled tasks in the Windows TaskCache registry or PowerShell cmdlet execution.

 🕵️ **What is the name of the scheduled task that was created by the attacker?**

Query used:

```
DeviceRegistryEvents
| where DeviceName == "slflarewinsysmo"
| where ActionType == "RegistryKeyCreated"
| where RegistryKey contains "TaskCache"
| project Timestamp, RegistryKey, InitiatingProcessCommandLine, InitiatingProcessFolderPath
```
<img width="800" src="https://github.com/user-attachments/assets/3f61a993-550c-4244-9f28-5c085587dbd0"/>

🧠 **Thought process:** It took me a while to find the right task because it blends in so well with other tasks, but giving enough kql filters really narrowed down my choices and I finally found the answer.

**Answer: MicrosoftUpdateSync**

---

## 🟩 Flag 6 – What Defender Setting Was Modified?

**Objective:**

Identify the folder path that was excluded from Defender scans.

**What to Hunt:**

Look for registry modification events linked to Defender exclusions.
Focus on exclusions that prevent scanning of specific folders.


 🕵️ **What folder path did the attacker add to Microsoft Defender’s exclusions after establishing persistence?**

Query used:

```
DeviceRegistryEvents
| where DeviceName == "slflarewinsysmo"
| where RegistryKey =~ @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
```

🧠 **Thought process:** I saw some Defender logs in the previous flag, so it was easier to narrow down and I knew exactly what I was looking for.

<img width="800" src="https://github.com/user-attachments/assets/1bacaf69-24c8-4547-bd6e-65e89db6533d"/>


**Answer: C:\Windows\Temp**

---

## 🟩 Flag 7 – What Discovery Command Did the Attacker Run?

**Objective:**

Identify the exact command line the attacker executed to perform system discovery.

**What to Hunt:**

Review process execution data for evidence of built-in Windows tools used for enumeration. Pay attention to attacker tooling or interactive shells used to issue these commands.


 🕵️ **What is the earliest discovery command that the attacker ran to enumerate the host?**

Query used:

```
DeviceProcessEvents
| where DeviceName == "slflarewinsysmo"
| where FileName == "powershell.exe" or InitiatingProcessFileName == "powershell.exe"
| project Timestamp, ProcessCommandLine, FileName, SHA256,InitiatingProcessFileName
```

🧠 **Thought process:** The query gives me a lot of results but once I ordered by timestamp ascending I could see the whole timeline of what the actor did. I wasn't hunting for the earliest enumerating attack but rather the whole attack, step by step and I could spot the enumerating attack quite early. This then gave me a lot of information for upcoming flags.

<img width="600" src="https://github.com/user-attachments/assets/f6cfc778-0248-4606-91b9-79510ff8ea71"/>


**Answer: "cmd.exe" /c systeminfo**

---

## 🟩 Flag 8 – Archive File Created by Attacker

**Objective:**

Identify the name of the archive file created by the attacker.

**What to Hunt:**

Look for file creation or process activity involving archiving tools. Focus on .zip, .rar, or .7z files created in non-standard directories such as Temp, AppData, or ProgramData.


 🕵️ **What archive file did the attacker create to prepare for exfiltration?**


🧠 **Thought process:** I got the answer from the previous flag, where I could see the whole process of what had happened.

**Answer: backup_sync.zip**

---

## 🟩 Flag 9 – C2 Connection Destination

**Objective:**

Identify the destination the attacker’s beacon connected to or retrieved tooling from.

**What to Hunt:**

Review outbound network connections tied to suspicious activity. Look for external IPs or domains contacted shortly after initial execution or persistence. Traffic may involve HTTP/S downloads or beacon callbacks.

 🕵️ **What destination did the attacker’s C2 beacon connect to for remote access?**


🧠 **Thought process:** I got the answer from flag 7 still; the answer can be visible in the picture provided there.

**Answer: 185.92.220.87**

---

## 🟩 Flag 10 – Exfiltration Attempt Detected

**Objective:**

Identify the external IP address and port used during this data exfiltration attempt.

**What to Hunt:**

Search DeviceNetworkEvents for outbound traffic occurring after the archive was created. Focus on unusual external destinations.


 🕵️ **What external IP address and port did the attacker attempt to use when trying to exfiltrate the staged archive file?**


🧠 **Thought process:** I saw that exact answer in previous flag, can be seen in the flag 7 picture.

**Answer: 185.92.220.87:8081**

---

**Recommended next steps:**

- Isolate/reimage the host; remove the scheduled task and Defender exclusions.

- Rotate credentials for slflare and any admins; review RDP exposure and enforce MFA.

- Deploy brute-force throttling/lockout, harden inbound rules, and baseline scheduled tasks.

- Add detections for execution from Public/Temp/ProgramData and for new Defender exclusions.




