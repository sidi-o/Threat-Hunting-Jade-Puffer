# Threat-Hunting-Jade-Puffer

# Agentic Ransomware Threat Hunt — Flowforge Estate

## Overview

This project documents a complete threat hunt investigating an **agent-driven ransomware attack** against a Linux-based AI infrastructure environment.

The investigation covers the complete attack chain, from **initial access and command & control to credential access, lateral movement, privilege escalation, and ransomware impact**.

The investigation was performed using security telemetry and **Kusto Query Language (KQL)**, with findings mapped to **MITRE ATT&CK** and **MITRE ATLAS** where applicable.

> **Environment:** Flowforge AI-workflow infrastructure
> **Platform:** Linux
> **Investigation window:** 30 July 2026, approximately 19:21–19:38 UTC
> **Workspace:** `LAW-HuntPractice`
> **Hosts:** `ff-lf-01`, `ff-minio-01`, `ff-nacos-01`, `ff-db-01`

---

## Scenario

An analytics rule triggered on `ff-lf-01` after a service account started a process that had never previously been observed.

The investigation revealed a rapid attack chain that moved through multiple systems and ultimately encrypted and destroyed database data.

The telemetry also contained **LLM-agent reasoning logs**, allowing the investigation to determine how the attack was initiated and how the attacker adapted during execution.

The investigation concluded that the activity was:

**Human-tasked, machine-executed.**

A human supplied the initial objective, while an LLM-based agent autonomously performed the subsequent attack chain.

---

# Attack Chain

```text
Initial Access
      │
      ▼
Langflow RCE
CVE-2025-3248
      │
      ▼
Python execution
      │
      ├──────────────► Command & Control
      │                45.131.66.106:4444
      │
      ▼
Credential Access
pg_dump executed as langflow
      │
      ▼
Credential classification
8 provider families
      │
      ▼
Discovery
Network service sweep
      │
      ▼
Lateral Movement
MinIO default credentials
      │
      ▼
Credential theft
terraform-state
credentials.json
      │
      ▼
Privilege Escalation
Nacos exploitation
      │
      ▼
Persistence
svc_maint account
      │
      ▼
Impact
AES_ENCRYPT
      │
      ├──► 1,342 rows encrypted
      ├──► config_info dropped
      └──► history dropped
```

---

# Investigation Timeline

| Time (UTC) | Activity                                    |
| ---------- | ------------------------------------------- |
| 19:21      | Initial Langflow exploitation               |
| 19:21      | `python3.11` spawned by Langflow            |
| 19:27      | Second Python interpreter started           |
| 19:27+     | Internal service discovery                  |
| 19:27+     | MinIO accessed using default credentials    |
| 19:34:36   | Nacos privilege-escalation attempt rejected |
| 19:35:07   | Successful account creation                 |
| ~19:38     | Ransomware impact observed                  |

The complete attacker activity occurred in approximately **17 minutes**.

---

# 1. Initial Access

## Exploited Endpoint

```text
/api/v1/validate/code
```

The endpoint was associated with a Langflow remote-code-execution vulnerability.

### Vulnerability

```text
CVE-2025-3248
```

### External Staging Address

```text
64.20.53.230
```

### Process Execution

```text
python3.11
```

The Python interpreter was spawned by the Langflow process.

### KQL

```kql
Syslog
| where RunId_CF =~ "jp-46-20260730"
| where ProcessName =~ "langflow" and SyslogMessage has "validate/code"
| project TimeGenerated, SyslogMessage
```
<img width="1422" height="288" alt="image" src="https://github.com/user-attachments/assets/9f0d4865-a857-4f6c-9be0-b10e42e80a80" />


Process validation:

```kql
LinuxProcess_CL
| where RunId =~ "jp-46-20260730"
| where DvcHostname =~ "ff-lf-01" and TargetProcessName =~ "python3.11"
| project TimeGenerated, TargetProcessName, ActingProcessCommandLine
```
<img width="1416" height="338" alt="image" src="https://github.com/user-attachments/assets/ec02d54d-0d7a-4396-900b-406ddebda76c" />



### MITRE ATT&CK

* **T1190 — Exploit Public-Facing Application**
* **T1059.006 — Python**

### Detection Insight

The executable name `python3.11` by itself is not a reliable detection indicator.

The important signal is the **process lineage**:

```text
Langflow
   └── python3.11
```

Parent-child relationships provide a more resilient behavioral detection mechanism than simply matching the executable name.

---

# 2. Telemetry Limitation — Fileless Claim

A process event contained no SHA256 hash, leading to the initial conclusion that the payload was fileless.

The investigation showed that this conclusion was unsupported.

```kql
LinuxProcess_CL
| where RunId =~ "jp-46-20260730"
| summarize total = count(), has_hash = countif(isnotempty(TargetProcessSHA256))
```
<img width="1422" height="285" alt="image" src="https://github.com/user-attachments/assets/701fbd60-3aac-465a-b39b-cc366309ac55" />



The `TargetProcessSHA256` field was empty across the process telemetry.

This means the missing hash represents a **telemetry coverage limitation**, not evidence that the payload was fileless.

### SOC Lesson

> Absence of a hash is not evidence of a fileless payload when hash collection itself is incomplete.

This is an important example of distinguishing:

```text
No evidence
```

from:

```text
Evidence of absence
```

---

# 3. Command & Control

The investigation identified the following external destination:

```text
45.131.66.106:4444
```

The destination port was particularly useful because legitimate external services observed during the investigation used HTTPS:

```text
443
```

while the suspected C2 communication used:

```text
4444
```

### KQL

```kql
LinuxNetwork_CL
| where RunId =~ "jp-46-20260730"
| where DvcHostname =~ "ff-lf-01" and DstPortNumber == 4444
| project TimeGenerated, DstIpAddr, DstPortNumber
```
<img width="1417" height="288" alt="image" src="https://github.com/user-attachments/assets/eff584ff-0986-4864-bfd9-cc61ba20a5a9" />



### MITRE ATT&CK

**T1571 — Non-Standard Port**

### Persistence

The C2 mechanism was associated with a cron job executing every 30 minutes under:

```text
langflow
```

### KQL

```kql
LinuxSystem_CL
| where RunId =~ "jp-46-20260730"
| where Facility =~ "cron"
| where Computer =~ "ff-lf-01"
| extend VisualIntervalle = bin(TimeGenerated, 30m)
| summarize NombreExecutions = count() by VisualIntervalle, Mechanism = "cron", RunId, Facility
| order by VisualIntervalle asc
```
<img width="1406" height="671" alt="image" src="https://github.com/user-attachments/assets/ae653e98-ae48-424c-989d-dc2ff1ab71a1" />




### MITRE ATT&CK

**T1053.003 — Cron**

---

# 4. Credential Access

The attacker executed:

```text
pg_dump
```

on:

```text
ff-db-01
```

However, the important distinction was the account executing the command.

The malicious dump was executed by:

```text
langflow
```

rather than the legitimate backup account:

```text
backup
```

### KQL

```kql
LinuxProcess_CL
| where RunId =~ "jp-46-20260730"
| where TargetProcessName =~ "pg_dump"
| project TimeGenerated, TargetUsername,TargetProcessCommandLine
```
<img width="1405" height="417" alt="image" src="https://github.com/user-attachments/assets/a4dfc7ca-b775-46a9-a635-e1b6fc57e8f4" />


### Detection Insight

A detection based only on:

```text
pg_dump
```

would generate legitimate backup activity.

The more useful discriminator is:

```text
pg_dump + unexpected account
```

This demonstrates why **contextual detection** is important in SOC investigations.

---

## Credential Classification

The attacker classified credentials belonging to **8 provider families**:

### LLM providers

* OpenAI
* Anthropic
* DeepSeek
* Gemini

### Cloud providers

* Alibaba
* Aliyun
* Tencent
* Huawei

### KQL

```kql
LLMAgentLogs_CL
| where RunId =~ "jp-46-20260730"
| where model_response has "keys" and model_response has "provider"
| project TimeGenerated, model_response
```
<img width="1425" height="295" alt="image" src="https://github.com/user-attachments/assets/e2147570-c54c-495b-b004-bf3f82a04fef" />



### MITRE ATT&CK

**T1552 — Unsecured Credentials**

---

# 5. Discovery & Lateral Movement

A second Python interpreter was observed on `ff-lf-01`.

```text
PID: 4491
```

This interpreter was associated with the internal network sweep.

### KQL

```kql
LinuxProcess_CL
| where RunId =~ "jp-46-20260730"
| where DvcHostname =~ "ff-lf-01" and TargetProcessName =~ "python3.11"
| project TimeGenerated, TargetProcessId, ActingProcessCommandLine
```
<img width="1420" height="337" alt="image" src="https://github.com/user-attachments/assets/cfb3ff4d-e524-47f2-96c7-bb72f0e7f765" />


---

## Internal Service Discovery

The process contacted:

| Destination |   Port | Service |
| ----------- | -----: | ------- |
| `10.4.0.20` | `9000` | MinIO   |
| `10.4.0.30` | `3306` | MySQL   |
| `10.4.0.40` | `8848` | Nacos   |

### KQL

```kql
LinuxNetwork_CL
| where RunId =~ "jp-46-20260730"
| where ActingProcessId == 4491
| project TimeGenerated, DstIpAddr, DstPortNumber
| sort by TimeGenerated asc
```
<img width="1415" height="342" alt="image" src="https://github.com/user-attachments/assets/eada46dc-f0c5-4e8d-a3ab-3561eafab958" />



### MITRE ATT&CK

**T1046 — Network Service Discovery**

---

# 6. MinIO Access

The attacker successfully accessed MinIO using default credentials:

```text
minioadmin:minioadmin
```

This was not an exploitation of a vulnerability.

It was access using a valid default account.

### MITRE ATT&CK

**T1078.001 — Default Accounts**

---

## Data Retrieved

The attacker obtained:

```text
terraform-state
credentials.json
```

These files potentially contained infrastructure and credential information.

### KQL

```kql
Syslog
| where RunId_CF =~ "jp-46-20260730"
| where Computer =~ "ff-minio-01" and SyslogMessage has "GetObject"
| project TimeGenerated,  SyslogMessage
```
<img width="1407" height="305" alt="image" src="https://github.com/user-attachments/assets/20f54a52-2c70-408d-bec8-1382ac7c702b" />




### MITRE ATT&CK

**T1552.001 — Credentials In Files**

---

# 7. Agent Self-Correction

One of the most interesting findings was the agent's response to an unexpected data format.

The agent expected:

```text
JSON
```

but received:

```text
XML
```

Instead of stopping, the agent adapted its parser and retried the request.

### KQL

```kql
LLMAgentLogs_CL
| where RunId =~ "jp-46-20260730"
| where model_response has "XML" or model_response has "JSON"
| project TimeGenerated, model_response
```
<img width="1421" height="306" alt="image" src="https://github.com/user-attachments/assets/9fdf1ce4-45cc-4dc9-ae3e-159cc7172cce" />



This provides behavioral evidence of an automated agent adapting its execution based on tool output.

---

# 8. Privilege Escalation

The attacker attempted to exploit Nacos.

The first attempt failed.

### Failed Attempt

```text
19:34:36 UTC
HTTP 403
Blank password hash
```

### KQL

```kql
Syslog
| where RunId_CF =~ "jp-46-20260730"
| where Computer =~ "ff-nacos-01" and SyslogMessage has "403"
| project TimeGenerated, SyslogMessage
```
<img width="1413" height="277" alt="image" src="https://github.com/user-attachments/assets/b08d8f5f-7516-47dd-a15a-fe8afdc2190b" />



The attempted technique was associated with:

```text
CVE-2021-29441
```

---

## Successful Account Creation

A successful account creation occurred at:

```text
19:35:07 UTC
```

with:

```text
PID: 8801
UID: 997
```

### KQL

```kql
LinuxAudit_CL
| where RunId =~ "jp-46-20260730"
| where Computer =~ "ff-nacos-01" and AuditType =~ "ADD_USER"
| project TimeGenerated, EventOriginalMessage
```
<img width="1647" height="281" alt="image" src="https://github.com/user-attachments/assets/d5d99aa0-a936-4540-ad0b-37891aa020b1" />



### Account Created

```text
svc_maint
```

### MITRE ATT&CK

* **T1068 — Exploitation for Privilege Escalation**
* **T1136.001 — Create Account: Local Account**

---

# 9. Container Escape Investigation

The attacker queried the Docker API:

```text
GET /containers/json
```

through:

```text
docker.sock
```

However, the telemetry did not contain the response.

The available fields were insufficient to establish which containers were visible.

### KQL

```kql
LinuxContainer_CL
| where RunId =~ "jp-46-20260730"
| project TimeGenerated, Computer, RuntimeService, Operation
```
<img width="1415" height="281" alt="image" src="https://github.com/user-attachments/assets/c387aa27-631b-4ec6-a88d-72789af261dd" />



### Finding

The correct conclusion is:

```text
Container visibility cannot be established from the available telemetry.
```

This is another example where the investigation must distinguish an actual observation from a telemetry gap.

### MITRE ATT&CK

**T1611 — Escape to Host**

---

# 10. Ransomware Impact

The attack ultimately reached the database.

The attacker used:

```text
AES_ENCRYPT
```

against:

```text
1,342 rows
```

and subsequently dropped:

```text
config_info
history
```

### KQL

```kql
Syslog
| where RunId_CF =~ "jp-46-20260730"
| where Computer =~ "ff-db-01" and (SyslogMessage has "AES_ENCRYPT" or SyslogMessage has "DROP TABLE")
| project TimeGenerated, SyslogMessage
```
<img width="1416" height="337" alt="image" src="https://github.com/user-attachments/assets/253c2ea3-dae4-4568-bba0-950a9ad8d282" />



### MITRE ATT&CK

* **T1486 — Data Encrypted for Impact**
* **T1485 — Data Destruction**

The encryption key was generated at runtime and was not saved.

---

# 11. Ransom Note

The attacker created:

```text
README_RANSOM
```

The note referenced the following Bitcoin address:

```text
3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy
```

### KQL

```kql
Syslog
| where RunId_CF =~ "jp-46-20260730"
| where Computer =~ "ff-db-01" and SyslogMessage has "README_RANSOM"
| project TimeGenerated, SyslogMessage
```
<img width="1418" height="305" alt="image" src="https://github.com/user-attachments/assets/cf312231-4894-4418-9bdb-59d587c03439" />



The investigation notes that this address corresponds to a Bitcoin documentation/example address rather than a usable ransom-payment destination.

This provides an additional indicator of the generated nature of the ransomware output.

---

# 12. Determining the Attacker's Autonomy

The investigation found a separate LLM-agent session:

```text
jp-7f3c9a21
```

associated with:

```text
jadepuffer-agent
```

The session contained a single human instruction directing the agent to gain access to the Flowforge estate and locate/exfiltrate credentials.

The subsequent telemetry contained multiple `model_response` records showing the agent's reasoning and decisions.

### KQL

```kql
LLMAgentLogs_CL
| where RunId =~ "jp-46-20260730"
| summarize count() by TimeGenerated, actor, session_id
| sort by count_ desc
```
<img width="1402" height="691" alt="image" src="https://github.com/user-attachments/assets/7d616787-968c-4b05-bca1-6e0ff1e87fdc" />



Further investigation:

```kql
LLMAgentLogs_CL
| where RunId =~ "jp-46-20260730"
| where session_id == "jp-7f3c9a21"
| summarize count() byTimeGenerated, actor, model_response
```
<img width="1647" height="563" alt="image" src="https://github.com/user-attachments/assets/392cd579-b9ff-4515-9bbf-1c73d17951c0" />



### Evidence

Three categories of evidence supported the assessment:

1. A human supplied the initial task.
2. The LLM agent generated subsequent reasoning and decisions.
3. The attack chain executed continuously at machine speed across multiple hosts.

### Assessment

```text
Human-tasked
        ↓
LLM-directed execution
        ↓
Autonomous reconnaissance
        ↓
Autonomous credential access
        ↓
Autonomous lateral movement
        ↓
Autonomous privilege escalation
        ↓
Autonomous ransomware impact
```

---

# 13. Real Activity vs. Benign Noise

The investigation also tested whether suspicious events could be explained by legitimate activity.

## Python Processes

Multiple `python3.11` processes existed on `ff-lf-01`.

Legitimate examples included:

```text
bash
langflow-worker
```

The attacker processes instead exhibited:

```text
python3.11
```

as the parent.

### KQL

```kql
LinuxProcess_CL
| where RunId =~ "jp-46-20260730"
| where DvcHostname =~ "ff-lf-01" and TargetProcessName =~ "python3.11"
| summarize count() by ActingProcessName
```
<img width="1423" height="311" alt="image" src="https://github.com/user-attachments/assets/1d4e1eb3-0125-463d-b588-0b54b66bb1cb" />



This demonstrates why:

```text
Process name
```

alone is insufficient.

The more useful detection signal is:

```text
Process name + parent process + execution context
```

---

# 14. C2 vs. Legitimate External Traffic

External connections included legitimate development services such as:

```text
api.github.com
registry.npmjs.org
HuggingFace
```

These used:

```text
443
```

The suspicious C2 connection used:

```text
4444
```

### KQL

```kql
LinuxNetwork_CL
| where RunId =~ "jp-46-20260730"
| where DvcHostname =~ "ff-lf-01" and DstIpAddr !startswith "10."
| summarize count() by DstIpAddr, DstPortNumber
```
<img width="1420" height="425" alt="image" src="https://github.com/user-attachments/assets/46994043-8561-4909-8721-6a64028a1825" />



The investigation therefore used **connection behavior and port context**, rather than relying solely on the destination IP.

---

# 15. Temporal Analysis

The attacker activity appeared as a dense burst rather than isolated events.

The entire chain occurred over approximately:

```text
17 minutes
```

Legitimate Python activity was distributed throughout the working day, while the attack activity formed a concentrated cluster.

This temporal characteristic was useful for separating malicious activity from the normal operational baseline.

<img width="1413" height="451" alt="image" src="https://github.com/user-attachments/assets/716642cf-4902-4c06-aea8-1297a2cb4c3e" />

---

# MITRE ATT&CK Mapping

| Technique                             | ID        | Observed Activity                         |
| ------------------------------------- | --------- | ----------------------------------------- |
| Exploit Public-Facing Application     | T1190     | Langflow RCE                              |
| Python                                | T1059.006 | Python interpreters used during execution |
| Non-Standard Port                     | T1571     | C2 over port 4444                         |
| Cron                                  | T1053.003 | Scheduled C2 persistence                  |
| Unsecured Credentials                 | T1552     | Credential discovery                      |
| Default Accounts                      | T1078.001 | MinIO default credentials                 |
| Credentials In Files                  | T1552.001 | `terraform-state`, `credentials.json`     |
| Network Service Discovery             | T1046     | Internal service sweep                    |
| Exploitation for Privilege Escalation | T1068     | Nacos exploitation                        |
| Create Account: Local Account         | T1136.001 | `svc_maint`                               |
| Escape to Host                        | T1611     | Docker socket probing                     |
| Data Encrypted for Impact             | T1486     | AES encryption                            |
| Data Destruction                      | T1485     | Database tables dropped                   |

---

# MITRE ATLAS Mapping

The investigation also contains behaviors relevant to **AI/ML-specific attack analysis**.

| ATLAS Technique | Observed Behavior                                                        |
| --------------- | ------------------------------------------------------------------------ |
| AML.T0054       | LLM-related exploitation / prompt-driven execution context               |
| AML.T0048       | Machine-driven credential classification and autonomous attack execution |

The investigation particularly focused on the distinction between a traditional scripted attack and an LLM-driven workflow capable of adapting to unexpected results.

---

# Detection Engineering Lessons

## 1. Process lineage is more valuable than process names

Weak detection:

```text
TargetProcessName == "python3.11"
```

Better contextual detection:

```text
python3.11
+
unexpected parent
+
unexpected service account
+
suspicious network activity
```

---

## 2. Account identity matters

Weak detection:

```text
pg_dump
```

Better detection:

```text
pg_dump
+
TargetUsername != expected_backup_account
```

---

## 3. Non-standard ports can provide behavioral context

External IP addresses can change.

The combination of:

```text
external destination
+
unusual destination port
+
unexpected process
```

provides stronger context.

---

## 4. Telemetry gaps must be explicitly documented

Two important investigation limitations were identified:

### Process hashes

```text
TargetProcessSHA256
```

was not populated.

### Container telemetry

The Docker API request was logged, but the response was unavailable.

These limitations should be documented rather than replaced with assumptions.

---

# Pyramid of Pain

The investigation produced indicators at several levels.

```text
                    TTPs
                     ▲
                     │
              Behavioral patterns
                     │
                Host artifacts
                     │
              Network indicators
                     │
                    IPs
                     │
                   Hashes
```

Examples from the investigation:

### Lower-level indicators

```text
64.20.53.230
45.131.66.106
```

### Host indicators

```text
svc_maint
README_RANSOM
PID 4491
```

### Behavioral indicators

```text
Langflow → python3.11
python3.11 → internal service sweep
pg_dump executed by unexpected account
C2 over port 4444
encrypt → drop tables
```

Behavioral detections generally provide greater resilience against simple infrastructure changes.

---

# Key Indicators of Compromise

| Indicator               | Type                 | Context                  |
| ----------------------- | -------------------- | ------------------------ |
| `64.20.53.230`          | IP                   | Initial access / staging |
| `45.131.66.106:4444`    | Network              | C2                       |
| `/api/v1/validate/code` | Endpoint             | Langflow exploitation    |
| `CVE-2025-3248`         | Vulnerability        | Initial access           |
| `svc_maint`             | Account              | Persistence              |
| `minioadmin:minioadmin` | Credential           | Default account access   |
| `terraform-state`       | File/object          | Credential exposure      |
| `credentials.json`      | File/object          | Credential exposure      |
| `README_RANSOM`         | Database artifact    | Ransom note              |
| `AES_ENCRYPT`           | Behavioral indicator | Data encryption          |
| `config_info`           | Database artifact    | Destruction              |
| `history`               | Database artifact    | Destruction              |

---

# Investigation Methodology

The investigation followed a structured threat-hunting process:

```text
1. Alert triage
       ↓
2. Establish initial access
       ↓
3. Build process lineage
       ↓
4. Identify C2
       ↓
5. Investigate persistence
       ↓
6. Trace credential access
       ↓
7. Scope lateral movement
       ↓
8. Investigate privilege escalation
       ↓
9. Determine impact
       ↓
10. Separate malicious activity from noise
       ↓
11. Assess attacker autonomy
       ↓
12. Document telemetry limitations
```

---

# Skills Demonstrated

This project demonstrates practical experience with:

* Threat hunting
* KQL
* Microsoft Sentinel-style log analysis
* Linux process investigation
* Process parent-child analysis
* Network telemetry analysis
* C2 identification
* Credential-access investigation
* Lateral-movement analysis
* Privilege-escalation investigation
* Ransomware investigation
* MITRE ATT&CK mapping
* MITRE ATLAS mapping
* Threat intelligence correlation
* Detection engineering
* False-positive analysis
* Telemetry-gap identification
* Timeline reconstruction
* AI-agent behavior analysis

---

# Main Takeaways

This investigation demonstrates several important SOC principles:

### Context beats isolated indicators

A process name, IP address, or command is rarely enough by itself.

### Process lineage is critical

```text
What executed?
Who executed it?
What launched it?
What did it connect to?
```

These questions provide much stronger investigative context.

### Failed attacks are valuable evidence

The failed Nacos attempt provided evidence of the attacker's privilege-escalation strategy even before the successful attempt.

### Telemetry limitations matter

A missing field should not automatically be interpreted as evidence that an event did not occur.

### Automation changes attacker behavior

The investigation showed rapid execution, self-correction, and machine-speed progression across multiple stages.

---

# References

* Sysdig Threat Research — JADEPUFFER disclosure
* MITRE ATT&CK
* MITRE ATLAS
* KQL / Microsoft security telemetry concepts



No real-world systems were targeted as part of this project.
