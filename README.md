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
| where ProcessName =~ "langflow"
    and SyslogMessage has "validate/code"
| project TimeGenerated, SyslogMessage
```
<img width="1162" height="336" alt="image" src="https://github.com/user-attachments/assets/4d5bffc1-63b4-462c-83de-c178d54a6fac" />

<img width="943" height="348" alt="image" src="https://github.com/user-attachments/assets/240f6a7d-f08f-4e46-910e-e01d96197cea" />

Process validation:

```kql
LinuxProcess_CL
| where RunId =~ "jp-46-20260730"
| where DvcHostname =~ "ff-lf-01"
    and TargetProcessName =~ "python3.11"
| project TimeGenerated,
          TargetProcessName,
          ActingProcessCommandLine
```
<img width="1167" height="362" alt="image" src="https://github.com/user-attachments/assets/6f8a7eb6-c3fa-4933-89df-f0363deca937" />


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
| summarize
    total = count(),
    has_hash = countif(isnotempty(TargetProcessSHA256))
```
<img width="1173" height="323" alt="image" src="https://github.com/user-attachments/assets/0648d5ee-3422-402c-97ab-3044745a2b5e" />


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
| where DvcHostname =~ "ff-lf-01"
    and DstPortNumber == 4444
| project
    TimeGenerated,
    DstIpAddr,
    DstPortNumber
```
<img width="986" height="495" alt="image" src="https://github.com/user-attachments/assets/23bcc103-c3b5-46e4-ad1a-65951da17d7b" />


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
| where computer =~ "ff-lf-01"
| extend VisualIntervalle = bin(TimeGenerated, 30m)
| summarize NombreExecutions = count() by VisualIntervalle, Mechanism = "cron", RunId, Facility
| order by VisualIntervalle asc
```
<img width="1197" height="375" alt="image" src="https://github.com/user-attachments/assets/2043fcb2-2f9a-4c95-8eab-63adaf749ffa" />


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
<img width="1272" height="427" alt="image" src="https://github.com/user-attachments/assets/d066654e-916e-4152-a717-76dc9b021791" />

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
<img width="1283" height="330" alt="image" src="https://github.com/user-attachments/assets/79d42a4b-bb84-43a7-a1de-924afc0d9090" />


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
<img width="1443" height="442" alt="image" src="https://github.com/user-attachments/assets/2ae8fd91-ccd6-4aeb-ad3f-c992213e065f" />

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
<img width="1437" height="393" alt="image" src="https://github.com/user-attachments/assets/b30f0fdc-a86b-4e38-a58a-93136ee7f2a2" />


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
<img width="1402" height="412" alt="image" src="https://github.com/user-attachments/assets/8c246a89-f021-4297-bd44-28525cdcaf3e" />



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
<img width="1596" height="507" alt="image" src="https://github.com/user-attachments/assets/818b116a-8728-4fde-84fa-dd712f9d59f6" />


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
<img width="1580" height="477" alt="image" src="https://github.com/user-attachments/assets/0220147d-a2a2-4497-a535-5e97d57bd1dc" />


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
<img width="1588" height="466" alt="image" src="https://github.com/user-attachments/assets/3bdbd465-0f17-44d8-a506-7af4d8df84af" />


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
<img width="1415" height="338" alt="image" src="https://github.com/user-attachments/assets/cbb607d9-8e34-49fd-9b29-87cda929d2f3" />


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
<img width="1417" height="382" alt="image" src="https://github.com/user-attachments/assets/8d146f27-0e49-4d1e-988f-a2a0e4391c30" />


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
<img width="1422" height="367" alt="image" src="https://github.com/user-attachments/assets/4601b092-2b96-459e-8a28-e928c5d367b0" />


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
| summarize count() by actor, session_id
| sort by count_ desc
```
<img width="1417" height="447" alt="image" src="https://github.com/user-attachments/assets/2923cbae-d4ac-4f1a-8991-fd2319a64d04" />


Further investigation:

```kql
LLMAgentLogs_CL
| where RunId =~ "jp-46-20260730"
| where session_id == "jp-7f3c9a21"
| summarize count() by actor, model_response
```
<img width="1412" height="618" alt="image" src="https://github.com/user-attachments/assets/344366cb-611f-4a43-98aa-de1e982b5471" />


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
<img width="1417" height="305" alt="image" src="https://github.com/user-attachments/assets/b975dc35-0023-4b13-8be9-09c32eac1290" />


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
<img width="1412" height="425" alt="image" src="https://github.com/user-attachments/assets/78f33698-bc14-485f-bdeb-4a0fb3ae27d1" />


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
