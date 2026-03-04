# BC-001 — RDP Brute Force: Credential Access Detection & Response

| Field | Detail |
| --- | --- |
| **Case ID** | BC-001 |
| **Date** | March 4, 2026 |
| **Severity** | 🟠 Medium → Escalated to 🔴 High |
| **Status** | ✅ Resolved — True Positive |
| **MITRE Tactic** | Credential Access |
| **MITRE Technique** | [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/) |
| **Attacker Host** | 192.168.100.154 (Kali Linux) |
| **Target Host** | 192.168.100.161 (windows11_finance) |
| **Detection Source** | Wazuh Rule 60122 / 60204 |

---

## 🧭 Overview

I simulated an RDP brute force attack from a Kali Linux VM against a Windows 11 endpoint (`windows11_finance`) representing a finance department workstation. The attack was detected by Wazuh via repeated Windows Event ID 4625 failures, automatically forwarded to TheHive through a custom Python integration, enriched using Cortex analyzers, and contained via an OPNsense firewall block rule.

This case also uncovered a detection gap in Windows audit policy configuration — a successful credential validation was not logged as a 4624 event — which was identified, root-caused, and remediated during the investigation.

---

## 🎯 Objectives

- Simulate a realistic RDP brute force attack against a Windows endpoint
- Validate that Wazuh detects and correlates repeated authentication failures
- Triage the alert end-to-end through TheHive using the automated Wazuh → TheHive pipeline
- Enrich the attacker IP observable using Cortex analyzers
- Apply host containment via OPNsense firewall rule
- Identify and remediate a Windows audit policy detection gap

---

## 🧰 Tools & Technologies

| Tool | Purpose |
| --- | --- |
| **Kali Linux + Hydra** | Attack simulation — RDP brute force |
| **Wazuh** | SIEM detection — Event ID 4625 correlation, Rules 60122 / 60204 |
| **TheHive** | Incident case management and analyst workflow |
| **Cortex + VirusTotal** | Observable enrichment — IP reputation analysis |
| **OPNsense** | Perimeter containment — firewall block rule |
| **Nmap** | Containment verification |

---

## 🏗️ Lab Environment

- **Attacker:** Kali Linux VM — `192.168.100.154`
- **Target:** Windows 11 VM (`windows11_finance`) — `192.168.100.161`, Wazuh Agent ID 003
- **SIEM:** Wazuh Manager on Ubuntu Server VM
- **IR Stack:** TheHive + Cortex deployed via Docker Compose on Ubuntu Server
- **Firewall:** OPNsense with Suricata IPS on LAN interface
- **Network:** Isolated VMware LAN subnet — all VMs on the same /24 segment

---

## ⚔️ Attack Simulation

I launched the brute force attack from Kali Linux using **Hydra v9.6** targeting RDP (port 3389) on the Windows 11 endpoint:

```bash
hydra -l Administrator -P custom_pass.txt rdp://192.168.100.161 -t 1 -W 3
```

- `-t 1` — single thread to generate realistic sequential login noise
- `-W 3` — 3 second wait between attempts
- Password list contained 21 entries including the valid credential

Hydra successfully identified valid credentials for the `Administrator` account within approximately 2 minutes.

---

## 🔍 Detection

### Wazuh Alert — Rule 60122 (Logon Failure)

Wazuh detected the attack via Windows Event ID **4625** (failed logon) forwarded from the `windows11_finance` agent. Rule **60122** fired repeatedly as individual failures were logged, followed by Rule **60204** (Multiple Windows Logon Failures) as the aggregated correlation rule.

### Alert Detail — Wazuh Event Metadata

Inspecting an individual alert confirmed the attack vector and source:

| Field | Value |
| --- | --- |
| `agent.name` | windows11_finance |
| `agent.ip` | 192.168.100.161 |
| `data.win.eventdata.ipAddress` | 192.168.100.154 |
| `data.win.eventdata.targetUserName` | Administrator |
| `data.win.eventdata.workstationName` | kali |
| `data.win.eventdata.logonType` | 3 (Network) |
| `rule.mitre.id` | T1110 |
| `rule.mitre.tactic` | Credential Access |

---

## 🔎 Detection Gap — Missing 4624 Success Event

### Finding

Despite Hydra confirming a valid credential was found, **no Event ID 4624 (successful logon) was observed in Wazuh.** The detection pipeline captured all 4625 failures but missed the credential validation success.

### Root Cause

Windows only logs Event ID 4624 on a fully established interactive session — not on a raw credential handshake. Hydra validates credentials at the protocol level without completing a full RDP session, so no success event is written to the Security log.

Additionally, the Windows audit policy on `windows11_finance` was not configured to capture logon successes:

```
auditpol /get /category:"Logon/Logoff"
# Result: Failure only — Success not enabled
```

### Remediation Applied

```cmd
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Account Logon" /success:enable /failure:enable
```

### Recommendation

In a production environment, Windows audit policy should be enforced via **Group Policy (GPO)** across all endpoints to ensure consistent success and failure logging. Detection should also be supplemented with **network-level RDP monitoring via Suricata** to catch credential validation independent of host-based logging.

---

## 🗂️ TheHive — Case Management

The Wazuh → TheHive integration automatically forwarded the 60204 alert to TheHive as a structured alert. I promoted it to a full case and assigned the following:

- **Title:** Multiple Windows Logon Failures
- **Severity:** Medium (upgraded to High on escalation)
- **TLP:** Amber
- **Tags:** `brute-force` `RDP` `T1110` `windows` `wazuh` `credential-access`

### Observables Added

| Type | Value | Classification |
| --- | --- | --- |
| IP  | 192.168.100.154 | Malicious (attacker) |
| IP  | 192.168.100.161 | Suspicious (target) |
| hostname | windows11_finance | Suspicious |

---

## 🔬 Cortex Enrichment

I ran Cortex analyzers on the attacker IP observable (`192.168.100.154`):

| Analyzer | Result |
| --- | --- |
| **VirusTotal** | 0/94 engines flagged — clean (expected: internal lab IP) |
| **AbuseIPDB** | No reports — internal RFC1918 address |

> **Note:** In a real-world investigation, this step would run against an external attacker IP. Cortex returned clean results as expected for an internal lab address. The process and pipeline were validated successfully.

---

## 🛡️ Containment

### OPNsense Firewall Block Rule

I applied a full host containment rule in OPNsense blocking all outbound traffic from the attacker IP on the LAN interface:

| Field | Value |
| --- | --- |
| Action | Block |
| Interface | LAN |
| Direction | Inbound |
| Protocol | TCP |
| Source | 192.168.100.154 (Kali) |
| Destination | Any |
| Description | BLOCK - RDP Brute Force - TheHive Case #1 |

**Containment rationale:** Full host block applied rather than port-specific rule to prevent lateral movement to other hosts on the network segment following a confirmed brute force event.

### Block Verification — Nmap

Post-containment, I ran an Nmap scan from Kali to confirm the rule was active:

```bash
nmap -p 3389 192.168.100.161
```

Result: `Host seems down` — port filtered, connection blocked.

---

## 📋 IR Timeline

| Time | Event |
| --- | --- |
| 17:18:51 | Hydra brute force launched from Kali against `192.168.100.161:3389` |
| 17:18:51 – 17:20:52 | 21 login attempts executed over ~2 minutes |
| 23:20:10 | Wazuh Rule 60204 fired — Multiple Windows Logon Failures |
| 23:20:10 – 23:20:47 | Rule 60122 firing repeatedly on individual 4625 events |
| 23:12 | Wazuh → TheHive integration auto-forwarded alert |
| 23:12 | Alert promoted to Case #1 in TheHive |
| 23:12 | Cortex analyzers executed on attacker IP observable |
| 00:00 | OPNsense block rule applied — full host containment |
| 00:15 | Tasks assigned and completed in TheHive |
| 00:19 | Nmap confirmed connection filtered |
| 00:19 | Case closed — True Positive |

---

## 📝 Lessons Learned

**1. Audit policy must be enforced at deployment, not patched reactively.**
The missing 4624 success event was only discovered during the investigation. In a real environment, this gap could allow an attacker's successful logon to go undetected while only failures are logged. GPO enforcement of audit policy is critical.

**2. Automated detection-to-case pipeline significantly reduces MTTD.**
The Wazuh → TheHive integration created a structured case automatically — no manual alert-to-ticket translation needed. This mirrors how MSSPs operate at scale and reduces analyst toil during high-volume alert periods.

**3. Cortex enrichment is most valuable for external IPs.**
For internal lab IPs, enrichment returns clean results by design. The value of Cortex becomes apparent when triaging external attacker IPs against reputation databases — a key step in any real phishing or intrusion investigation.

**4. Targeted vs. full host containment is a judgment call.**
A port-specific block (3389 only) would have stopped the RDP attack. A full host block prevents lateral movement to other network assets. In this case, full containment was applied based on confirmed malicious activity. In production, this decision would be escalated to Tier 2 before applying a broad block.

---

## 📁 Evidence

```
/case-001/
  ├── README.md
  ├── /screenshots/
  │   ├── loginfound.png          — Hydra output confirming valid credential
  │   ├── wazuh-alerts-spike.png  — Wazuh 60122 alert volume spike
  │   ├── wazuh-alert-detail.png  — Wazuh Rule 60204 full alert metadata
  │   ├── wazuh-event-json.png    — Raw event data from Wazuh Discover
  │   ├── thehive-alert-queue.png — Auto-forwarded alert in TheHive
  │   ├── thehive-case-tasks.png  — Case tasks completed
  │   ├── cortex-virustotal.png   — Cortex VirusTotal enrichment result
  │   ├── opnsense-block-rule.png — Firewall containment rule
  │   └── nmap-filtered.png       — Post-block Nmap verification
  └── /logs/
      └── wazuh-alert-60122.json  — Raw Wazuh alert JSON export
```

---

## 🔗 References

- [MITRE ATT&CK — T1110 Brute Force](https://attack.mitre.org/techniques/T1110/)
- [Wazuh Rules — Windows Authentication](https://documentation.wazuh.com/current/user-manual/ruleset/rules-classification.html)
- [Windows Event ID 4625 Documentation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625)
- [Hydra — THC Hydra](https://github.com/vanhauser-thc/thc-hydra)
- [TheHive Project](https://thehive-project.org/)
