# 🔵 Blue Team Cases

> Documented incident response and detection cases conducted inside a fully isolated SOC home lab. Each case follows the complete Tier 1–2 SOC analyst workflow — from initial alert triage through containment, enrichment, and formal case closure.

---

## 🏗️ Lab Environment

All cases are conducted inside a purpose-built enterprise-grade SOC lab consisting of:

| Component | Role |
| --- | --- |
| **Kali Linux** | Adversary emulation / attack simulation |
| **OPNsense + Suricata** | Perimeter firewall + inline IPS |
| **Wazuh** | SIEM + EDR — log aggregation, detection, endpoint monitoring |
| **TheHive** | Incident case management and analyst workflow |
| **Cortex** | Automated IOC enrichment and observable analysis |
| **MISP** | Threat intelligence platform — IOC feeds and TTP context |

Every case begins with a simulated adversary action and flows through the full alert lifecycle: **detection → triage → enrichment → containment → closure.**

---

## 📂 Case Index

| ID  | Title | Tactic | Technique | Severity | Status |
| --- | --- | --- | --- | --- | --- |
| [BC-001](./case-001/) | RDP Brute Force — Credential Access Detection & Response | Credential Access | T1110 — Brute Force | 🟠 Medium | ✅ Resolved |
| BC-002 | *Coming soon* | —   | —   | —   | 🔄 Planned |
| BC-003 | *Coming soon* | —   | —   | —   | 🔄 Planned |

---

## 🔄 SOC Workflow — How Each Case Is Structured

Every case in this repository mirrors the workflow a Tier 1–2 SOC analyst executes on a real shift:

```
1. SIMULATE    →  Adversary activity generated from Kali Linux
2. DETECT      →  Wazuh detection rules fire on suspicious telemetry
3. ALERT       →  Wazuh auto-forwards alert to TheHive via custom integration
4. TRIAGE      →  Alert reviewed, severity assessed, case promoted in TheHive
5. ENRICH      →  Cortex analyzers run on extracted observables (IPs, hashes)
6. CONTEXTUALIZE → MISP cross-references IOCs against threat intelligence feeds
7. CONTAIN     →  Response action executed (firewall block, account lockout, etc.)
8. CLOSE       →  IR timeline documented, case resolved, lessons learned captured
9. MAP         →  Technique mapped to MITRE ATT&CK framework
```

---

## 🗺️ MITRE ATT&CK Coverage

| Tactic | Technique | Case |
| --- | --- | --- |
| Credential Access | T1110 — Brute Force | BC-001 |

---

## 🧰 Tools Used Across Cases

`Wazuh` `TheHive` `Cortex` `MISP` `OPNsense` `Suricata` `Kali Linux` `Hydra` `Nmap` `VirusTotal` `AbuseIPDB`

---

> 📄 Full lab architecture and setup documentation → [LAB-SETUP.md](../../LAB-SETUP.md)
