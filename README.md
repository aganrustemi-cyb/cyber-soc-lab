# 🛡️ Cyber SOC Home Lab

> A fully isolated, enterprise-grade Security Operations Center built from scratch — simulating real Tier 1–2 SOC analyst workflows across attack simulation, detection engineering, incident response, and threat intelligence.

---

## 📁 Repository Navigation

| Section | Description |
|---|---|
| [⚙️ Lab Setup](https://github.com/aganrustemi-cyb/cyber-soc-lab/blob/main/LAB-SETUP.md) | Full architecture, deployment steps, and integration documentation |
| [🔴🔵 Red & Blue Team Cases](https://github.com/aganrustemi-cyb/cyber-soc-lab/tree/main/cases) | Attack scenarios paired with detection and response walkthroughs |
| [🔍 Detection Rules](https://github.com/aganrustemi-cyb/cyber-soc-lab/tree/main/detection-rules) | Custom Wazuh and Suricata rules written for the lab environment |
| [🚨 Incident Response](https://github.com/aganrustemi-cyb/cyber-soc-lab/tree/main/incident-response) | Structured IR reports and response playbooks |
| [🗺️ MITRE ATT&CK Mapping](https://github.com/aganrustemi-cyb/cyber-soc-lab/tree/main/mitre-mapping) | Techniques mapped to the ATT&CK framework |
| [🕵️ Threat Hunting](https://github.com/aganrustemi-cyb/cyber-soc-lab/tree/main/threat-hunting) | Hypothesis-driven hunts conducted across lab telemetry |
| [📚 Resources](https://github.com/aganrustemi-cyb/cyber-soc-lab/tree/main/resources) | References and learning material used throughout the build |
| [🔧 Tools & Configs](https://github.com/aganrustemi-cyb/cyber-soc-lab/tree/main/tools-configs) | Configuration files, scripts, and integration artifacts |

---

## 🏗️ Lab Architecture

```
┌──────────────────────────────────────────────┐
│          ATTACK SIMULATION                   │
│     Kali Linux — adversary emulation         │
└─────────────────┬────────────────────────────┘
                  │
┌─────────────────▼────────────────────────────┐
│          PERIMETER SECURITY                  │
│     OPNsense Firewall + Suricata IPS         │
└─────────────────┬────────────────────────────┘
                  │
┌─────────────────▼────────────────────────────┐
│       SIEM / LOG AGGREGATION / EDR           │
│  Wazuh — correlation, alerting, FIM, SCA     │
└─────────────────┬────────────────────────────┘
                  │  alert forwarding
┌─────────────────▼────────────────────────────┐
│       INCIDENT RESPONSE & THREAT INTEL       │
│  TheHive (cases) · Cortex (enrichment)       │
│  MISP (IOCs, TTPs, threat intelligence)      │
└──────────────────────────────────────────────┘
```

---

## 🧰 Stack Overview

| Component | Role |
|---|---|
| **Kali Linux** | Attack simulation — generates realistic threat telemetry |
| **OPNsense** | Perimeter firewall — traffic segmentation + Suricata IPS |
| **Wazuh** | SIEM + EDR — log aggregation, detection, FIM, endpoint monitoring |
| **TheHive** | Incident case management — structured triage and investigation |
| **Cortex** | Enrichment engine — automated IOC analysis via analyzers |
| **MISP** | Threat intelligence — IOC feeds, TTP context, campaign data |

---

## 🔄 SOC Workflow — Alert Lifecycle

A key goal of this lab is to practice the **end-to-end alert lifecycle** that a SOC analyst handles daily. Every simulated attack flows through the full pipeline:

```
1. GENERATE      →  Adversary activity simulated from Kali Linux
2. DETECT        →  Suricata IPS + Wazuh rules fire on suspicious telemetry
3. ALERT         →  Wazuh raises structured security event
4. FORWARD       →  Custom integration pushes alert to TheHive automatically
5. TRIAGE        →  Alert reviewed, severity assessed, case opened in TheHive
6. ENRICH        →  Cortex analyzers run on observables (IPs, hashes, domains)
7. CONTEXTUALIZE →  MISP cross-references IOCs against threat intelligence feeds
8. RESPOND       →  Response actions documented; IR report produced
9. MAP           →  Technique mapped to MITRE ATT&CK framework
```

This pipeline mirrors the workflow a Tier 1–2 analyst follows on every shift.

---

## 🎯 What This Lab Demonstrates

This build goes beyond installing tools. It demonstrates the ability to **integrate, configure, and orchestrate** multiple security systems into a cohesive detection and response pipeline — replicating infrastructure used in real SOC environments.

**Core competencies practiced:**

- Centralized log collection and cross-source event correlation
- Custom detection rule authoring and tuning (Wazuh + Suricata)
- Alert generation from simulated adversary activity
- Case creation, triage, and structured investigation workflows (TheHive)
- Automated observable enrichment (Cortex analyzers)
- Threat intelligence integration and IOC-driven detection (MISP)
- MITRE ATT&CK technique mapping and adversary emulation
- Hypothesis-driven threat hunting across SIEM telemetry
- End-to-end incident response documentation

Together, this stack covers the **full alert lifecycle** — from telemetry generation through detection, investigation, enrichment, and response — directly mirroring Tier 1–2 SOC analyst responsibilities.

---

## 🗺️ MITRE ATT&CK Coverage

Simulated attacks and detections in this lab are mapped to the [MITRE ATT&CK Framework](https://attack.mitre.org/), documenting which techniques were emulated, detected, and responded to.

| Tactic | Example Techniques Covered |
|---|---|
| **Reconnaissance** | T1046 — Network Service Scanning (Nmap) |
| **Discovery** | T1082 — System Information Discovery |
| **Lateral Movement** | T1021 — Remote Services |
| **Command & Control** | T1071 — Application Layer Protocol |
| **Credential Access** | T1110 — Brute Force |
| **Exfiltration** | T1041 — Exfiltration Over C2 Channel |

> Full technique mapping available in the [MITRE Mapping folder](https://github.com/aganrustemi-cyb/cyber-soc-lab/tree/main/mitre-mapping).

---

## 🔬 Skills & Tools Index

A quick-reference index of the technologies and skills demonstrated across this repository — aligned with common SOC analyst job requirements.

**SIEM & Detection**
`Wazuh` `Suricata` `Custom Detection Rules` `Log Correlation` `Alert Tuning` `FIM` `SCA`

**Incident Response**
`TheHive` `Case Management` `Alert Triage` `IR Documentation` `Response Playbooks`

**Threat Intelligence**
`MISP` `IOC Enrichment` `TTP Mapping` `Threat Feeds` `MITRE ATT&CK`

**Security Automation**
`Cortex` `Python Scripting` `REST API Integration` `Wazuh Custom Integrations`

**Network Security**
`OPNsense` `Firewall Configuration` `IPS/IDS` `Traffic Segmentation` `Network Forensics`

**Infrastructure & Deployment**
`Docker` `Docker Compose` `Linux Administration` `VMware` `Ubuntu Server`

**Offensive / Adversary Emulation**
`Kali Linux` `Nmap` `Attack Simulation` `Red Team Scenarios`

---

## 📊 Lab at a Glance

| Metric | Value |
|---|---|
| **VMs deployed** | 5 (Kali, OPNsense, Wazuh, Ubuntu/Docker, Windows 11) |
| **Integrated services** | 6 (Wazuh, TheHive, Cortex, MISP, OPNsense, Kali) |
| **Custom integrations built** | 1 (Wazuh → TheHive Python pipeline) |
| **Detection rule sources** | Wazuh built-in + custom Suricata rules |
| **Deployment method** | VMware (VMs) + Docker Compose (IR stack) |
| **Network architecture** | Isolated LAN subnet + NAT WAN |

---

## 🗂️ Repository Structure

```
Cyber-SOC-Lab/
│
├── README.md
├── ABOUT_ME.md
├── CERTIFICATIONS.md
├── SKILLS-MATRIX.md
├── LAB-SETUP.md
│
├── cases/
│   ├── red-team/
│   │   └── Case-001-Example/
│   │       ├── README.md
│   │       ├── evidence/
│   │       ├── notes.md
│   │       └── artifacts/
│   │
│   └── blue-team/
│       └── Case-001-Example/
│           ├── README.md
│           ├── evidence/
│           ├── notes.md
│           └── artifacts/
│
├── detection-rules/
│   ├── sigma/
│   ├── wazuh/
│   └── splunk/
│
├── threat-hunting/
│   ├── TH-001/
│   └── TH-002/
│
├── incident-response/
│   ├── IR-001/
│   └── IR-002/
│
├── tools-configs/
│
├── mitre-mapping/
│
└── resources/
```
