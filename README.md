I designed and deployed a fully isolated Security Operations Center (SOC) home lab that mirrors the workflows and tooling used in modern enterprise security operations. This environment is intended for hands-on practice with both offense (attack simulation) and defense (detection, analysis, and response), giving me practical experience that goes far beyond theoretical study.

This lab incorporates key defensive and investigative technologies — from log aggregation and correlation to case management and threat intelligence — and is configured to ingest, correlate, and act on telemetry generated internally by simulated attacks.

🔧 Architecture & Core Components

Attack Simulation & Adversary Emulation
Using Kali Linux and purpose-built attack vectors to generate realistic threat activity that produces detectable telemetry across defensive stacks.

Edge Security & Network Traffic Control
OPNsense serves as the virtual perimeter firewall, enforcing segmentation and forwarding traffic logs for centralized analysis.

Centralized Monitoring & Event Correlation
Wazuh SIEM aggregates logs from agents, endpoints, and firewalls to perform correlation, alerting, and pattern detection across data sources.

Incident Case Management & Automation
TheHive enables structured investigation workflows, while Cortex automates enrichment of observables within incidents.

Threat Intelligence Integration
MISP provides contextual threat data (IOCs, TTPs, campaigns) which enriches detection logic and improves alert relevance.

Endpoint Visibility & Response
CrowdStrike Falcon EDR augments endpoint telemetry, offering real-time behavioral detection and enhanced analytical data.

Together, this stack forms a defense-in-depth SOC environment, capturing the full lifecycle of alert generation, detection, investigation, and response — effectively training for real Tier 1–Tier 2 SOC analyst responsibilities.

🎯 What This Build Demonstrates

This lab goes beyond installing tools: it shows integration, configuration, and workflow orchestration among multiple security systems, replicating a realistic monitoring and response infrastructure similar to what’s used in real SOC teams. The lab has enabled me to practice:

Centralized log collection and event correlation

Custom alert creation and tuning

Generation of actionable security alerts from simulated attacks

Case creation, triage, and investigation workflows

Enrichment with threat intelligence and automated analysis

<details>
  <summary>Click to view lab sctructure for easier navigation</summary>
```
  Cyber-SOC-Lab/
│
├── README.md                    ⭐ Landing / Portfolio Homepage
├── ABOUT_ME.md                  ⭐ Short professional overview + contact
├── CERTIFICATIONS.md            ⭐ Verified security certs list
├── SKILLS-MATRIX.md             ⭐ Skills you’ve built (tools, tech areas)
├── LAB-SETUP.md                 ⭐ How your SOC lab / environment is built
│
├── cases/
│   ├── red-team/
│   │     └── Case-001-Example/
│   │           ├── README.md     📌 Case write-up
│   │           ├── evidence/     📸 Screenshots, logs
│   │           ├── notes.md      🧠 Investigator’s notes
│   │           └── artifacts/    🗂 Logs, pcap, SIEM exports
│   └── blue-team/
│         └── Case-001-Example/
│               ├── README.md
│               ├── evidence/
│               ├── notes.md
│               └── artifacts/
│
├── detection-rules/             📊 Custom SIEM / IDS rules
│     ├── sigma/
│     ├── wazuh/
│     └── splunk/
│
├── threat-hunting/              🕵️ Hunt hypotheses & results
│     ├── TH-001/
│     └── TH-002/
│
├── incident-response/           🚨 Response playbooks & reports
│     ├── IR-001/
│     └── IR-002/
│
├── tools-configs/               🔧 Configs for SIEM, Sysmon, etc.
│
├── mitre-mapping/               📌 MITRE ATT&CK coverage tracker
│
└── resources/                   📎 Helpful external links & guides

```
</details>

Endpoint behavioral monitoring

This build illustrates my ability to deploy, integrate, and operate complex security tooling, replicate adversary activity, and extract meaningful insights through analysis — core competencies expected of entry to mid-level SOC analysts.
