<img width="437" height="324" alt="vmware_syg6dATZr7" src="https://github.com/user-attachments/assets/ab4526ab-2b61-4146-b949-38c1ada13f3a" /># Cybersecurity SOC Home Lab — Full Stack Defensive/Offensive Architecture

## 🎯 Purpose of This Lab Setup

This lab setup documents the architecture and selected tools used to replicate a realistic Security Operations Center (SOC) environment. It is designed to demonstrate hands-on experience with both offensive simulation and defensive telemetry collection, detection, and response workflows, emulating real-world enterprise security operations.

The goal of this setup is to:

- Deploy foundational security tooling that mirrors production SOC stacks

- Generate meaningful telemetry from simulated attacker activity

- Correlate and analyze logs across network, endpoint, and SIEM platforms

- Support incident investigation workflows with case management and automated enrichment

- Integrate threat intelligence into detection logic and alert triage

## 🚀 Quick Navigation
Click a link to jump to that section below

- [Kali Linux - Attacker Platform](#kali-linux---attacker-platform)
- [OPNsense - Perimeter Firewall](#opnsense---perimeter-firewall)
- [Wazuh SIEM - Log Aggregation Detection](#wazuh-siem---log-aggregation-detection)
- [TheHive - Case Management](#thehive---case-management)
- [Cortex - Automated Analysis](#cortex---automated-analysis)
- [MISP - Threat Intelligence Platform](#misp---threat-intelligence-platform)
- [CrowdStrike Falcon - Endpoint Protection EDR](#crowdstrike-falcon---endpoint-protection-edr)
- [How Components Interact](#how-components-interact)

---

## Kali Linux - Attacker Platform
- [Downloaded VMware machine directly from kali.org]
- [Changed 2gb to 4 ram, changed network settings to the private VM2 (same subnet as OPNsense LAN)]
- [Installed through GUI]
- [Ran sudo apt update && sudo apt upgrade command to see if its up to date]

---

## OPNsense - Perimeter Firewall 

  
### Configuration And Installation
- Downloaded the opnsense.b2 file directly from opnsense.org

- Installed bunzip2 on my Windows main machine and extracted the opnsense b2 file

- Created a new machine with FreeBD12 and two network Adapters. First adapter acting as WAN (My NAT) and the second adapter acting as LAN (VM2) same subnet as my Kali Attack machine.

- Assigned interfaces WAN to em0 and LAN to em1 accordingly

<img width="101" height="44" alt="NVIDIA_Overlay_B0rqavcjFL" src="https://github.com/user-attachments/assets/578aefe8-8a8d-4aa2-a149-388b82beb129" />

-Set the LAN IPv4 adress on my subnet with 24 bit count, of course. No IPv6 at the moment]

 <img width="572" height="371" alt="NVIDIA_Overlay_s5vwOOtNx4" src="https://github.com/user-attachments/assets/9ffb5f53-c739-432e-b7ff-33a1bc14c3e5" />

- Updated OPNsense firmware, installed the vmware-tools plugin
- Configured and enabled Netmap(IPS) like this:

<img width="679" height="525" alt="NVIDIA_Overlay_6wqhzsvUgW" src="https://github.com/user-attachments/assets/b653e122-a8f3-44d5-bf0d-103c9d61e826" />

 Note: Using Hyperscan for better performance, and enabling it only on my LAN for now.

- Enabling Secure Shell and permitting default root and password since it cant be accessed from WAN right now, in a real environment this would be set up differently

<img width="671" height="523" alt="NVIDIA_Overlay_aj2EmKWc1m" src="https://github.com/user-attachments/assets/ca7d4dc5-05a1-4a1e-af1e-f8977a492079" />

### Adding Custom IPS Rules
- Downloading FilaZilla on my Kali Attack machine and connection with 
```python
sftp://ipadress root@password:22
```

- Changed my mind and SSHed into OPNsense and edited one of the test files on `/usr/local/etc/suricata/opnsense_rules/opnsense_test.rules` after installing nano on the opnsense machine

- Git cloned some of the ready open-source Suricata rules for nmap from https://github.com/aleksibovellan/opnsense-suricata-nmaps

 <img width="743" height="432" alt="NVIDIA_Overlay_5BTqlNLcVR" src="https://github.com/user-attachments/assets/477608f8-8d4b-4e27-ae56-3e370f9ae9fe" />

 - Learned and read about how Suricata signatures work from the documentation website, so i know exactly know what it does and that i can create my own rules in the future if i need them
-Ran a T4 nmap scan from my Kali Attack Machine with 
`nmap -T4 --top-ports 500 192.168.242.25` (my opnsense IP adress)

<img width="510" height="303" alt="NVIDIA_Overlay_Q59nkCGM4j" src="https://github.com/user-attachments/assets/2fc197df-658a-4172-9d99-1628766dd4a6" />



---

## Wazuh SIEM - Log Aggregation Detection

### Deploying the manager


- Downloaded and installed latest ubuntu machine on vmware
 
- Downloaded vmware tools and curl on ubuntu server
 
- Ran curl `-sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a`  to install the manager.
 
 <img width="844" height="280" alt="NVIDIA_Overlay_6sP6Bk73Tf" src="https://github.com/user-attachments/assets/560c6030-2ee4-4925-9955-aac53999565c" />
 
 - Wazuh got installed.
 
 - <img width="495" height="319" alt="vmware_5Ekx5YDaJJ" src="https://github.com/user-attachments/assets/bd35e201-f35d-45a7-b6d7-7c8cd30f068c" />

 
 ### Deploying Windows Agent
 
 - Downloading the Windows 11 ISO
 - Installing it on VMWare
 - 
 - <img width="437" height="324" alt="vmware_syg6dATZr7" src="https://github.com/user-attachments/assets/b4b25390-d286-4ce1-8554-a24114f3e4ab" />

 - Installing the agent on the W11 Machine with `Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.3-1.msi -OutFile $env:tmp\wazuh-agent; msiexec.exe /i $env:tmp\wazuh-agent /q WAZUH_MANAGER='192.168.205.131' WAZUH_AGENT_NAME='Windows11Financee'`
 - 

<img width="701" height="647" alt="vmware_I6aqGn3Sqx" src="https://github.com/user-attachments/assets/d93f2507-e554-4af3-8240-52344052c6a6" />

 - Verifying that agent is installed after looking at the endpoints
   

 <img width="586" height="220" alt="vmware_W52iD5uOjw" src="https://github.com/user-attachments/assets/92744f1b-b07e-444f-b25c-c1adcb1a9d50" />

 
 
 
---

## TheHive - Case Management
*(Your content goes here)*

---

## Cortex - Automated Analysis
*(Your content goes here)*

---

## MISP - Threat Intelligence Platform
*(Your content goes here)*

---

## CrowdStrike Falcon - Endpoint Protection EDR
*(Your content goes here)*

---

## How Components Interact
*(Your content goes here)*
