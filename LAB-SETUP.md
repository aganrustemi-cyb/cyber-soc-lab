# 🛡️ SOC Home Lab — Full-Stack Defensive Architecture

> **Hands-on simulation of an enterprise Security Operations Center using open-source tooling.**  
> This lab replicates real-world SOC workflows: log ingestion, threat detection, incident case management, automated enrichment, and threat intelligence integration.

---

## 📐 Lab Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        ATTACK SIMULATION                        │
│                        Kali Linux VM                            │
└────────────────────────────┬────────────────────────────────────┘
                             │  LAN (VM2 subnet)
┌────────────────────────────▼────────────────────────────────────┐
│                    PERIMETER SECURITY                           │
│              OPNsense Firewall + Suricata IPS                   │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│               SIEM / LOG AGGREGATION / EDR                      │
│         Wazuh Manager + Windows Agent (FIM · SCA · EDR)         │
└─────────────────────────────┬───────────────────────────────────┘
                              │  Alert forwarding (custom integration)
                   ┌──────────▼──────────────────────────────────┐
                   │         INCIDENT RESPONSE STACK              │
                   │  TheHive · Cortex · MISP (Docker)            │
                   │  Case Mgmt · Enrichment · Threat Intel       │
                   └─────────────────────────────────────────────┘
```

---

## 🧰 Stack at a Glance

| Component | Role | Deployment |
|---|---|---|
| **Kali Linux** | Attack simulation / red team | VMware VM |
| **OPNsense** | Perimeter firewall + Suricata IPS | VMware VM (FreeBSD) |
| **Wazuh** | SIEM + EDR — log aggregation, detection, FIM & endpoint monitoring | Ubuntu Server VM |
| **TheHive** | Incident case management | Docker (Ubuntu) |
| **Cortex** | Automated analysis & IOC enrichment | Docker (Ubuntu) |
| **MISP** | Threat intelligence platform | Docker (Ubuntu) |

---

## 📋 Quick Navigation

- [Kali Linux — Attacker Platform](#-kali-linux--attacker-platform)
- [OPNsense — Perimeter Firewall & IPS](#-opnsense--perimeter-firewall--ips)
- [Wazuh — SIEM, EDR & Log Aggregation](#-wazuh--siem-edr--log-aggregation)
- [TheHive + Cortex + MISP — IR Stack](#-thehive--cortex--misp--incident-response-stack)
- [Wazuh → TheHive Integration](#-wazuh--thehive-integration)
- [End-to-End Data Flow](#-end-to-end-data-flow)

---

## 🐉 Kali Linux — Attacker Platform

**Purpose:** Simulate adversary activity to generate realistic telemetry across the lab environment.

**Setup:**
- Deployed pre-built VMware image from kali.org
- Allocated 4 GB RAM; connected to VM2 (LAN) subnet — same network segment as OPNsense
- Updated all packages post-install: `sudo apt update && sudo apt upgrade`

**Used to simulate:** Nmap reconnaissance, port scanning, and network-layer attack patterns detected by Suricata IPS.

---

## 🔥 OPNsense — Perimeter Firewall & IPS

**Purpose:** Act as the lab's network perimeter — enforce traffic segmentation and detect malicious activity with inline IPS.

### Network Configuration

| Interface | Adapter | Role |
|---|---|---|
| WAN (em0) | NAT | Uplink to host network |
| LAN (em1) | VM2 | Internal lab subnet |

- Extracted OPNsense `.img` from `.bz2` archive on Windows host using `bunzip2`
- Deployed as FreeBSD 12 VM; assigned static LAN IPv4 with /24 prefix
- Installed `vmware-tools` plugin; upgraded firmware post-deploy

### IPS Configuration (Suricata via Netmap)

- Enabled **Netmap** mode for inline IPS operation on the LAN interface
- Selected **Hyperscan** pattern matcher for improved rule-matching performance
- SSH access enabled for rule management (root login permitted on LAN only — noted as lab-only configuration; in production this would be restricted to key-based auth on a management VLAN)

### Custom Suricata Rules — Nmap Detection

Deployed open-source Suricata rules from [`aleksibovellan/opnsense-suricata-nmaps`](https://github.com/aleksibovellan/opnsense-suricata-nmaps) to detect reconnaissance scanning.

Rules were reviewed against [Suricata documentation](https://suricata.readthedocs.io/) to understand signature structure and build capability for writing custom rules.

**Validation test — Nmap T4 scan from Kali:**
```bash
nmap -T4 --top-ports 500 192.168.242.25
```
Confirmed Suricata alerts triggered on IPS interface.

<img width="510" height="303" alt="Nmap scan detected by Suricata" src="https://github.com/user-attachments/assets/2fc197df-658a-4172-9d99-1628766dd4a6" />

---

## 📊 Wazuh — SIEM, EDR & Log Aggregation

**Purpose:** Central log aggregation, endpoint detection & response (EDR), security event correlation, and rule-based alerting across endpoints. Wazuh agents provide host-based visibility including file integrity monitoring (FIM), security configuration assessment (SCA), and active response capabilities.

### Manager Deployment (Ubuntu Server)

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && \
sudo bash ./wazuh-install.sh -a
```

All-in-one installation deploys: Wazuh Manager, Indexer, and Dashboard.

<img width="844" height="280" alt="Wazuh installation" src="https://github.com/user-attachments/assets/560c6030-2ee4-4925-9955-aac53999565c" />

### Windows 11 Agent Deployment

Deployed a Windows 11 VM (named `Windows11Finance` to simulate an endpoint in a finance department).

Agent installed via PowerShell:
```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.3-1.msi `
  -OutFile $env:tmp\wazuh-agent
msiexec.exe /i $env:tmp\wazuh-agent /q `
  WAZUH_MANAGER='192.168.205.131' `
  WAZUH_AGENT_NAME='Windows11Finance'
```

Agent verified as active in Wazuh Dashboard:

<img width="586" height="220" alt="Agent confirmed active" src="https://github.com/user-attachments/assets/92744f1b-b07e-444f-b25c-c1adcb1a9d50" />

---

## 🐝 TheHive + Cortex + MISP — Incident Response Stack

**Purpose:** Full incident response and threat intelligence pipeline — from alert triage to IOC enrichment and case management.

### Infrastructure

All three services deployed via Docker Compose on Ubuntu Server (12–16 GB RAM recommended).

| Service | Role |
|---|---|
| **TheHive** | Case and incident management |
| **Cortex** | Analyzer engine — automated IOC enrichment |
| **MISP** | Threat intelligence — IOC feeds and sharing |
| **Redis** | Task queue backend for Cortex/MISP |
| **MySQL** | Persistent storage for MISP |

### Deployment

```bash
# Install Docker
sudo apt update && sudo apt install docker-compose
sudo systemctl enable docker && sudo systemctl start docker

# Deploy stack
mkdir soc-stack && cd soc-stack
# docker-compose.yml sourced from: https://github.com/ls111-cybersec/thehive-cortex-misp-docker-compose-lab11update
docker compose up -d

# Verify all containers running
docker ps
```

**Service endpoints:**

| Service | URL |
|---|---|
| MISP | `http://<VM_IP>` |
| TheHive | `http://<VM_IP>:9000` |
| Cortex | `http://<VM_IP>:9001` |

---

### 🔧 Troubleshooting: MISP Base URL Misconfiguration

**Symptoms observed:**
- Infinite login redirect loop
- CSS and logo assets failing to load
- Session authentication failures
- Requests resolving to NAT IP (`10.0.2.10`) instead of VM bridged IP

**Root cause:**  
MISP dynamically generates static asset paths and session tokens based on `HOSTNAME` and `MISP_BASEURL`. Leaving these set to `localhost` or the VMware NAT address caused all asset routing and session validation to break.

**Before (broken):**
```env
HOSTNAME=https://10.0.2.10
MISP_BASEURL=localhost
```

**After (corrected):**
```env
HOSTNAME=http://192.168.100.162
MISP_BASEURL=http://192.168.100.162
```

**Resolution steps:**
1. Updated `.env` to use the bridged VM IP
2. Restarted containers: `docker compose down && docker compose up -d`
3. Cleared browser session cookies
4. Validated asset paths via browser DevTools

**Takeaway:** Demonstrated understanding of container networking (Bridged vs NAT), HTTP session persistence, and application-layer routing behavior.

---

### 🔧 Troubleshooting: CakePHP Cache Errors (MISP)

```bash
docker exec -it misp-core bash
rm -rf /var/www/MISP/app/tmp/cache/*
chown -R www-data:www-data /var/www/MISP/app/tmp
docker restart misp-core
```

---

### Integration: Cortex → TheHive

Configured Cortex as an enrichment provider inside TheHive using the internal Docker hostname:
```
http://cortex:9001
```
Analyzers enabled for automated IOC analysis on case observables.

### Integration: MISP → TheHive

- Generated MISP API key via admin panel
- Configured MISP connector in TheHive settings
- Validated end-to-end IOC ingestion — threat intel events from MISP surfaced as enrichment data on TheHive cases

---

## 🔗 Wazuh → TheHive Integration

**Purpose:** Automatically forward Wazuh security alerts into TheHive as structured cases — closing the loop between detection and response.

### Integration Script

A custom Python integration script (`custom-w2thive.py`) was deployed inside Wazuh's integration framework. It:
- Parses Wazuh alert JSON
- Extracts artifacts (IPs, URLs, domains) via regex
- Creates structured TheHive alerts via the `thehive4py` API

`lvl_threshold = 0` — all alerts forwarded (appropriate for single-agent lab; in production this would be tuned to rule severity level).

<details>
<summary>View full integration script</summary>

```python
#!/var/ossec/framework/python/bin/python3
import json, sys, os, re, logging, uuid
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact

lvl_threshold = 0
suricata_lvl_threshold = 3
debug_enabled = False
info_enabled = True

pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
log_file = '{0}/logs/integrations.log'.format(pwd)
logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)
if info_enabled: logger.setLevel(logging.INFO)
if debug_enabled: logger.setLevel(logging.DEBUG)
fh = logging.FileHandler(log_file)
fh.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(fh)

def main(args):
    alert_file_location = args[1]
    thive = args[3]
    thive_api_key = args[2]
    thive_api = TheHiveApi(thive, thive_api_key)
    w_alert = json.load(open(alert_file_location))
    alt = pr(w_alert, '', [])
    format_alt = md_format(alt)
    artifacts_dict = artifact_detect(format_alt)
    alert = generate_alert(format_alt, artifacts_dict, w_alert)
    if w_alert['rule']['groups'] == ['ids', 'suricata']:
        if 'data' in w_alert and 'alert' in w_alert['data']:
            if int(w_alert['data']['alert']['severity']) <= suricata_lvl_threshold:
                send_alert(alert, thive_api)
    elif int(w_alert['rule']['level']) >= lvl_threshold:
        send_alert(alert, thive_api)

def pr(data, prefix, alt):
    for key, value in data.items():
        if hasattr(value, 'keys'):
            pr(value, prefix + '.' + str(key), alt=alt)
        else:
            alt.append((prefix + '.' + str(key) + '|||' + str(value)))
    return alt

def md_format(alt, format_alt=''):
    md_title_dict = {}
    for now in alt:
        now = now[1:]
        dot = now.split('|||')[0].find('.')
        if dot == -1:
            md_title_dict[now.split('|||')[0]] = [now]
        else:
            if now[0:dot] in md_title_dict:
                md_title_dict[now[0:dot]].append(now)
            else:
                md_title_dict[now[0:dot]] = [now]
    for now in md_title_dict:
        format_alt += '### ' + now.capitalize() + '\n| key | val |\n| ------ | ------ |\n'
        for let in md_title_dict[now]:
            key, val = let.split('|||')[0], let.split('|||')[1]
            format_alt += '| **' + key + '** | ' + val + ' |\n'
    return format_alt

def artifact_detect(format_alt):
    artifacts_dict = {}
    artifacts_dict['ip'] = re.findall(r'\d+\.\d+\.\d+\.\d+', format_alt)
    artifacts_dict['url'] = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', format_alt)
    artifacts_dict['domain'] = [u.split('//')[1].split('/')[0] for u in artifacts_dict['url']]
    return artifacts_dict

def generate_alert(format_alt, artifacts_dict, w_alert):
    sourceRef = str(uuid.uuid4())[0:6]
    if 'agent' in w_alert:
        if 'ip' not in w_alert['agent']:
            w_alert['agent']['ip'] = 'no agent ip'
    else:
        w_alert['agent'] = {'id': 'no agent id', 'name': 'no agent name'}
    artifacts = [AlertArtifact(dataType=k, data=v) for k, vals in artifacts_dict.items() for v in vals]
    return Alert(
        title=w_alert['rule']['description'], tlp=2,
        tags=['wazuh', 'rule=' + w_alert['rule']['id'],
              'agent_name=' + w_alert['agent']['name'],
              'agent_id=' + w_alert['agent']['id'],
              'agent_ip=' + w_alert['agent']['ip']],
        description=format_alt, type='wazuh_alert',
        source='wazuh', sourceRef=sourceRef, artifacts=artifacts)

def send_alert(alert, thive_api):
    response = thive_api.create_alert(alert)
    if response.status_code == 201:
        logger.info('Created TheHive alert: ' + str(response.json()['id']))
    else:
        logger.error('Error: {}/{}'.format(response.status_code, response.text))

if __name__ == "__main__":
    try:
        main(sys.argv)
    except Exception:
        logger.exception('Integration error')
```

</details>

<details>
<summary>View bash wrapper script (custom-w2thive)</summary>

```bash
#!/bin/sh
WPYTHON_BIN="framework/python/bin/python3"
SCRIPT_PATH_NAME="$0"
DIR_NAME="$(cd $(dirname ${SCRIPT_PATH_NAME}); pwd -P)"
SCRIPT_NAME="$(basename ${SCRIPT_PATH_NAME})"
case ${DIR_NAME} in
    */active-response/bin | */wodles*)
        if [ -z "${WAZUH_PATH}" ]; then WAZUH_PATH="$(cd ${DIR_NAME}/../..; pwd)"; fi
        PYTHON_SCRIPT="${DIR_NAME}/${SCRIPT_NAME}.py" ;;
    */bin)
        if [ -z "${WAZUH_PATH}" ]; then WAZUH_PATH="$(cd ${DIR_NAME}/..; pwd)"; fi
        PYTHON_SCRIPT="${WAZUH_PATH}/framework/scripts/${SCRIPT_NAME}.py" ;;
    */integrations)
        if [ -z "${WAZUH_PATH}" ]; then WAZUH_PATH="$(cd ${DIR_NAME}/..; pwd)"; fi
        PYTHON_SCRIPT="${DIR_NAME}/${SCRIPT_NAME}.py" ;;
esac
${WAZUH_PATH}/${WPYTHON_BIN} ${PYTHON_SCRIPT} $@
```

</details>

### Deployment Steps

**1. Install `thehive4py` into Wazuh's isolated Python environment:**
```bash
sudo /var/ossec/framework/python/bin/pip3 install thehive4py
```
> ⚠️ Wazuh uses its own Python interpreter under `/var/ossec/framework/python/` — installing to system Python has no effect.

**2. Deploy scripts and set permissions:**
```bash
sudo chmod 755 /var/ossec/integrations/custom-w2thive.py
sudo chmod 755 /var/ossec/integrations/custom-w2thive
sudo chown root:wazuh /var/ossec/integrations/custom-w2thive.py
sudo chown root:wazuh /var/ossec/integrations/custom-w2thive
```

**3. Configure `ossec.conf`** — add integration block at the correct scope level (outside `<global>`, inside `<ossec_config>`):
```xml
<ossec_config>
  <integration>
    <name>custom-w2thive</name>
    <hook_url>192.168.100.156:9000</hook_url>
    <api_key>YOUR_THEHIVE_API_KEY</api_key>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>
```

**4. Restart Wazuh manager:**
```bash
sudo systemctl restart wazuh-manager
```

---

### 🔧 Troubleshooting: ossec.conf XML Scope Error

**Symptom:** `wazuh-manager` failed to start after editing `ossec.conf`.

**Root cause:** Integration block was accidentally placed *inside* the `<global>` element instead of as a sibling block.

**Diagnosis:**
```bash
sudo systemctl status wazuh-manager
# Revealed XML parse error in ossec.conf
```

**Fix:** Moved `<integration>` block to the correct position — as a direct child of `<ossec_config>`, not nested inside `<global>`.

**Takeaway:** Demonstrated ability to diagnose service startup failures from logs and resolve configuration schema errors under a live system.

---

### ✅ Integration Result

<img width="1126" height="419" alt="Wazuh alerts appearing in TheHive" src="https://github.com/user-attachments/assets/31b38121-2c13-48ff-812e-5080d8b0a564" />

- Wazuh alerts automatically forwarded to TheHive via REST API
- Structured alert artifacts (IPs, URLs, domains) extracted and mapped
- End-to-end detection-to-case pipeline fully operational

---

## 🌐 End-to-End Data Flow

```
Kali Linux (attack)
    │
    ▼
OPNsense Suricata IPS ──► Alert logged to OPNsense
    │
    ▼
Wazuh Agent (Windows 11) ──► Events forwarded to Wazuh Manager
    │
    ▼
Wazuh Manager (SIEM) ──► Detection rules fire ──► Alert generated
    │
    ▼
custom-w2thive integration
    │
    ▼
TheHive (case created) ──► Cortex (analyzers run) ──► IOCs enriched
    │
    ▼
MISP (threat intel lookup) ──► IOC context returned to case
```

---

## 🧠 Skills Demonstrated

| Domain | Skills |
|---|---|
| **Network Security** | Firewall configuration, IPS rule deployment, traffic segmentation |
| **SIEM** | Wazuh deployment, agent management, detection engineering |
| **Incident Response** | Case management workflows, TheHive, structured alert triage |
| **Threat Intelligence** | MISP deployment, IOC ingestion, TI-driven enrichment |
| **Security Automation** | Custom Python integration, API-based alert forwarding, Cortex analyzers |
| **Infrastructure** | Docker Compose orchestration, service dependency management |
| **Troubleshooting** | XML config debugging, container networking, application-layer routing |

---

## 📚 References

- [Wazuh → TheHive Integration (ls111-cybersec)](https://github.com/ls111-cybersec/wazuh-thehive-integration-ep13)
- [TheHive + Cortex + MISP Docker Compose](https://github.com/ls111-cybersec/thehive-cortex-misp-docker-compose-lab11update)
- [opnsense-suricata-nmaps rules (aleksibovellan)](https://github.com/aleksibovellan/opnsense-suricata-nmaps)
- [Free SOC Incident Response Platform (OpenSecure)](https://opensecure.medium.com/your-own-free-security-incident-response-platform-in-minutes-bff8c25b45ac)
- [Suricata Rule Documentation](https://suricata.readthedocs.io/)
