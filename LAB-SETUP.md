# Cybersecurity SOC Home Lab — Full Stack Defensive/Offensive Architecture

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
 
  <img width="495" height="319" alt="vmware_5Ekx5YDaJJ" src="https://github.com/user-attachments/assets/bd35e201-f35d-45a7-b6d7-7c8cd30f068c" />

 
 ### Deploying Windows Agent
 
 - Downloading the Windows 11 ISO
   
 - Installing it on VMWare
   
  <img width="437" height="324" alt="vmware_syg6dATZr7" src="https://github.com/user-attachments/assets/b4b25390-d286-4ce1-8554-a24114f3e4ab" />

 - Installing the agent on the W11 Machine with `Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.3-1.msi -OutFile $env:tmp\wazuh-agent; msiexec.exe /i $env:tmp\wazuh-agent /q WAZUH_MANAGER='192.168.205.131' WAZUH_AGENT_NAME='Windows11Financee'`
 - 

 <img width="701" height="647" alt="vmware_I6aqGn3Sqx" src="https://github.com/user-attachments/assets/d93f2507-e554-4af3-8240-52344052c6a6" />

 - Verifying that agent is installed after looking at the endpoints
   

 <img width="586" height="220" alt="vmware_W52iD5uOjw" src="https://github.com/user-attachments/assets/92744f1b-b07e-444f-b25c-c1adcb1a9d50" />

 
 
 
---

## TheHive - Case Management
Important to note **from now on i switched all of vms to bridged connection so i can also use my other computer because i was running out of ram**

- Created a new Ubuntu Machine to install TheHive on.
- Used these commands to install through docker 
```bash
- apt-get update
  - apt-get install \
    ca-certificates \
    curl \
    gnupg \
    lsb-release
  
  - curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
  - echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
  - apt-get update
  - apt-get install docker-ce docker-ce-cli containerd.io docker-compose-plugin
  - docker run -p 9000:9000 strangebee/thehive:5
```
   <img width="599" height="458" alt="NVIDIA_Overlay_Bz08Ml25He" src="https://github.com/user-attachments/assets/fcfb990b-460d-4ba0-9ef6-f6fbf0359d10" />
  

   <img width="599" height="268" alt="NVIDIA_Overlay_ve9mDciOBB" src="https://github.com/user-attachments/assets/b0ac39d0-595d-4529-9e94-011d1c49600c" />

   <img width="1202" height="570" alt="NVIDIA_Overlay_lTogS0ZDcd" src="https://github.com/user-attachments/assets/9a183591-6a6a-4a56-99ee-b606cfd74ccf" />

  
  ### Integration with Wazuh
  
  - This is the Python module that will be referenced in the custom integration script that we will be creating in the next step. 
  **`sudo /var/ossec/framework/python/bin/pip3 install thehive4py`**
  - The below script will need to be created in /var/ossec/integrations/ and called **custom-w2thive.py** I used nano to create/edit the script. This script has the `lvl_threshold` variable set to `0`, meaning that all alerts created by Wazuh will be forwarded to The Hive. Since i only have 1 agent, too much noise is not the problem for us in this LAB environment.
 ```python
 #!/var/ossec/framework/python/bin/python3
import json
import sys
import os
import re
import logging
import uuid
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact
#start user config
# Global vars
#threshold for wazuh rules level
lvl_threshold=0
#threshold for suricata rules level
suricata_lvl_threshold=3
debug_enabled = False
#info about created alert
info_enabled = True
#end user config
# Set paths
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
log_file = '{0}/logs/integrations.log'.format(pwd)
logger = logging.getLogger(__name__)
#set logging level
logger.setLevel(logging.WARNING)
if info_enabled:
    logger.setLevel(logging.INFO)
if debug_enabled:
    logger.setLevel(logging.DEBUG)
# create the logging file handler
fh = logging.FileHandler(log_file)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)

def main(args):
    logger.debug('#start main')
    logger.debug('#get alert file location')
    alert_file_location = args[1]
    logger.debug('#get TheHive url')
    thive = args[3]
    logger.debug('#get TheHive api key')
    thive_api_key = args[2]
    thive_api = TheHiveApi(thive, thive_api_key )
    logger.debug('#open alert file')
    w_alert = json.load(open(alert_file_location))
    logger.debug('#alert data')
    logger.debug(str(w_alert))
    logger.debug('#gen json to dot-key-text')
    alt = pr(w_alert,'',[])
    logger.debug('#formatting description')
    format_alt = md_format(alt)
    logger.debug('#search artifacts')
    artifacts_dict = artifact_detect(format_alt)
    alert = generate_alert(format_alt, artifacts_dict, w_alert)
    logger.debug('#threshold filtering')
    if w_alert['rule']['groups']==['ids','suricata']:
        #checking the existence of the data.alert.severity field
        if 'data' in w_alert.keys():
            if 'alert' in w_alert['data']:
                #checking the level of the source event
                if int(w_alert['data']['alert']['severity'])<=suricata_lvl_threshold:
                    send_alert(alert, thive_api)
    elif int(w_alert['rule']['level'])>=lvl_threshold:
        #if the event is different from suricata AND suricata-event-type: alert check lvl_threshold
        send_alert(alert, thive_api)

def pr(data,prefix, alt):
    for key,value in data.items():
        if hasattr(value,'keys'):
            pr(value,prefix+'.'+str(key),alt=alt)
        else:
            alt.append((prefix+'.'+str(key)+'|||'+str(value)))
    return alt

def md_format(alt,format_alt=''):
    md_title_dict = {}
    #sorted with first key
    for now in alt:
        now = now[1:]
        #fix first key last symbol
        dot = now.split('|||')[0].find('.')
        if dot==-1:
            md_title_dict[now.split('|||')[0]] =[now]
        else:
            if now[0:dot] in md_title_dict.keys():
                (md_title_dict[now[0:dot]]).append(now)
            else:
                md_title_dict[now[0:dot]]=[now]
    for now in md_title_dict.keys():
        format_alt+='### '+now.capitalize()+'\n'+'| key | val |\n| ------ | ------ |\n'
        for let in md_title_dict[now]:
            key,val = let.split('|||')[0],let.split('|||')[1]
            format_alt+='| **' + key + '** | ' + val + ' |\n'
    return format_alt

def artifact_detect(format_alt):
    artifacts_dict = {}
    artifacts_dict['ip'] = re.findall(r'\d+\.\d+\.\d+\.\d+',format_alt)
    artifacts_dict['url'] =  re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',format_alt)
    artifacts_dict['domain'] = []
    for now in artifacts_dict['url']: artifacts_dict['domain'].append(now.split('//')[1].split('/')[0])
    return artifacts_dict

def generate_alert(format_alt, artifacts_dict,w_alert):
    #generate alert sourceRef
    sourceRef = str(uuid.uuid4())[0:6]
    artifacts = []
    if 'agent' in w_alert.keys():
        if 'ip' not in w_alert['agent'].keys():
            w_alert['agent']['ip']='no agent ip'
    else:
        w_alert['agent'] = {'id':'no agent id', 'name':'no agent name'}
    for key,value in artifacts_dict.items():
        for val in value:
            artifacts.append(AlertArtifact(dataType=key, data=val))
    alert = Alert(title=w_alert['rule']['description'],
              tlp=2,
              tags=['wazuh', 
              'rule='+w_alert['rule']['id'], 
              'agent_name='+w_alert['agent']['name'],
              'agent_id='+w_alert['agent']['id'],
              'agent_ip='+w_alert['agent']['ip'],],
              description=format_alt ,
              type='wazuh_alert',
              source='wazuh',
              sourceRef=sourceRef,
              artifacts=artifacts,)
    return alert

def send_alert(alert, thive_api):
    response = thive_api.create_alert(alert)
    if response.status_code == 201:
        logger.info('Create TheHive alert: '+ str(response.json()['id']))
    else:
        logger.error('Error create TheHive alert: {}/{}'.format(response.status_code, response.text))

if __name__ == "__main__":
    try:
       logger.debug('debug mode') # if debug enabled       
       # Main function
       main(sys.argv)
    except Exception:
       logger.exception('EGOR')
```
 - Next, we need to create a bash script called custom-w2thive and place it in /var/ossec/integrations/custom-w2thive which is needed to properly execute the .py script created above. 
 ```bash
 #!/bin/sh
# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GP>
WPYTHON_BIN="framework/python/bin/python3"
SCRIPT_PATH_NAME="$0"
DIR_NAME="$(cd $(dirname ${SCRIPT_PATH_NAME}); pwd -P)"
SCRIPT_NAME="$(basename ${SCRIPT_PATH_NAME})"
case ${DIR_NAME} in
    */active-response/bin | */wodles*)
        if [ -z "${WAZUH_PATH}" ]; then
            WAZUH_PATH="$(cd ${DIR_NAME}/../..; pwd)"
        fi
    PYTHON_SCRIPT="${DIR_NAME}/${SCRIPT_NAME}.py"
    ;;
    */bin)
    if [ -z "${WAZUH_PATH}" ]; then
        WAZUH_PATH="$(cd ${DIR_NAME}/..; pwd)"
    fi
    PYTHON_SCRIPT="${WAZUH_PATH}/framework/scripts/${SCRIPT_NAME}.py"
    ;;
     */integrations)
        if [ -z "${WAZUH_PATH}" ]; then
            WAZUH_PATH="$(cd ${DIR_NAME}/..; pwd)"
        fi
    PYTHON_SCRIPT="${DIR_NAME}/${SCRIPT_NAME}.py"
    ;;
esac
${WAZUH_PATH}/${WPYTHON_BIN} ${PYTHON_SCRIPT} $@
```
  - Making sure Wazuh has the correct permissions to run the scripts
  ```
  sudo chmod 755 /var/ossec/integrations/custom-w2thive.py
  sudo chmod 755 /var/ossec/integrations/custom-w2thive
  sudo chown root:wazuh /var/ossec/integrations/custom-w2thive.py
  sudo chown root:wazuh /var/ossec/integrations/custom-w2thive
  ```

  <img width="1469" height="753" alt="NVIDIA_Overlay_eCqZWA0Pey" src="https://github.com/user-attachments/assets/c45e1a3c-5f84-4add-9820-aec40e61ed13" />

  
  - Final step, configuring the ossec.conf file located at `/var/ossec/etc/ossec.conf` and inserting a integration code 
  ``` 
  <ossec_config>
…
  <integration>
    <name>custom-w2thive</name>
    <hook_url>192.168.100.156:9000</hook_url>
    <api_key>API that i created from a new Service user on Wazuh Dashboard</api_key>
    <alert_format>json</alert_format>
  </integration>
…
</ossec_config>
```
- <img width="683" height="345" alt="NVIDIA_Overlay_m967HmSASm" src="https://github.com/user-attachments/assets/8c58db97-ac62-4a11-bb2b-e0310e840bd1" />

**Note:** You probably already saw what the problem here was, i accidentally edited the code into the `<global>`. And the consequences was that the Wazuh service wasnt starting anymore so heres 
**how i fixed it**.

 <img width="759" height="204" alt="NVIDIA_Overlay_swzIga3wCh" src="https://github.com/user-attachments/assets/d6de09ef-7db3-4142-9777-a113d53b3e58" />

- Checked to see what exactly isnt letting the service start

  <img width="815" height="141" alt="NVIDIA_Overlay_GOActCPntC" src="https://github.com/user-attachments/assets/0edf2de2-7e48-45eb-9e42-7a22e4568c50" />

- And then i checked the `ossec.conf` file and put it under `<global>` instead of inside it and it worked.

  <img width="431" height="95" alt="NVIDIA_Overlay_TD96gmdhw5" src="https://github.com/user-attachments/assets/93b15d10-4922-4c3a-a34d-467e86874374" />




- Restarting the wazuh-manager with `sudo systemctl restart wazuh-manager`


- **References** \
[Wazuh SIEM & The Hive Integration](https://github.com/ls111-cybersec/wazuh-thehive-integration-ep13?tab=readme-ov-file) \
[Your Own Free Security Incident Response Platform in Minutes](https://opensecure.medium.com/your-own-free-security-incident-response-platform-in-minutes-bff8c25b45ac)
  

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
