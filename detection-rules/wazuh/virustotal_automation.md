
# 🔐 Automated Malware Detection & Remediation  
### Wazuh + VirusTotal Active Response (SOC Automation Project)
---

## 📌 Project Overview

This project demonstrates an automated malware detection and response workflow using:

- Wazuh File Integrity Monitoring (FIM)
- VirusTotal Threat Intelligence Integration
- Custom Active Response Script (Automated File Removal)

The objective is to simulate a real-world SOC automation scenario where malicious files are:

1. Detected  
2. Validated against threat intelligence  
3. Automatically removed  
4. Logged and alerted for analyst visibility  

---

## 🏗 Architecture & Workflow

### 1️⃣ File Integrity Monitoring (FIM)

- Monitors file creation, modification, and deletion.
- Maintains file hashes.
- Generates alerts upon file change detection.

### 2️⃣ VirusTotal Integration

- Triggered automatically when a FIM alert occurs.
- File hash is checked against VirusTotal.
- If malicious → Active Response is initiated.

### 3️⃣ Automated Remediation

- Custom Python script securely deletes the malicious file.
- All actions are logged in `active-responses.log`.
- Custom Wazuh rules generate success/failure alerts.

---

# ⚙️ Implementation

---

## 1️⃣ Enable FIM for Windows Agents

Configured centrally so all enrolled Windows agents automatically receive FIM configuration.

<img width="787" height="224" alt="NVIDIA_Overlay_mW5MmbWFrl" src="https://github.com/user-attachments/assets/ab5d2ad9-9f23-453c-84b0-eaf31d2be038" />

<img width="1179" height="292" alt="NVIDIA_Overlay_sjhxmcsRle" src="https://github.com/user-attachments/assets/2ed418ab-0afd-4029-b506-f345ffc4a676" />


---

## 2️⃣ Configure VirusTotal Integration

Added to:

```

/var/ossec/etc/ossec.conf

````

```xml
<integration>
  <name>virustotal</name>
  <api_key>API_KEY</api_key> 
  <group>syscheck</group>
  <alert_format>json</alert_format>
</integration>
````

---

## 3️⃣ Custom Active Response Script

The following script securely removes malicious files detected by VirusTotal.

```python
# Copyright (C) 2015-2025, Wazuh Inc.
# All rights reserved.

import os
import sys
import json
import datetime
import stat
import tempfile
import pathlib

if os.name == 'nt':
    LOG_FILE = "C:\\Program Files (x86)\\ossec-agent\\active-response\\active-responses.log"
else:
    LOG_FILE = "/var/ossec/logs/active-responses.log"

ADD_COMMAND = 0
DELETE_COMMAND = 1
CONTINUE_COMMAND = 2
ABORT_COMMAND = 3

OS_SUCCESS = 0
OS_INVALID = -1

class message:
    def __init__(self):
        self.alert = ""
        self.command = 0

def write_debug_file(ar_name, msg):
    with open(LOG_FILE, mode="a") as log_file:
        log_file.write(str(datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')) + " " + ar_name + ": " + msg +"\n")

def setup_and_check_message(argv):
    input_str = ""
    for line in sys.stdin:
        input_str = line
        break

    msg_obj = message()
    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'Decoding JSON has failed, invalid input format')
        msg_obj.command = OS_INVALID
        return msg_obj

    msg_obj.alert = data
    command = data.get("command")

    if command == "add":
        msg_obj.command = ADD_COMMAND
    elif command == "delete":
        msg_obj.command = DELETE_COMMAND
    else:
        msg_obj.command = OS_INVALID
        write_debug_file(argv[0], 'Not valid command: ' + command)

    return msg_obj

def send_keys_and_check_message(argv, keys):
    keys_msg = json.dumps({"version": 1,"origin":{"name": argv[0],"module":"active-response"},"command":"check_keys","parameters":{"keys":keys}})
    write_debug_file(argv[0], keys_msg)

    print(keys_msg)
    sys.stdout.flush()

    input_str = ""
    while True:
        line = sys.stdin.readline()
        if line:
            input_str = line
            break

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'Decoding JSON has failed, invalid input format')
        return OS_INVALID

    action = data.get("command")
    if action == "continue":
        return CONTINUE_COMMAND
    elif action == "abort":
        return ABORT_COMMAND
    else:
        write_debug_file(argv[0], "Invalid value of 'command'")
        return OS_INVALID

def secure_delete_file(filepath_str, ar_name):
    filepath = pathlib.Path(filepath_str)

    if '::' in filepath_str:
        raise Exception(f"Refusing to delete ADS or NTFS stream: {filepath_str}")

    if os.path.islink(filepath):
        raise Exception(f"Refusing to delete symbolic link: {filepath}")

    attrs = os.lstat(filepath).st_file_attributes
    if attrs & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise Exception(f"Refusing to delete reparse point: {filepath}")

    resolved_filepath = filepath.resolve()

    if not resolved_filepath.is_file():
        raise Exception(f"Target is not a regular file: {resolved_filepath}")

    os.remove(resolved_filepath)

def main(argv):
    write_debug_file(argv[0], "Started")
    msg = setup_and_check_message(argv)

    if msg.command < 0:
        sys.exit(OS_INVALID)

    if msg.command == ADD_COMMAND:
        alert = msg.alert["parameters"]["alert"]
        keys = [alert["rule"]["id"]]
        action = send_keys_and_check_message(argv, keys)

        if action != CONTINUE_COMMAND:
            if action == ABORT_COMMAND:
                write_debug_file(argv[0], "Aborted")
                sys.exit(OS_SUCCESS)
            else:
                write_debug_file(argv[0], "Invalid command")
                sys.exit(OS_INVALID)

        try:
            file_path = alert["data"]["virustotal"]["source"]["file"]
            if os.path.exists(file_path):
                secure_delete_file(file_path, argv[0])
                write_debug_file(argv[0], json.dumps(msg.alert) + " Successfully removed threat")
            else:
                write_debug_file(argv[0], f"File does not exist: {file_path}")
        except OSError as error:
            write_debug_file(argv[0], json.dumps(msg.alert) + "Error removing threat")
        except Exception as e:
            write_debug_file(argv[0], f"{json.dumps(msg.alert)}: Error removing threat: {str(e)}")
    else:
        write_debug_file(argv[0], "Invalid command")

    write_debug_file(argv[0], "Ended")
    sys.exit(OS_SUCCESS)

if __name__ == "__main__":
    main(sys.argv)
```

The script was compiled to `.exe` and placed in:

```
C:\Program Files (x86)\ossec-agent\active-response\bin
```

---

## 4️⃣ Active Response Configuration

```xml
<ossec_config>
  <command>
    <name>remove-threat</name>
    <executable>scriptt.exe</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

  <active-response>
    <disabled>no</disabled>
    <command>remove-threat</command>
    <location>local</location>
    <rules_id>87105</rules_id>
  </active-response>
</ossec_config>
```

---

## 5️⃣ Custom Detection Rules

Added to:

```
/var/ossec/etc/rules/local_rules.xml
```

```xml
<group name="virustotal,">
  <rule id="100092" level="12">
      <if_sid>657</if_sid>
      <match>Successfully removed threat</match>
      <description>$(parameters.program) removed threat located at $(parameters.alert.data.virustotal.source.file)</description>
  </rule>

  <rule id="100093" level="12">
    <if_sid>657</if_sid>
    <match>Error removing threat</match>
    <description>Error removing threat located at $(parameters.alert.data.virustotal.source.file)</description>
  </rule>
</group>
```

---

# 📊 Results

<img width="1035" height="221" alt="vmware_Iji54xGNM3" src="https://github.com/user-attachments/assets/07299d40-d9de-4a30-ad02-8b0bfa7d0680" />

* ✅ Malicious file detected via FIM
* ✅ Hash checked against VirusTotal
* ✅ Threat confirmed
* ✅ File securely removed
* ✅ Alert generated for SOC visibility

---

# 🧠 Skills Demonstrated

* SIEM Configuration (Wazuh)
* Threat Intelligence Integration
* Active Response Automation
* Secure File Handling
* SOC Workflow Simulation
* Detection Engineering
* Log Analysis & Custom Rule Writing

---

# 📚 References

* Wazuh Official Documentation
  [https://documentation.wazuh.com/current/proof-of-concept-guide/detect-remove-malware-virustotal.html](https://documentation.wazuh.com/current/proof-of-concept-guide/detect-remove-malware-virustotal.html)

