## VirusTotal Automation For Wazuh 


### What does this automation do?

- Wazuh FIM looks for any file addition, change, or deletion on the monitored folders. This module has the hash of these files stored and triggers alerts when it detects any changes.

- Wazuh then tiggers VirusTotal integration whenever an FIM alert occurs, then scans the file for any malware
 
- Deletes the file if the VT scan shows any malware



### How i set this up

- Enabling FIM for all of my Windows Agents so the configuration happens automatically for every new agent

<img width="787" height="224" alt="NVIDIA_Overlay_mW5MmbWFrl" src="https://github.com/user-attachments/assets/7939af49-f9de-48eb-b400-ecfc87d5c4e8" />

<img width="1179" height="292" alt="NVIDIA_Overlay_sjhxmcsRle" src="https://github.com/user-attachments/assets/5faaf457-c0de-4217-b726-0561e051e764" />


- Adding the VirusTotal integration to my `/var/ossec/etc/ossec.conf`

```xml
<integration>
  <name>virustotal</name>
  <api_key>API_KEY</api_key> 
  <group>syscheck</group>
  <alert_format>json</alert_format>
</integration>
```

<img width="581" height="462" alt="NVIDIA_Overlay_0PYYS5VIp1" src="https://github.com/user-attachments/assets/d0d91a72-9d54-4b87-b134-efb12442f886" />


- Creating the remove malware script.exe

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

    # Reject NTFS alternate data streams
    if '::' in filepath_str:
        raise Exception(f"Refusing to delete ADS or NTFS stream: {filepath_str}")

    # Reject symbolic links and reparse points
    if os.path.islink(filepath):
        raise Exception(f"Refusing to delete symbolic link: {filepath}")

    attrs = os.lstat(filepath).st_file_attributes
    if attrs & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise Exception(f"Refusing to delete reparse point: {filepath}")

    resolved_filepath = filepath.resolve()

    # Ensure it's a regular file
    if not resolved_filepath.is_file():
        raise Exception(f"Target is not a regular file: {resolved_filepath}")

  # Perform deletion
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

- Used PyCharm to compile this and convert it to an .exe so that the Windows Agent can run it and pasted it into `C:\Program Files (x86)\ossec-agent\active-response\bin` directory
- Enabled active response and added a new command to my ossec.conf file

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
- Added two new rules on my `/var/ossec/etc/rules/local_rules.xml` file to alert about the active response results 
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
## Results

<img width="1035" height="221" alt="vmware_Iji54xGNM3" src="https://github.com/user-attachments/assets/f7a19903-f86c-4439-bfb5-b65d76fa52e6" />


## References 
[Wazuh Documentation](https://documentation.wazuh.com/current/proof-of-concept-guide/detect-remove-malware-virustotal.html)
