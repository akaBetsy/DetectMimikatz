import json
from collections import Counter

# Load logs from JSON files
security_log_file = "logs_security.json"
sysmon_log_file = "logs_sysmon.json"
output_filtered_logs = "output_filtered_logs.json"
output_mitre_stages_count = "output_mitre_stages_count.json"

# MITRE ATT&CK mapping (local static list)
mitre_mapping = {
    "4624": "TA0005 - Defense Evasion | T1078 - Valid Accounts",
    "4688": "TA0002 - Execution | T1569.002 - System Services",
    "4672": "TA0004 - Privilege Escalation | T1068 - Exploitation for Privilege Escalation",
    "4673": "TA0004 - Privilege Escalation | T1548 - Abuse Elevation Control Mechanism",
    "4776": "TA0006 - Credential Access | T1110.001 - Password Guessing",
    "4768": "TA0006 - Credential Access | T1558.003 - Kerberos Authentication",
    "4769": "TA0006 - Credential Access | T1558.004 - Kerberos Ticket Granting",
    "5145": "TA0006 - Credential Access | T1003.001 - LSASS Memory Access"
}

# Function to load logs
def load_logs(log_file):
    try:
        with open(log_file, "r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"[!] Log file not found: {log_file}")
        return []

# Load logs from both sources
security_logs = load_logs(security_log_file)
sysmon_logs = load_logs(sysmon_log_file)

# Combine logs
all_logs = security_logs + sysmon_logs

# Filter logs based on conditions
filtered_logs = []
attack_stage_counter = Counter()

for log in all_logs:
    message = log.get("Message", "").lower()
    rule_name = log.get("RuleName", "No RuleName Assigned")
    event_id = str(log.get("EventID", "Unknown"))
    mitre_stage = mitre_mapping.get(event_id, "No MITRE Mapping")
    
    if "mimi" in message or rule_name != "No RuleName Assigned":
        log["MITRE Stage"] = mitre_stage  # Use local MITRE mapping only
        filtered_logs.append(log)
        
        # Count occurrences of each attack stage
        if mitre_stage != "No MITRE Mapping":
            attack_stage_counter[mitre_stage] += 1

# Save filtered logs to a new JSON file
with open(output_filtered_logs, "w", encoding="utf-8") as file:
    json.dump(filtered_logs, file, indent=4)

# Save attack stage counts to a separate file
with open(output_mitre_stages_count, "w", encoding="utf-8") as file:
    json.dump(attack_stage_counter, file, indent=4)

print(f"Filtered logs saved to {output_filtered_logs}")
print(f"Attack stage counts saved to {output_mitre_stages_count}")
