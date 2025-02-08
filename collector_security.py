import xml.etree.ElementTree as ET
import win32evtlog
import json
import re

# Load Security Config File
config_path = "config-security-and-sysmon.ps1"

# Extract RuleNames from the PowerShell config file
def extract_rulenames_from_ps1(config_file):
    rule_names_dict = {}
    with open(config_file, "r", encoding="utf-8") as file:
        for line in file:
            match = re.search(r'\$RuleNames\["(.+?)"\]\s*=\s*"(.+?)"', line)
            if match:
                rule_names_dict[match.group(1)] = match.group(2)
    return rule_names_dict

# Define the Security Log Source
SECURITY_LOG_SOURCE = "Security"

def extract_security_logs(output_json):
    """Extract all Security logs and save them to a JSON file, including RuleNames but without filtering logs."""
    hand = win32evtlog.OpenEventLog(None, SECURITY_LOG_SOURCE)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    
    logs = []
    rule_names = extract_rulenames_from_ps1(config_path)  # Load RuleNames

    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if not events:
            break
        
        for event in events:
            event_id = event.EventID & 0xFFFF  # Extract event ID
            event_data = event.StringInserts
            
            event_message = " ".join(event_data) if event_data else "No Event Data"
            rule_name = rule_names.get(event_id, "No RuleName Assigned")
            
            logs.append({
                "Timestamp": event.TimeGenerated.Format(),
                "EventID": event_id,
                "RuleName": rule_name,
                "Message": event_message
            })
    
    win32evtlog.CloseEventLog(hand)
    
    # Save logs to JSON
    with open(output_json, "w", encoding="utf-8") as file:
        json.dump(logs, file, indent=4)
    
    print(f"Logs saved to {output_json}")

# Run the export function
extract_security_logs("logs_security.json")
