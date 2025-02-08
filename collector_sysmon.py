import xml.etree.ElementTree as ET
import win32evtlog
import json

# Load Sysmon Config File
config_path = "config-sysmon.xml"
tree = ET.parse(config_path)
root = tree.getroot()

# Extract RuleNames from Sysmon Config
rule_names = {}
for event_filter in root.findall(".//EventFiltering/*"):
    rule_name_elem = event_filter.find("RuleName")
    if rule_name_elem is not None:
        rule_names[event_filter.tag] = rule_name_elem.text

# Define the Sysmon Log Source
SYSLOG_SOURCE = "Microsoft-Windows-Sysmon/Operational"

def extract_sysmon_logs(output_json):
    """Extract all Sysmon logs and save them to a JSON file, including RuleNames but without filtering logs."""
    hand = win32evtlog.OpenEventLog(None, SYSLOG_SOURCE)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    
    logs = []
    
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
extract_sysmon_logs("logs_sysmon.json")
