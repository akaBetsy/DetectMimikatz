import win32evtlog
import json
import datetime

# MITRE ATT&CK Mapping (Event IDs → Attack Stages)
MITRE_ATTACK_MAPPING = {
    "Execution": [1, 4688],  # Process Creation
    "Privilege Escalation": [4672],  # Special Privileges Assigned
    "Credential Access": [10, 13, 4673, 4776],  # LSASS Access, Logon Attempts
    "Persistence": [4698, 4697, 7045],  # Scheduled Tasks, Service Creation
    "Defense Evasion": [1102, 104],  # Security Log Cleared, Sysmon Stopped
    "Discovery": [4688, 4690],  # Process Execution
    "Lateral Movement": [5140, 4624],  # Network Logons
    "Impact": [1102],  # Security Log Cleared
}

# Function to fetch logs from a specified log source and event IDs, then save as JSON
def fetch_windows_logs(log_name, event_ids):
    print(f"[*] Exporting logs from {log_name}...")

    try:
        hand = win32evtlog.OpenEventLog(None, log_name)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        logs_found = {stage: [] for stage in MITRE_ATTACK_MAPPING.keys()}

        print(f"[*] Reading logs from {log_name}...")

        while True:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            if not events:
                break
            for event in events:
                for stage, attack_event_ids in MITRE_ATTACK_MAPPING.items():
                    if event.EventID in attack_event_ids:
                        logs_found[stage].append({
                            "Timestamp": event.TimeGenerated.Format(),
                            "EventID": event.EventID,
                            "Source": event.SourceName,
                            "Message": event.StringInserts if event.StringInserts else "No message data"
                        })

        win32evtlog.CloseEventLog(hand)

        return logs_found

    except Exception as e:
        print(f"[✖] Error reading {log_name}: {e}")
        return None

# Function to export Sysmon and Security logs with MITRE ATT&CK mapping
def export_logs():
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    sysmon_logs = fetch_windows_logs("Microsoft-Windows-Sysmon/Operational", sum(MITRE_ATTACK_MAPPING.values(), []))
    security_logs = fetch_windows_logs("Security", sum(MITRE_ATTACK_MAPPING.values(), []))

    mitre_summary = {stage: {"Sysmon": len(sysmon_logs[stage]), "Security": len(security_logs[stage])} for stage in MITRE_ATTACK_MAPPING.keys()}

    # Save detailed logs to JSON
    with open(f"mitre_sysmon_logs_{timestamp}.json", "w", encoding="utf-8") as f:
        json.dump(sysmon_logs, f, indent=4)

    with open(f"mitre_security_logs_{timestamp}.json", "w", encoding="utf-8") as f:
        json.dump(security_logs, f, indent=4)

    # Save MITRE summary
    with open(f"mitre_summary_{timestamp}.json", "w", encoding="utf-8") as f:
        json.dump(mitre_summary, f, indent=4)

    print(f"[✔] Exported logs with MITRE ATT&CK mapping to JSON files.")
    print(f"[✔] MITRE Summary: {mitre_summary}")

# Main function
def main():
    print("\n===== Export Sysmon & Security Logs (MITRE ATT&CK) =====")
    export_logs()
    print("[✔] Log export complete. Check JSON files in the current directory.")

if __name__ == "__main__":
    main()
