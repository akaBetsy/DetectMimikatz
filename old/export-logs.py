import win32evtlog
import json
import datetime

# Function to fetch logs from a specified log source and event IDs, then save as JSON
def fetch_windows_logs(log_name, event_ids, output_file):
    print(f"[*] Exporting logs from {log_name}...")

    try:
        hand = win32evtlog.OpenEventLog(None, log_name)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        total = win32evtlog.GetNumberOfEventLogRecords(hand)
        logs_found = []

        print(f"[*] Reading {total} events from {log_name}...")

        while True:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            if not events:
                break
            for event in events:
                if event.EventID in event_ids:
                    logs_found.append({
                        "Timestamp": event.TimeGenerated.Format(),
                        "EventID": event.EventID,
                        "Source": event.SourceName,
                        "Message": event.StringInserts if event.StringInserts else "No message data"
                    })

        win32evtlog.CloseEventLog(hand)

        # Save to JSON
        if logs_found:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(logs_found, f, indent=4)
            print(f"[✔] Exported {len(logs_found)} events to {output_file}")
        else:
            print(f"[✖] No matching events found in {log_name}.")

    except Exception as e:
        print(f"[✖] Error reading {log_name}: {e}")

# Function to export Sysmon logs
def export_sysmon_logs():
    sysmon_event_ids = [1, 5, 10, 11, 12, 13]
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    fetch_windows_logs("Microsoft-Windows-Sysmon/Operational", sysmon_event_ids, f"sysmon_logs_{timestamp}.json")

# Function to export Security logs
def export_security_logs():
    security_event_ids = [4624, 4672, 4688, 4719, 4776, 1102]
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    fetch_windows_logs("Security", security_event_ids, f"security_logs_{timestamp}.json")

# Main function
def main():
    print("\n===== Export Sysmon & Security Logs (JSON) =====")
    export_sysmon_logs()
    export_security_logs()
    print("[✔] Log export complete. Check JSON files in the current directory.")

if __name__ == "__main__":
    main()
